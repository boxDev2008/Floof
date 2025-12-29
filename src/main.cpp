#include "Parser.h"
#include "CodeGenerator.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <memory>
#include <map>
#include <future>

#include <toml++/toml.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;

void EnableConsoleFeatures(void)
{
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    SetConsoleOutputCP(CP_UTF8);

    std::cout.imbue(std::locale("en_US.UTF-8"));
    std::cerr.imbue(std::locale("en_US.UTF-8"));
#endif
}

namespace Color
{
    constexpr const char *RESET = "\033[0m";
    constexpr const char *BOLD = "\033[1m";
    constexpr const char *DIM = "\033[2m";

    constexpr const char *RED = "\033[31m";
    constexpr const char *GREEN = "\033[32m";
    constexpr const char *YELLOW = "\033[33m";
    constexpr const char *BLUE = "\033[34m";
    constexpr const char *MAGENTA = "\033[35m";
    constexpr const char *CYAN = "\033[36m";
    constexpr const char *WHITE = "\033[37m";

    constexpr const char *BRIGHT_GREEN = "\033[92m";
    constexpr const char *BRIGHT_CYAN = "\033[96m";
    constexpr const char *BRIGHT_YELLOW = "\033[93m";
}

namespace
{
    constexpr const char *MAIN_TEMPLATE = R"(pub proc main -> i32 {
    printf("Hello Floof!\n");
    return 0;
})";

    constexpr const char *BUILD_TOML_TEMPLATE = R"([project]
name = "{}"
version = "1.0.0"

[build]
debug = false

[linker]
libraries = []
library_paths = [])";
}

class ProjectBuilder;
struct BuildConfig;

struct BuildConfig
{
    std::string projectName;
    bool isDebug;
    std::vector<std::string> libraries;
    std::vector<std::string> libraryPaths;

    static BuildConfig fromToml(const fs::path &configPath)
    {
        BuildConfig config;
        toml::table tbl = toml::parse_file(configPath.string());

        config.projectName = tbl["project"]["name"].as_string()->get();
        config.isDebug = tbl["build"]["debug"].as_boolean()->get();

        if (auto libs = tbl["linker"]["libraries"].as_array())
        {
            for (const auto &lib : *libs)
            {
                config.libraries.push_back(lib.as_string()->get());
            }
        }

        if (auto paths = tbl["linker"]["library_paths"].as_array())
        {
            for (const auto &path : *paths)
            {
                config.libraryPaths.push_back(path.as_string()->get());
            }
        }

        return config;
    }
};

class ProjectBuilder
{
private:
    fs::path projectDir;
    LLVMContext context;

    void initializeLLVM()
    {
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargets();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllAsmParsers();
        llvm::InitializeAllAsmPrinters();
    }

    std::map<std::string, std::unique_ptr<ModuleAST>> parseSourceFiles()
    {
        std::map<std::string, std::unique_ptr<ModuleAST>> moduleMap;
        
        for (const auto &entry : fs::recursive_directory_iterator(projectDir / "src"))
        {
            if (!entry.is_regular_file() || entry.path().extension() != ".floof")
                continue;
                
            fs::path path = entry.path();
            std::ifstream file(path);
            std::stringstream buffer;
            buffer << file.rdbuf();
            
            Lexer lexer(buffer.str());
            Parser parser(lexer);
            auto module = parser.ParseModule();
            
            fs::path relativePath = fs::relative(path, projectDir / "src");
            std::string moduleName = relativePath.replace_extension("").string();
            
            std::replace(moduleName.begin(), moduleName.end(), '/', '.');
            std::replace(moduleName.begin(), moduleName.end(), '\\', '.');
            
            moduleMap.insert({moduleName, std::move(module)});
        }
        
        return moduleMap;
    }

    llvm::TargetMachine *createTargetMachine()
    {
        std::string targetTriple = llvm::sys::getDefaultTargetTriple();
        std::string error;

        const llvm::Target *target = llvm::TargetRegistry::lookupTarget(targetTriple, error);
        if (!target)
        {
            throw std::runtime_error("Target lookup failed: " + error);
        }

        llvm::TargetOptions opt;
        return target->createTargetMachine(
            targetTriple, "generic", "", opt, llvm::Reloc::PIC_);
    }

    std::string compileSingleModule(
        const std::string& moduleName,
        const ModuleAST& moduleAST,
        const std::map<std::string, std::unique_ptr<ModuleAST>>& moduleMap,
        const fs::path& projectDir,
        const llvm::TargetMachine& baseTM)
    {
        llvm::LLVMContext localContext;

        std::unique_ptr<llvm::TargetMachine> targetMachine(
            baseTM.getTarget().createTargetMachine(
                baseTM.getTargetTriple().str(),
                baseTM.getTargetCPU(),
                baseTM.getTargetFeatureString(),
                baseTM.Options,
                baseTM.getRelocationModel(),
                baseTM.getCodeModel(),
                baseTM.getOptLevel()
            )
        );

        CodeGenerator codeGen(
            localContext,
            const_cast<ModuleAST&>(moduleAST),
            moduleName,
            const_cast<std::map<std::string, std::unique_ptr<ModuleAST>>&>(moduleMap)
        );
        auto module = codeGen.GetModule();

        module->setTargetTriple(targetMachine->getTargetTriple().str());
        module->setDataLayout(targetMachine->createDataLayout());

        fs::path objectPath = projectDir / "obj" / (moduleName + ".o");

        std::error_code ec;
        llvm::raw_fd_ostream dest(objectPath.string(), ec, llvm::sys::fs::OF_None);
        if (ec)
            throw std::runtime_error("Could not open file: " + ec.message());

        llvm::legacy::PassManager pass;
        if (targetMachine->addPassesToEmitFile(
                pass, dest, nullptr, llvm::CGFT_ObjectFile))
        {
            throw std::runtime_error("TargetMachine can't emit object file");
        }

        pass.run(*module);
        dest.flush();

        return "\"" + objectPath.string() + "\" ";
    }

    std::string compileModulesToObjects(
        std::map<std::string, std::unique_ptr<ModuleAST>>& moduleMap,
        llvm::TargetMachine* baseTM)
    {
        std::vector<std::future<std::string>> jobs;

        for (const auto& [moduleName, moduleAST] : moduleMap)
        {
            std::cout << Color::DIM << "  └─ " << Color::RESET
                    << "Compiling " << Color::CYAN << moduleName << ".floof"
                    << Color::RESET << "...\n";

            jobs.emplace_back(std::async(std::launch::async, [&, moduleName]() {
                return compileSingleModule(
                    moduleName,
                    *moduleAST,
                    moduleMap,
                    projectDir,
                    *baseTM
                );
            }));
        }

        std::string objectFiles;
        for (auto& job : jobs)
            objectFiles += job.get();

        std::cout << Color::DIM << "  └─ " << Color::RESET
                << "Compiled " << Color::BRIGHT_GREEN
                << jobs.size() << Color::RESET << " module(s)\n";

        return objectFiles;
    }

    void linkObjects(const std::string &objectFiles, const BuildConfig &config)
    {
        std::cout << Color::DIM << "  └─ " << Color::RESET << "Linking...\n";
        std::string executableName = config.projectName;
#ifdef _WIN32
        executableName += ".exe";
#endif

        std::string outputPath = (projectDir / "build" / executableName).string();
        std::string command = "clang -o " + outputPath + " " + objectFiles;

        if (config.isDebug)
            command += " -g -O0";

        for (const auto &lib : config.libraries)
            command += " -l" + lib;

        for (const auto &path : config.libraryPaths)
            command += " -L" + path;

        int result = system(command.c_str());
        if (result != 0)
            throw std::runtime_error("Linking failed with code: " + std::to_string(result));
    }

public:
    ProjectBuilder()
    {
        initializeLLVM();
    }

    void createNewProject(const fs::path &path)
    {
        projectDir = path;

        std::cout << Color::BRIGHT_CYAN << "Creating new Floof project..." << Color::RESET << "\n\n";

        fs::create_directory(projectDir);
        fs::create_directory(projectDir / "src");

        std::cout << Color::DIM << "  └─ " << Color::RESET << "Created directory structure\n";

        // Create main.floof
        std::ofstream mainFile(projectDir / "src/main.floof");
        mainFile << MAIN_TEMPLATE;
        mainFile.close();

        std::cout << Color::DIM << "  └─ " << Color::RESET << "Generated src/main.floof\n";

        // Create build.toml
        std::string tomlContent = BUILD_TOML_TEMPLATE;
        size_t pos = tomlContent.find("{}");
        if (pos != std::string::npos)
        {
            tomlContent.replace(pos, 2, projectDir.filename().string());
        }

        std::ofstream configFile(projectDir / "build.toml");
        configFile << tomlContent;
        configFile.close();

        std::cout << Color::DIM << "  └─ " << Color::RESET << "Generated build.toml\n\n";
        std::cout << Color::BRIGHT_GREEN << "✓ " << Color::BOLD << "Project '"
                  << projectDir.filename().string() << "' created successfully!"
                  << Color::RESET << '\n';
    }

    void buildProject(const fs::path &path)
    {
        projectDir = path;

        std::cout << Color::BRIGHT_CYAN << "Building " << Color::BOLD
                  << projectDir.filename().string() << Color::RESET << "...\n\n";

        fs::create_directories(projectDir / "obj");
        fs::create_directories(projectDir / "build");

        auto moduleMap = parseSourceFiles();
        auto targetMachine = std::unique_ptr<llvm::TargetMachine>(createTargetMachine());

        std::string objectFiles = compileModulesToObjects(moduleMap, targetMachine.get());

        BuildConfig config = BuildConfig::fromToml(projectDir / "build.toml");
        linkObjects(objectFiles, config);

        std::cout << "\n"
                  << Color::BRIGHT_GREEN << "✓ " << Color::BOLD
                  << "Build completed successfully!" << Color::RESET << '\n';
    }

    void runProject(const fs::path &path)
    {
        projectDir = path;

        BuildConfig config = BuildConfig::fromToml(projectDir / "build.toml");

        std::cout << Color::BRIGHT_CYAN << "Running " << Color::BOLD
                  << config.projectName << Color::RESET << "...\n";
        std::cout << Color::DIM << "─────────────────────────────────────"
                  << Color::RESET << "\n\n";

        std::string command = "cd " + (projectDir / "build").string() +
#ifdef _WIN32
    " && .\\" + config.projectName;
#else
    " && ./" + config.projectName;
#endif

    int status = system(command.c_str());
    
    int exitCode;
    #ifdef _WIN32
        exitCode = status;
    #else
        if (WIFEXITED(status))
            exitCode = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            exitCode = 128 + WTERMSIG(status);
        else
            exitCode = status;
    #endif

        std::cout << "\n"
                  << Color::DIM << "─────────────────────────────────────"
                  << Color::RESET << "\n";

        if (exitCode == 0)
        {
            std::cout << "Finished with exit code " << Color::BRIGHT_GREEN
                      << exitCode << Color::RESET << '\n';
        }
        else
        {
            std::cout << "Finished with exit code " << Color::RED
                      << exitCode << Color::RESET << '\n';
        }
    }
};

int main(int argc, char **argv)
{
    try
    {
        EnableConsoleFeatures();
        if (argc < 3)
        {
            std::cerr << Color::RED << "✗ Error: " << Color::RESET
                      << "Missing arguments\n\n";
            std::cerr << Color::BOLD << "Usage: " << Color::RESET
                      << "floof <command> <project_path>\n\n";
            std::cerr << Color::BOLD << "Commands:\n"
                      << Color::RESET;
            std::cerr << Color::CYAN << "  new" << Color::RESET
                      << "       - Create a new Floof project\n";
            std::cerr << Color::CYAN << "  build" << Color::RESET
                      << "     - Build the project\n";
            std::cerr << Color::CYAN << "  run" << Color::RESET
                      << "       - Run the compiled project\n";
            std::cerr << Color::CYAN << "  buildrun" << Color::RESET
                      << "  - Build and run the project\n";
            return 1;
        }

        ProjectBuilder builder;
        std::string command = argv[1];
        fs::path projectPath = argv[2];

        if (command == "new")
            builder.createNewProject(projectPath);
        else if (command == "build")
            builder.buildProject(projectPath);
        else if (command == "run")
            builder.runProject(projectPath);
        else if (command == "buildrun")
        {
            builder.buildProject(projectPath);
            builder.runProject(projectPath);
        }
        else
        {
            std::cerr << Color::RED << "✗ Error: " << Color::RESET
                      << "Unknown command '" << Color::YELLOW << command
                      << Color::RESET << "'\n\n";
            std::cerr << Color::BOLD << "Available commands: " << Color::RESET
                      << Color::CYAN << "new" << Color::RESET << ", "
                      << Color::CYAN << "build" << Color::RESET << ", "
                      << Color::CYAN << "run" << Color::RESET << ", "
                      << Color::CYAN << "buildrun" << Color::RESET << "\n";
            return 1;
        }
    }
    catch (const toml::parse_error &err)
    {
        std::cerr << Color::RED << "✗ Build configuration error:\n"
                  << Color::RESET << err << '\n';
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << Color::RED << "✗ Error: " << Color::RESET
                  << e.what() << '\n';
        return 1;
    }

    return 0;
}