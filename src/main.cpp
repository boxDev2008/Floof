#include "Parser.h"
#include "CodeGenerator.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <memory>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>

#include <toml++/toml.hpp>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using Seconds = std::chrono::duration<double>;

static void EnableConsoleFeatures(void)
{
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
    std::cout.imbue(std::locale("en_US.UTF-8"));
    std::cerr.imbue(std::locale("en_US.UTF-8"));
#endif
}

namespace C
{
    constexpr const char* RESET   = "\033[0m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* DIM     = "\033[2m";
    constexpr const char* RED     = "\033[31m";
    constexpr const char* CYAN    = "\033[36m";
    constexpr const char* BGREEN  = "\033[92m";
    constexpr const char* BCYAN   = "\033[96m";
    constexpr const char* BYELLOW = "\033[93m";
}

static std::string fmtSeconds(double s)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(6) << s << "s";
    return o.str();
}

static void step(const std::string& msg)
{
    std::cout << C::DIM << "  └─ " << C::RESET << msg << "\n";
}

struct BuildConfig
{
    std::string projectName;
    bool isDebug = false;
    std::vector<std::string> libraries;
    std::vector<std::string> libraryPaths;

    static BuildConfig load(const fs::path& path)
    {
        BuildConfig cfg;
        auto tbl = toml::parse_file(path.string());

        cfg.projectName = tbl["project"]["name"].as_string()->get();
        cfg.isDebug     = tbl["build"]["debug"].as_boolean()->get();

        if (auto libs = tbl["linker"]["libraries"].as_array())
            for (const auto& v : *libs)
                cfg.libraries.push_back(v.as_string()->get());

        if (auto paths = tbl["linker"]["library_paths"].as_array())
            for (const auto& v : *paths)
                cfg.libraryPaths.push_back(v.as_string()->get());

        return cfg;
    }
};

constexpr const char* MAIN_FLOOF = R"(pub proc main -> i32 {
    printf("Hello Floof!\n");
    return 0;
})";

constexpr const char* BUILD_TOML = R"([project]
name = "{}"
version = "1.0.0"

[build]
debug = false

[linker]
libraries = []
library_paths = [])";

static void initLLVM(void)
{
    llvm::InitializeAllTargetInfos();
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmParsers();
    llvm::InitializeAllAsmPrinters();
}

static llvm::TargetMachine* makeTargetMachine(void)
{
    std::string triple = llvm::sys::getDefaultTargetTriple();
    std::string error;
    const llvm::Target* target = llvm::TargetRegistry::lookupTarget(triple, error);
    if (!target)
        throw std::runtime_error("Target lookup failed: " + error);

    llvm::TargetOptions opt;
    return target->createTargetMachine(
        llvm::Triple(triple), "generic", "", opt,
        llvm::Reloc::PIC_, llvm::CodeModel::Small, llvm::CodeGenOptLevel::Aggressive);
}

static std::map<std::string, std::unique_ptr<ModuleAST>> parseSourceFiles(const fs::path& srcDir)
{
    std::map<std::string, std::unique_ptr<ModuleAST>> modules;

    for (const auto& entry : fs::recursive_directory_iterator(srcDir))
    {
        if (!entry.is_regular_file() || entry.path().extension() != ".floof")
            continue;

        std::ifstream file(entry.path());
        std::stringstream buf;
        buf << file.rdbuf();

        auto rel = fs::relative(entry.path(), srcDir).replace_extension("").string();
        std::replace(rel.begin(), rel.end(), '/', '.');
        std::replace(rel.begin(), rel.end(), '\\', '.');

        Lexer lexer(buf.str());
        Parser parser(lexer, rel);
        modules.emplace(rel, parser.ParseModule());
    }

    return modules;
}

static std::string compileModule(
    const std::string& name,
    const ModuleAST& ast,
    const std::map<std::string, std::unique_ptr<ModuleAST>>& allModules,
    const fs::path& projectDir,
    const llvm::TargetMachine& baseTM)
{
    llvm::LLVMContext ctx;

    std::unique_ptr<llvm::TargetMachine> tm(
        baseTM.getTarget().createTargetMachine(
            baseTM.getTargetTriple(), baseTM.getTargetCPU(),
            baseTM.getTargetFeatureString(), baseTM.Options,
            baseTM.getRelocationModel(), baseTM.getCodeModel(), baseTM.getOptLevel()));

    CodeGenerator cg(ctx,
        const_cast<ModuleAST&>(ast), name,
        const_cast<std::map<std::string, std::unique_ptr<ModuleAST>>&>(allModules));

    auto mod = cg.GetModule();
    mod->setTargetTriple(tm->getTargetTriple());
    mod->setDataLayout(tm->createDataLayout());

    fs::path obj = projectDir / "obj" / (name + ".o");
    std::error_code ec;
    llvm::raw_fd_ostream dest(obj.string(), ec, llvm::sys::fs::OF_None);
    if (ec)
        throw std::runtime_error("Could not open file: " + ec.message());

    llvm::legacy::PassManager pm;
    if (tm->addPassesToEmitFile(pm, dest, nullptr, llvm::CodeGenFileType::ObjectFile))
        throw std::runtime_error("TargetMachine can't emit object file");

    pm.run(*mod);
    dest.flush();

    return "\"" + obj.string() + "\" ";
}

static std::string compileAll(
    std::map<std::string, std::unique_ptr<ModuleAST>>& modules,
    llvm::TargetMachine* baseTM,
    const fs::path& projectDir)
{
    const size_t threadCount = std::min<size_t>(std::thread::hardware_concurrency(), modules.size());

    std::vector<std::pair<const std::string*, const ModuleAST*>> tasks;
    for (const auto& [name, ast] : modules)
        tasks.emplace_back(&name, ast.get());

    std::vector<std::string> results(tasks.size());
    std::atomic<size_t> next{0};
    std::mutex printMx, errorMx;
    std::exception_ptr firstErr;

    auto worker = [&]()
    {
        while (true)
        {
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= tasks.size()) break;

            auto t0 = Clock::now();
            try { results[i] = compileModule(*tasks[i].first, *tasks[i].second, modules, projectDir, *baseTM); }
            catch (...) { std::lock_guard lk(errorMx); if (!firstErr) firstErr = std::current_exception(); }
            double elapsed = Seconds(Clock::now() - t0).count();

            std::lock_guard lk(printMx);
            step("Compiled " + std::string(C::CYAN) + *tasks[i].first + ".floof" +
                 C::RESET + C::DIM + " (" + fmtSeconds(elapsed) + ")" + C::RESET);
        }
    };

    auto t0 = Clock::now();
    std::vector<std::thread> threads;
    for (size_t i = 0; i < threadCount; ++i)
        threads.emplace_back(worker);
    for (auto& t : threads) t.join();
    double elapsed = Seconds(Clock::now() - t0).count();

    if (firstErr) std::rethrow_exception(firstErr);

    step(std::string("Compiled ") + C::BGREEN + std::to_string(tasks.size()) + C::RESET +
         " module(s) across " + C::BYELLOW + std::to_string(threadCount) + C::RESET +
         " thread(s)" + C::DIM + " (" + fmtSeconds(elapsed) + ")" + C::RESET);

    std::string objectFiles;
    for (const auto& r : results) objectFiles += r;
    return objectFiles;
}

static void link(const std::string& objectFiles, const BuildConfig& cfg, const fs::path& projectDir)
{
    std::string exe = cfg.projectName;
#ifdef _WIN32
    exe += ".exe";
#endif
    std::string cmd = "clang -o " + (projectDir / "build" / exe).string() + " " + objectFiles;
    if (cfg.isDebug) cmd += " -g -O0";
    for (const auto& l : cfg.libraries)    cmd += " -l" + l;
    for (const auto& p : cfg.libraryPaths) cmd += " -L" + p;

    std::cout << C::DIM << "  └─ " << C::RESET << "Linking...";
    auto t0 = Clock::now();
    int rc = system(cmd.c_str());
    double elapsed = Seconds(Clock::now() - t0).count();

    if (rc != 0)
        throw std::runtime_error("Linking failed with code: " + std::to_string(rc));

    std::cout << C::DIM << " (" << fmtSeconds(elapsed) << ")" << C::RESET << "\n";
}

static void cmdNew(const fs::path& dir)
{
    std::cout << C::BCYAN << "Creating new Floof project..." << C::RESET << "\n\n";

    fs::create_directory(dir);
    fs::create_directory(dir / "src");
    step("Created directory structure");

    std::ofstream(dir / "src/main.floof") << MAIN_FLOOF;
    step("Generated src/main.floof");

    std::string toml = BUILD_TOML;
    toml.replace(toml.find("{}"), 2, dir.filename().string());
    std::ofstream(dir / "build.toml") << toml;
    step("Generated build.toml");

    std::cout << "\n" << C::BGREEN << "✓ " << C::BOLD
              << "Project '" << dir.filename().string() << "' created successfully!"
              << C::RESET << "\n";
}

static void cmdBuild(const fs::path& dir)
{
    std::cout << C::BCYAN << "Building " << C::BOLD
              << dir.filename().string() << C::RESET << "...\n\n";

    auto t0 = Clock::now();

    fs::create_directories(dir / "obj");
    fs::create_directories(dir / "build");

    auto modules = parseSourceFiles(dir / "src");
    auto tm = std::unique_ptr<llvm::TargetMachine>(makeTargetMachine());
    auto objectFiles = compileAll(modules, tm.get(), dir);

    auto cfg = BuildConfig::load(dir / "build.toml");
    link(objectFiles, cfg, dir);

    double total = Seconds(Clock::now() - t0).count();
    std::cout << "\n" << C::BGREEN << "✓ " << C::BOLD << "Build completed successfully! " << C::DIM << '(' << fmtSeconds(total) << ")\n\n" << C::RESET;
}

static void cmdRun(const fs::path& dir)
{
    auto cfg = BuildConfig::load(dir / "build.toml");

    std::cout << C::BCYAN << "Running " << C::BOLD << cfg.projectName << C::RESET << "...\n"
              << C::DIM << "─────────────────────────────────────" << C::RESET << "\n\n";

    std::string cmd = "cd " + (dir / "build").string() +
#ifdef _WIN32
        " && .\\" + cfg.projectName;
#else
        " && ./" + cfg.projectName;
#endif

    int status = system(cmd.c_str());
    int exitCode;
#ifdef _WIN32
    exitCode = status;
#else
    if      (WIFEXITED(status))   exitCode = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) exitCode = 128 + WTERMSIG(status);
    else                          exitCode = status;
#endif

    std::cout << "\n" << C::DIM << "─────────────────────────────────────" << C::RESET << "\n";
    std::cout << "Finished with exit code "
              << (exitCode == 0 ? C::BGREEN : C::RED) << exitCode << C::RESET << "\n";
}

int main(int argc, char** argv)
{
    try
    {
        EnableConsoleFeatures();

        if (argc < 3)
        {
            std::cerr << C::RED << "✗ Error: " << C::RESET << "Missing arguments\n\n"
                      << C::BOLD << "Usage: " << C::RESET << "floof <command> <project_path>\n\n"
                      << C::BOLD << "Commands:\n" << C::RESET
                      << C::CYAN << "  new"      << C::RESET << "       - Create a new Floof project\n"
                      << C::CYAN << "  build"    << C::RESET << "     - Build the project\n"
                      << C::CYAN << "  run"      << C::RESET << "       - Run the compiled project\n"
                      << C::CYAN << "  buildrun" << C::RESET << "  - Build and run the project\n";
            return 1;
        }

        initLLVM();

        std::string cmd  = argv[1];
        fs::path    path = argv[2];

        if      (cmd == "new")      cmdNew(path);
        else if (cmd == "build")    cmdBuild(path);
        else if (cmd == "run")      cmdRun(path);
        else if (cmd == "buildrun") { cmdBuild(path); cmdRun(path); }
        else
        {
            std::cerr << C::RED << "✗ Error: " << C::RESET
                      << "Unknown command '" << C::BYELLOW << cmd << C::RESET << "'\n\n"
                      << C::BOLD << "Available commands: " << C::RESET
                      << C::CYAN << "new"      << C::RESET << ", "
                      << C::CYAN << "build"    << C::RESET << ", "
                      << C::CYAN << "run"      << C::RESET << ", "
                      << C::CYAN << "buildrun" << C::RESET << "\n";
            return 1;
        }
    }
    catch (const toml::parse_error& err)
    {
        std::cerr << C::RED << "✗ Build configuration error:\n" << C::RESET << err << "\n";
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << C::RED << "✗ Error: " << C::RESET << e.what() << "\n";
        return 1;
    }

    return 0;
}