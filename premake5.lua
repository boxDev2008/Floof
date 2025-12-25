workspace "Floof"
    architecture "x64"
    configurations { "Debug", "Release" }
    startproject "floof"

local function get_llvm_config(command)
    local handle = io.popen("llvm-config " .. command)
    local result = handle:read("*a")
    handle:close()
    return result:gsub("\n", "")
end

local llvm_prefix = os.getenv("LLVM_DIR")
local llvm_libdir = llvm_prefix .. "/lib"
local llvm_includedir = llvm_prefix .. "/include"

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

project "floof"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++20"
    staticruntime "off"

    targetdir ("bin/" .. outputdir)
    objdir ("obj/" .. outputdir)

    files {
        "src/**.h",
        "src/**.hpp",
        "src/**.cpp"
    }

    includedirs {
        "src",
        "src/vendor",
        llvm_includedir
    }

    libdirs {
        llvm_libdir
    }

    filter "system:windows"
        systemversion "latest"
        defines { "_CRT_SECURE_NO_WARNINGS" }
        
        links {
            "LLVMCore",
            "LLVMSupport",
            "LLVMIRReader",
            "LLVMCodeGen",
            "LLVMMC",
            "LLVMMCParser",
            "LLVMOption",
            "LLVMBitWriter",
            "LLVMBitReader",
            "LLVMTarget",
            "LLVMX86CodeGen",
            "LLVMX86AsmParser",
            "LLVMX86Desc",
            "LLVMX86Info",
            "LLVMAsmPrinter",
            "LLVMSelectionDAG",
            "LLVMScalarOpts",
            "LLVMInstCombine",
            "LLVMTransformUtils",
            "LLVMAnalysis",
            "LLVMObject",
            "LLVMMCDisassembler",
            "LLVMExecutionEngine",
            "LLVMipo",
            "LLVMVectorize",
            "LLVMAsmParser",
            "LLVMTableGen",
            "LLVMDebugInfoCodeView",
            "LLVMDebugInfoMSF",
            "LLVMDebugInfoDWARF",
            "LLVMGlobalISel",
            "LLVMBinaryFormat",
            "LLVMRemarks",
            "LLVMBitstreamReader",
            "LLVMAggressiveInstCombine",
            "LLVMProfileData",
            "LLVMDemangle",
            "LLVMTextAPI",
            "LLVMFrontendOpenMP",
            "LLVMObjCARCOpts",
            "LLVMPasses",
            "LLVMCFGuard",
            "LLVMInstrumentation",  -- For ASan support
            "LLVMipo",              -- Interprocedural optimizations (may contain these symbols)
            "version",
            "ntdll"  -- For RtlGetLastNtStatus
        }

    filter "system:linux"
        local llvm_libs = get_llvm_config("--libs core support irreader codegen mc mcparser option bitwriter target x86codegen x86asmparser x86desc x86info")
        local llvm_syslibs = get_llvm_config("--system-libs")
        
        for lib in llvm_libs:gmatch("-l([%w_]+)") do
            links { lib }
        end
        
        links {
            "pthread",
            "dl",
            "z",
            "m",
            "stdc++"
        }
        
        buildoptions {
            "`llvm-config --cxxflags 2>/dev/null || llvm-config --cxxflags`"
        }
        
        linkoptions {
            "`llvm-config --ldflags 2>/dev/null || llvm-config --ldflags`"
        }

    filter "system:macosx"
        links {
            "LLVM-15"
        }
        
        libdirs {
            "/usr/local/opt/llvm@15/lib"
        }
        
        includedirs {
            "/usr/local/opt/llvm@15/include"
        }
        
        linkoptions {
            "-Wl,-rpath,/usr/local/opt/llvm@15/lib"
        }

    filter "configurations:Debug"
        defines { "DEBUG" }
        runtime "Debug"
        symbols "on"
        optimize "Off"

    filter "configurations:Release"
        defines { "NDEBUG" }
        runtime "Release"
        symbols "off"
        optimize "Full"
        flags { "LinkTimeOptimization" }