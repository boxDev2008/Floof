workspace "Floof"
    architecture "x64"
    configurations { "Debug", "Release" }
    startproject "floof"

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
        systemversion "latest"

        -- LLVM on Linux is typically a single shared library: libLLVM.so
        links {
            "LLVM",

            -- Required system libraries LLVM depends on
            "pthread",
            "dl",
            "z",
            "m",
            "tinfo"
        }

        -- Ensure the runtime loader can find libLLVM.so
        linkoptions {
            "-Wl,-rpath," .. llvm_libdir
        }

        -- LLVM expects these on Linux
        defines {
            "__STDC_CONSTANT_MACROS",
            "__STDC_FORMAT_MACROS",
            "__STDC_LIMIT_MACROS"
        }

        -- Clang/GCC warnings LLVM headers expect
        buildoptions {
            "-fPIC"
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