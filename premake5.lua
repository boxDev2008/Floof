workspace "Floof"
    architecture "x64"
    configurations { "Debug", "Release" }
    startproject "floof"

local llvm_prefix
local llvm_libdir
local llvm_includedir

if os.host() == "windows" then
    llvm_prefix = os.getenv("LLVM_DIR")
    llvm_libdir = path.join(llvm_prefix, "lib")
    llvm_includedir = path.join(llvm_prefix, "include")
end

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
        "src/vendor"
    }

    filter "system:windows"
        includedirs { llvm_includedir }
        libdirs { llvm_libdir }

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
            "LLVMDebugInfoDWARFLowLevel",
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
            "LLVMInstrumentation",
            "LLVMipo",
            "LLVMTargetParser",
            "LLVMIRPrinter",
            "LLVMCodeGenTypes",
            "LLVMCGData",
            "version",
            "ntdll"
        }

    filter "system:linux"
        systemversion "latest"

        links {
            "LLVM",
            "pthread",
            "dl",
            "z",
            "m",
            "tinfo"
        }

        defines {
            "__STDC_CONSTANT_MACROS",
            "__STDC_FORMAT_MACROS",
            "__STDC_LIMIT_MACROS"
        }

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

    filter {}