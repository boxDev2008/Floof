@echo off
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

if /I "%CONFIG%"=="Debug" (
    set "CXXFLAGS=/std:c++20 /Od /Zi /MDd /DDEBUG"
    set "OUTDIR=bin\Debug-Windows-x64"
) else if /I "%CONFIG%"=="Release" (
    set "CXXFLAGS=/std:c++20 /O2 /MD /DNDEBUG /flto"
    set "OUTDIR=bin\Release-Windows-x64"
) else (
    echo Usage: build.bat [Debug^|Release]
    exit /b 1
)

if "%LLVM_DIR%"=="" (
    echo LLVM_DIR is not set.
    echo Set LLVM_DIR to your LLVM installation directory.
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

clang-cl ^
    %CXXFLAGS% ^
    /I"src" ^
    /I"src\vendor" ^
    /I"%LLVM_DIR%\include" ^
    /Fe:"%OUTDIR%\floof.exe" ^
    src\main.cpp ^
    /link ^
    /LIBPATH:"%LLVM_DIR%\lib" ^
    LLVMCore.lib ^
    LLVMSupport.lib ^
    LLVMIRReader.lib ^
    LLVMCodeGen.lib ^
    LLVMMC.lib ^
    LLVMMCParser.lib ^
    LLVMOption.lib ^
    LLVMBitWriter.lib ^
    LLVMBitReader.lib ^
    LLVMTarget.lib ^
    LLVMX86CodeGen.lib ^
    LLVMX86AsmParser.lib ^
    LLVMX86Desc.lib ^
    LLVMX86Info.lib ^
    LLVMAsmPrinter.lib ^
    LLVMSelectionDAG.lib ^
    LLVMScalarOpts.lib ^
    LLVMInstCombine.lib ^
    LLVMTransformUtils.lib ^
    LLVMAnalysis.lib ^
    LLVMObject.lib ^
    LLVMMCDisassembler.lib ^
    LLVMExecutionEngine.lib ^
    LLVMipo.lib ^
    LLVMVectorize.lib ^
    LLVMAsmParser.lib ^
    LLVMTableGen.lib ^
    LLVMDebugInfoCodeView.lib ^
    LLVMDebugInfoMSF.lib ^
    LLVMDebugInfoDWARF.lib ^
    LLVMDebugInfoDWARFLowLevel.lib ^
    LLVMGlobalISel.lib ^
    LLVMBinaryFormat.lib ^
    LLVMRemarks.lib ^
    LLVMBitstreamReader.lib ^
    LLVMAggressiveInstCombine.lib ^
    LLVMProfileData.lib ^
    LLVMDemangle.lib ^
    LLVMTextAPI.lib ^
    LLVMFrontendOpenMP.lib ^
    LLVMObjCARCOpts.lib ^
    LLVMPasses.lib ^
    LLVMCFGuard.lib ^
    LLVMInstrumentation.lib ^
    LLVMTargetParser.lib ^
    LLVMIRPrinter.lib ^
    LLVMCodeGenTypes.lib ^
    LLVMCGData.lib ^
    version.lib ^
    ntdll.lib

if errorlevel 1 exit /b %errorlevel%

echo Built %OUTDIR%\floof.exe