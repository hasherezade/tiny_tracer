@echo off
setlocal

REM ------------------------------------------------------------
REM Locate latest Visual Studio installation
REM ------------------------------------------------------------

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`
    "%VSWHERE%" -latest -products * -property installationPath
`) do (
    set "VSROOT=%%i"
)

if "%VSROOT%"=="" (
    echo ERROR: Visual Studio installation not found
    exit /b 1
)

REM ------------------------------------------------------------
REM Optional: initialize VS build environment
REM ------------------------------------------------------------

if exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" (
    call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
)

REM ------------------------------------------------------------
REM Configure PATH
REM ------------------------------------------------------------

set "PATH=C:\msys64\usr\bin;%VSROOT%\VC\Tools\Llvm\x64\bin;C:\msys64\mingw64\bin;%PATH%"

REM ------------------------------------------------------------
REM Run make
REM ------------------------------------------------------------

C:\msys64\mingw64\bin\mingw32-make.exe %*

