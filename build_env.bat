@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "VS_ARCH="
set "MAKE_TARGET="
set "MAKE_ARGS="
set "EXPECT_TARGET_VALUE=0"

if /I "%~1"=="x64" (
    set "VS_ARCH=x64"
    set "MAKE_TARGET=intel64"
    shift
) else if /I "%~1"=="x86" (
    set "VS_ARCH=amd64_x86"
    set "MAKE_TARGET=ia32"
    shift
)

:collect_args
if "%~1"=="" goto args_done

set "ARG=%~1"

if "!EXPECT_TARGET_VALUE!"=="1" (
    if /I "!ARG!"=="intel64" set "MAKE_TARGET=intel64"
    if /I "!ARG!"=="ia32" set "MAKE_TARGET=ia32"
    set "EXPECT_TARGET_VALUE=0"
    shift
    goto collect_args
)

if /I "!ARG!"=="TARGET" (
    set "EXPECT_TARGET_VALUE=1"
    shift
    goto collect_args
)

if /I "!ARG:~0,7!"=="TARGET=" (
    set "MAKE_TARGET=!ARG:~7!"
    shift
    goto collect_args
)

set "MAKE_ARGS=!MAKE_ARGS! !ARG!"
shift
goto collect_args

:args_done

if not defined MAKE_TARGET (
    set "MAKE_TARGET=intel64"
)

if not defined VS_ARCH (
    if /I "%MAKE_TARGET%"=="ia32" (
        set "VS_ARCH=amd64_x86"
    ) else (
        set "VS_ARCH=x64"
    )
)

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

if not exist "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo ERROR: vcvarsall.bat not found
    exit /b 1
)

echo [*] Initializing Visual Studio environment: %VS_ARCH%
call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" %VS_ARCH%
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio environment: %VS_ARCH%
    exit /b 1
)

set "PATH=C:\msys64\usr\bin;%VSROOT%\VC\Tools\Llvm\x64\bin;C:\msys64\mingw64\bin;%PATH%"

echo [*] Running: C:\msys64\mingw64\bin\mingw32-make.exe%MAKE_ARGS% TARGET=%MAKE_TARGET%
C:\msys64\mingw64\bin\mingw32-make.exe%MAKE_ARGS% TARGET=%MAKE_TARGET%

exit /b %ERRORLEVEL%
