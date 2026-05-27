@echo off
setlocal

set "ROOT=%~dp0"
set "TARGET_DIR=%ROOT%install32_64"

set "TT_BUILD_32=TinyTracer32.dll"
set "TT_BUILD_64=TinyTracer64.dll"

set "TT_32=%ROOT%obj-ia32\%TT_BUILD_32%"
set "TT_64=%ROOT%obj-intel64\%TT_BUILD_64%"

set "DST_32=%TARGET_DIR%\%TT_BUILD_32%"
set "DST_64=%TARGET_DIR%\%TT_BUILD_64%"

if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%"
    if errorlevel 1 (
        echo ERROR: Could not create install directory: "%TARGET_DIR%"
        exit /b 1
    )
)

if exist "%DST_32%" del /q "%DST_32%"
if exist "%DST_64%" del /q "%DST_64%"

if not exist "%TT_32%" (
    echo ERROR: Could not find 32-bit build output: "%TT_32%"
    exit /b 1
)

if not exist "%TT_64%" (
    echo ERROR: Could not find 64-bit build output: "%TT_64%"
    exit /b 1
)

copy /y "%TT_32%" "%DST_32%" >nul
if errorlevel 1 (
    echo ERROR: 32-bit install failed.
    exit /b 1
)
echo [+] 32-bit install ok: "%DST_32%"

copy /y "%TT_64%" "%DST_64%" >nul
if errorlevel 1 (
    echo ERROR: 64-bit install failed.
    exit /b 1
)
echo [+] 64-bit install ok: "%DST_64%"

echo [+] TinyTracer install complete.
exit /b 0
