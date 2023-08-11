@echo off
setlocal enabledelayedexpansion

set search_dir=%1
echo Supplied SDK path: %search_dir%
if not defined search_dir (
    if EXIST "%PROGRAMFILES(X86)%" (
        set search_dir="%PROGRAMFILES(X86)%\Windows Kits\"
    ) else (
        set search_dir="%PROGRAMFILES%\Windows Kits\"
    )
)

set output_file="win\my_paths.h"
set header_name="Windows.h"

for /r %search_dir% %%i in (*%header_name%) do (
    set "sdir=%%~dpi"
)

if defined sdir (
    echo|(set /p="#define _WINDOWS_H_PATH_ %sdir:\=/%") > %output_file%
    echo Header subdirectory path found and saved to %output_file%.
) else (
    echo Header path not found.
)
endlocal
goto :eof
