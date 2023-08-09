@echo off
setlocal enabledelayedexpansion

set search_dir="C:\Program Files (x86)\Windows Kits\"
set output_file="my_paths.h"
set header_name="Windows.h"

for /r "C:\Program Files (x86)\Windows Kits\" %%i in (*%header_name%) do (
    set "sdir=%%~dpi"
	echo %%~dpi
)

if defined sdir (
	echo|(set /p="#define _WINDOWS_H_PATH_ %sdir:\=/%") > %output_file%
    echo Header subdirectory path found and saved to %output_file%.
) else (
    echo Header path not found.
)
endlocal
goto :eof

