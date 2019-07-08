@echo off

set TARGET_APP=%~1
echo PIN is trying to run the app:
echo "%TARGET_APP%"

rem PIN_DIR is your root directory of Intel Pin
set PIN_DIR=C:\pin\

rem PIN_TOOLS_DIR is your directory with this script and the Pin Tools
set PIN_TOOLS_DIR=C:\pin\source\tools\tiny_tracer\install32_64\

set PINTOOL32=%PIN_TOOLS_DIR%\TinyTracer32.dll
set PINTOOL64=%PIN_TOOLS_DIR%\TinyTracer64.dll
set PINTOOL=%PINTOOL32%

rem TRACED_MODULE - by default it is the main module, but it can be also a DLL within the traced process
set TRACED_MODULE=%TARGET_APP%

set TAG_FILE="%TRACED_MODULE%.tag"
set ENABLE_SHORT_LOGGING=1
set FOLLOW_SHELLCODES=1

%PIN_TOOLS_DIR%\pe_check.exe "%TARGET_APP%"
if %errorlevel% == 32 (
	echo 32bit selected
	set PINTOOL=%PINTOOL32%
)
if %errorlevel% == 64 (
	echo 64bit selected
	set PINTOOL=%PINTOOL64%
)

echo Target module: "%TRACED_MODULE%"
echo Tag file: %TAG_FILE%

%PIN_DIR%\pin.exe -t %PINTOOL% -m "%TRACED_MODULE%" -o %TAG_FILE% -f %FOLLOW_SHELLCODES% -s %ENABLE_SHORT_LOGGING% -- "%TARGET_APP%" 

if %ERRORLEVEL% EQU 0 echo [OK] PIN tracing finished: the traced application terminated.
rem Pausing script after the application is executed is useful to see all eventual printed messages and for troubleshooting
pause
