@echo off
rem This script is to be used from the command line

set TARGET_APP=%~1
set TARGET_PID=%~2

if "%TARGET_PID%"=="" goto display_args
if "%TARGET_APP%"=="" goto display_args
goto attach

:display_args
echo Attach TinyTracer to a process, and trace the selected module
echo Required args: [target module path] [target pid]
pause
goto finish

:attach
echo PIN is trying to attach to the app:
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

rem The ini file specifying the settings of the tracer
set SETTINGS_FILE=%PIN_TOOLS_DIR%\TinyTracer.ini

rem WATCH_BEFORE - a file with a list of functions which's parameters will be logged before execution
rem The file must be a list of records in a format: [dll_name];[func_name];[parameters_count]
set WATCH_BEFORE=%PIN_TOOLS_DIR%\params.txt

rem SYSCALLS_TABLE - a CSV file, mapping syscall ID to a function name. Format: [syscallID:hex],[functionName]
set SYSCALLS_TABLE=%PIN_TOOLS_DIR%\syscalls.txt

%PIN_TOOLS_DIR%\kdb_check.exe
if NOT %errorlevel% EQU 0 (
	echo Disable Kernel Mode Debugger before running the PIN tool!
	pause
	goto finish
)

if NOT exist %SYSCALLS_TABLE% (
	if exist %PIN_TOOLS_DIR%\syscall_extract.exe (
		%PIN_TOOLS_DIR%\syscall_extract.exe %SYSCALLS_TABLE%
	)
)

%PIN_TOOLS_DIR%\pe_check.exe "%TARGET_APP%"
if %errorlevel% == 32 (
	echo 32bit selected
	set PINTOOL=%PINTOOL32%
)
if %errorlevel% == 64 (
	echo 64bit selected
	set PINTOOL=%PINTOOL64%
)

rem The exports that you want to call from a dll, in format: [name1];[name2] or [#ordinal1];[#ordinal2]
set DLL_EXPORTS=""

echo Target module: "%TRACED_MODULE%"
echo Tag file: %TAG_FILE%

set EXE_CMD=%PIN_DIR%\pin.exe -pid %TARGET_PID% -t "%PINTOOL%" -m "%TRACED_MODULE%" -o %TAG_FILE% -s "%SETTINGS_FILE%" -l "%SYSCALLS_TABLE%" -b "%WATCH_BEFORE%" 

;rem "Trace EXE"
%EXE_CMD%

if %ERRORLEVEL% EQU 0 echo [OK] PIN tracing finished: the traced application terminated.
rem Pausing script after the application is executed is useful to see all eventual printed messages and for troubleshooting
pause
:finish
