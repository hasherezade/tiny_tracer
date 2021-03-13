@echo off

set TARGET_APP=%~1
set PE_TYPE=%~2
set IS_ADMIN=%~3
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
set TRACE_RDTSC=0

rem WATCH_BEFORE - a file with a list of functions which's parameters will be logged before execution
rem The file must be a list of records in a format: [dll_name];[func_name];[parameters_count]
set WATCH_BEFORE=%PIN_TOOLS_DIR%\params.txt

set DLL_LOAD32=%PIN_TOOLS_DIR%\dll_load32.exe
set DLL_LOAD64=%PIN_TOOLS_DIR%\dll_load64.exe

%PIN_TOOLS_DIR%\pe_check.exe "%TARGET_APP%"
if %errorlevel% == 32 (
	echo 32bit selected
	set PINTOOL=%PINTOOL32%
	set DLL_LOAD=%DLL_LOAD32%
)
if %errorlevel% == 64 (
	echo 64bit selected
	set PINTOOL=%PINTOOL64%
	set DLL_LOAD=%DLL_LOAD64%
)

echo Target module: "%TRACED_MODULE%"
echo Tag file: %TAG_FILE%
if [%IS_ADMIN%] == [A] (
	echo Elevation requested
)

set ADMIN_CMD=%PIN_TOOLS_DIR%\sudo.vbs

set DLL_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -m "%TRACED_MODULE%" -o %TAG_FILE% -f %FOLLOW_SHELLCODES% -d %TRACE_RDTSC% -s %ENABLE_SHORT_LOGGING% -b "%WATCH_BEFORE%" -- "%DLL_LOAD%" "%TARGET_APP%"
set EXE_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -m "%TRACED_MODULE%" -o %TAG_FILE% -f %FOLLOW_SHELLCODES% -d %TRACE_RDTSC% -s %ENABLE_SHORT_LOGGING% -b "%WATCH_BEFORE%" -- "%TARGET_APP%" 

;rem "Trace EXE"
if [%PE_TYPE%] == [exe] (
	if [%IS_ADMIN%] == [A] (
		%ADMIN_CMD% %EXE_CMD%
	) else (
		%EXE_CMD%
	)
)
;rem "Trace DLL"
if [%PE_TYPE%] == [dll] (
	if [%IS_ADMIN%] == [A] (
		%ADMIN_CMD% %DLL_CMD%
	) else (
		%DLL_CMD%
	)
)

if [%IS_ADMIN%] == [A] (
	rem In Admin mode, a new console should be created. Pause only if it failed, in order to display the error:
	if NOT %ERRORLEVEL% EQU 0 pause
) else (
	if %ERRORLEVEL% EQU 0 echo [OK] PIN tracing finished: the traced application terminated.
	rem Pausing script after the application is executed is useful to see all eventual printed messages and for troubleshooting
	pause
)


