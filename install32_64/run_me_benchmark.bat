@echo off
rem This script is to be used from the context menu

set TARGET_APP=%~1
set PE_TYPE=%~2
set IS_ADMIN=%~3

if "%TARGET_APP%"=="" goto display_args
if "%PE_TYPE%"=="" goto display_args
goto run_it

:display_args
echo Run a process with TinyTracer, and trace the selected module
echo It is recommended to run this script via installed context menu
echo Required args: [target app] [pe type: dll or exe]
pause
goto finish

:run_it
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

rem The ini file specifying the settings of the tracer
set SETTINGS_FILE=%PIN_TOOLS_DIR%\TinyTracer.ini

rem WATCH_BEFORE - a file with a list of functions which's parameters will be logged before execution
rem The file must be a list of records in a format: [dll_name];[func_name];[parameters_count]
set WATCH_BEFORE=%PIN_TOOLS_DIR%\params.txt

set DLL_LOAD32=%PIN_TOOLS_DIR%\dll_load32.exe
set DLL_LOAD64=%PIN_TOOLS_DIR%\dll_load64.exe

if exist %PIN_TOOLS_DIR%\kdb_check.exe (
	%PIN_TOOLS_DIR%\kdb_check.exe
	if NOT %errorlevel% EQU 0 (
		echo Disable Kernel Mode Debugger before running the PIN tool!
		pause
		exit
	)
)

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

rem The exports that you want to call from a dll, in format: [name1];[name2] or [#ordinal1];[#ordinal2]
set DLL_EXPORTS=""

rem The arguments that you want to pass to the run executable
set EXE_ARGS=""

echo Target module: "%TRACED_MODULE%"
echo Tag file: %TAG_FILE%
if [%IS_ADMIN%] == [A] (
	echo Elevation requested
)

set ADMIN_CMD=%PIN_TOOLS_DIR%\sudo.vbs

set DLL_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -m "%TRACED_MODULE%" -o %TAG_FILE% -s %SETTINGS_FILE% -b "%WATCH_BEFORE%" -- "%DLL_LOAD%" "%TARGET_APP%" %DLL_EXPORTS%
set EXE_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -m "%TRACED_MODULE%" -o %TAG_FILE% -s %SETTINGS_FILE% -b "%WATCH_BEFORE%" -- "%TARGET_APP%" "%EXE_ARGS%"


set start=%time%

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

set end=%time%

set options="tokens=1-4 delims=:.,"
for /f %options% %%a in ("%start%") do set start_h=%%a&set /a start_m=100%%b %% 100&set /a start_s=100%%c %% 100&set /a start_ms=100%%d %% 100
for /f %options% %%a in ("%end%") do set end_h=%%a&set /a end_m=100%%b %% 100&set /a end_s=100%%c %% 100&set /a end_ms=100%%d %% 100

set /a hours=%end_h%-%start_h%
set /a mins=%end_m%-%start_m%
set /a secs=%end_s%-%start_s%
set /a ms=%end_ms%-%start_ms%
if %ms% lss 0 set /a secs = %secs% - 1 & set /a ms = 100%ms%
if %secs% lss 0 set /a mins = %mins% - 1 & set /a secs = 60%secs%
if %mins% lss 0 set /a hours = %hours% - 1 & set /a mins = 60%mins%
if %hours% lss 0 set /a hours = 24%hours%
if 1%ms% lss 100 set ms=0%ms%

:: Mission accomplished
set /a totalsecs = %hours%*3600 + %mins%*60 + %secs%
echo command took %hours%:%mins%:%secs%.%ms% (%totalsecs%.%ms%s total)


if [%IS_ADMIN%] == [A] (
	rem In Admin mode, a new console should be created. Pause only if it failed, in order to display the error:
	if NOT %ERRORLEVEL% EQU 0 pause
) else (
	if %ERRORLEVEL% EQU 0 echo [OK] PIN tracing finished: the traced application terminated.
	rem Pausing script after the application is executed is useful to see all eventual printed messages and for troubleshooting
	pause
)
:finish
