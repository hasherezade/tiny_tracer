@echo off
echo PIN is trying to run the app:
echo %1%

rem PIN_DIR is your root directory of Intel Pin
set PIN_DIR=C:\pin\

rem PIN_TOOLS_DIR is your directory with this script and the Pin Tools
set PIN_TOOLS_DIR=C:\pin_tools\

set PINTOOL32=%PIN_TOOLS_DIR%\TinyTracer32.dll
set PINTOOL64=%PIN_TOOLS_DIR%\TinyTracer64.dll
set PINTOOL=%PINTOOL32%

set TARGET_APP=%1%
rem TRACED_APP - by default it is the main module, but it can be also a DLL within the traced process
set TRACED_APP=%1%
set ENABLE_SHORT_LOGGING=1

%PIN_TOOLS_DIR%\pe_check.exe %TARGET_APP%
if %errorlevel% == 32 (
	echo "32bit version"
	set PINTOOL=%PINTOOL32%
)
if %errorlevel% == 64 (
	echo "64bit version"
	set PINTOOL=%PINTOOL64%
)

set OLDDIR=%CD%
cd %PIN_DIR%
pin.exe -t %PINTOOL% -m %TARGET_APP% -o %TARGET_APP%.tag -s %ENABLE_SHORT_LOGGING% -- %TARGET_APP% 

chdir /d %OLDDIR%