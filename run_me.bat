@echo off
echo PIN is trying to run the app:
echo %1%

set OLDDIR=%CD%

set PIN_DIR=C:\pin
set PINTOOL=C:\pin_tools\TinyTracer.dll

set TARGET_APP=%1%
set TRACED_APP=%1% # by default it is the main module, but it can be also a DLL within the traced process

cd %PIN_DIR%
pin.exe -t %PINTOOL% -m %TARGET_APP% -o %TARGET_APP%.tag -- %TARGET_APP% 

chdir /d %OLDDIR%