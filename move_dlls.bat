rem First, compile the 32 and 64 bit version of TinyTracer. Then, you can use this script to copy them into the directory with the run_me.bat (default: install32_64).
move Release\TinyTracer.dll install32_64\TinyTracer32.dll
move x64\Release\TinyTracer.dll install32_64\TinyTracer64.dll
pause
