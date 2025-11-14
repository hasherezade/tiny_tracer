# Installation on Windows

0. Put the compiled tools in this directory, renamed accordingly:
- TinyTracer32.dll (32-bit build)
- TinyTracer64.dll (64-bit build)
1. Edit the run_me.bat:
- Replace PIN_DIR (default: C:\pin) with your own path to the Pin directory.
- Replace PIN_TOOLS_DIR (default: C:\pin\source\tools\tiny_tracer\install32_64\) with the path to the folder containing this bundle (scripts, tools + other utils).
2. Edit add_menu.reg and replace the path to the run_me.bat with its actual path (in your PIN_TOOLS_DIR).
3. Run add_menu.reg to add the Pin tool to the context menu
4. Now you can trace any EXE by clicking "Run with PIN" from the context menu.
5. Whenever you want to uninstall it, just run "delete_menu.reg"

# Installation on Linux

Read the instructions inside `tiny_runner.sh`
