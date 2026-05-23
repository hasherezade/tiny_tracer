# tiny_tracer
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/f988180bfb4d45ebbe4764bde1058c2f)](https://app.codacy.com/gh/hasherezade/tiny_tracer/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hasherezade/tiny_tracer)](https://github.com/hasherezade/tiny_tracer/commits)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/tiny_tracer/master)](https://github.com/hasherezade/tiny_tracer/commits)
[![Build status](https://ci.appveyor.com/api/projects/status/543ql60gxxuri9j2?svg=true)](https://ci.appveyor.com/project/hasherezade/tiny-tracer)

[![GitHub release](https://img.shields.io/github/release/hasherezade/tiny_tracer.svg)](https://github.com/hasherezade/tiny_tracer/releases)
[![GitHub release date](https://img.shields.io/github/release-date/hasherezade/tiny_tracer?color=blue)](https://github.com/hasherezade/tiny_tracer/releases)


A Pin Tool for tracing:
+  API calls, including [input and output of selected functions](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-function-input-and-output)
+  [defined local functions](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-defined-local-functions)
+  selected instructions: [RDTSC](https://c9x.me/x86/html/file_module_x86_id_278.html), [CPUID](https://c9x.me/x86/html/file_module_x86_id_45.html), [INT](https://c9x.me/x86/html/file_module_x86_id_142.html)
+  [inline system calls, including parameters of selected syscalls](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-syscalls)
+  transition between sections of the traced module (helpful in finding OEP of the packed module)
+  [executed instructions in defined code fragments](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-with-disassembly)

Evades some of the known [anti-debug](https://github.com/hasherezade/tiny_tracer/wiki/The-INI-file#antidebug) and [anti-VM](https://github.com/hasherezade/tiny_tracer/wiki/The-INI-file#antivm) techniques

Generates a report in a `.tag` format (which can be [loaded into other analysis tools](https://github.com/hasherezade/tiny_tracer/wiki/Using-the-TAGs-with-disassemblers-and-debuggers)):

```txt
RVA;traced event
```
i.e.

```txt
345c2;section: .text
58069;called: C:\Windows\SysWOW64\kernel32.dll.IsProcessorFeaturePresent
3976d;called: C:\Windows\SysWOW64\kernel32.dll.LoadLibraryExW
3983c;called: C:\Windows\SysWOW64\kernel32.dll.GetProcAddress
3999d;called: C:\Windows\SysWOW64\KernelBase.dll.InitializeCriticalSectionEx
398ac;called: C:\Windows\SysWOW64\KernelBase.dll.FlsAlloc
3995d;called: C:\Windows\SysWOW64\KernelBase.dll.FlsSetValue
49275;called: C:\Windows\SysWOW64\kernel32.dll.LoadLibraryExW
4934b;called: C:\Windows\SysWOW64\kernel32.dll.GetProcAddress
...
```

## 🚧 How to build

It was tested with [Intel Pin 4.2](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).

### On Windows

To compile you need [MSYS2](https://www.msys2.org/) and `clang-cl`.

You can get `clang-cl` in one of two ways:
- **With Visual Studio 2022**: Install the **C++ Clang tools for Windows** component via the Visual Studio Installer. The compiler will be at:
  `C:\Program Files\Microsoft Visual Studio\2022\<edition>\VC\Tools\Llvm\x64\bin\clang-cl.exe`
- **Without Visual Studio**: Download and install the standalone LLVM package from [LLVM GitHub releases](https://github.com/llvm/llvm-project/releases) (look for `LLVM-<version>-win64.exe`). The compiler will be at:
  `C:\Program Files\LLVM\bin\clang-cl.exe`

**Steps:**

1. Install the `mingw-w64-x86_64-make` package in MSYS2:
   ```
   pacman -S mingw-w64-x86_64-make
   ```

2. Clone this repo into `\source\tools` inside your Pin root directory.

3. Open the **MSYS2 MINGW64** shell and navigate to the project:
   ```
   cd /c/pin/source/tools/tiny_tracer
   ```

4. Make sure `clang-cl` is on your PATH:
   ```
   # If installed via Visual Studio:
   export PATH="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin:$PATH"

   # If installed standalone:
   export PATH="/c/Program Files/LLVM/bin:$PATH"
   ```

5. Build:
   ```
   bash make_mingw.sh
   ```

**Using Visual Studio as IDE (optional):** Open the `tiny_tracer` folder via **File -> Open -> Folder**. The included `CppProperties.json` and `.vs/tasks.vs.json` provide IntelliSense and build integration. The build still goes through the makefile - Visual Studio is used only as an editor.

To build with Intel Pin < 4.0 on Windows, use the older versions of TinyTracer that can be found in the releases.

### On Linux

For now the support for Linux is experimental. Yet it is possible to build and use Tiny Tracer on Linux as well. Please refer [tiny_runner.sh](https://github.com/hasherezade/tiny_tracer/blob/master/install32_64/tiny_runner.sh) for more information.
Detailed description available [here](https://github.com/hasherezade/tiny_tracer/wiki/Installation#on-linux).

## ⚙ Usage

📖 Details about the usage you will find on [the project's Wiki](https://github.com/hasherezade/tiny_tracer/wiki).<br/>

## 🛠 Helpers

For automatic generation of [`params.txt` for API arguments tracing](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-parameters-of-functions), try [IAT-Tracer](https://github.com/YoavLevi/IAT-Tracer) by [YoavLevi](https://github.com/YoavLevi)


## WARNINGS

+  In order for Pin to work correctly, Kernel Debugging must be **DISABLED**.
+  In [`install32_64`](https://github.com/hasherezade/tiny_tracer/tree/master/install32_64) you can find a utility that checks if Kernel Debugger is disabled (`kdb_check.exe`, [source](https://github.com/hasherezade/pe_utils/tree/master/kdb_check)), and it is used by the Tiny Tracer's `.bat` scripts. This utilty sometimes gets flagged as a malware by Windows Defender (it is a known false positive). If you encounter this issue, you may need to [exclude](https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26) the installation directory from Windows Defender scans.
+  Since the version 3.20 Pin has dropped a support for **old versions of Windows**. If you need to use the tool on Windows < 8, try to compile it with Pin 3.19.


---

🤔 Questions? Ideas? Join [Discussions](https://github.com/hasherezade/tiny_tracer/discussions)!

---
