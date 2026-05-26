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

You can build it on Windows or on Linux. Detailed descriptions available [here](https://github.com/hasherezade/tiny_tracer/wiki/Installation).

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
