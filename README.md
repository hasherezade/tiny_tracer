# tiny_tracer
A Pin Tool for tracing:
+ API calls 
+ transition between sections of the traced module (helpful in finding OEP of the packed module)

Generates a report in a format:
```
RVA;traced event
```
i.e.
```
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

How to build?
-
To compile the prepared project you need to use [Visual Studio >= 2012](https://visualstudio.microsoft.com/downloads/). It was tested with [Intel Pin 3.7 and Pin 3.10](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).<br/>
Clone this repo into `\source\tools` that is inside your Pin root directory. Open the project in Visual Studio and build. More details about the installation and usage you will find on [the project's Wiki](https://github.com/hasherezade/tiny_tracer/wiki).<br/>
