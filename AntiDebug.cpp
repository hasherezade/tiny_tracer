#include "AntiDebug.h"

#include <iostream>

#include "ProcessInfo.h"
#include "Util.h"
#include "TraceLog.h"
#include "Settings.h"
#include "PinLocker.h"

#include "my_paths.h"
#include "win_constants.h"

/* ================================================================== */
// Global variables used by AntiDebug
/* ================================================================== */
ADDRINT pebAddr = 0;
ADDRINT heapFlags = 0;
ADDRINT heapForceFlags = 0;
std::vector<std::string> loadedLib;

enum class WatchedType {
    NOT_WATCHED = 0,
    WATCHED_MY_MODULE,
    WATCHED_SHELLCODE
};

extern TraceLog traceLog;
extern Settings m_Settings;
extern WatchedType isWatchedAddress(const ADDRINT Address);
extern std::wstring paramToStr(VOID* arg1);
extern VOID LogFunctionArgs(const ADDRINT Address, CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10);


/* ==================================================================== */
// Function to check if is native 32 bit or not
/* ==================================================================== */

typedef BOOL WINAPI IsWow64Process_T(WINDOWS::HANDLE,WINDOWS::PBOOL);

BOOL IsNativeOs32(void)
{
    BOOL isNativeOs32 = FALSE;
    if (sizeof(void*) == 4)
    {
        BOOL isWow64 = FALSE;
        WINDOWS::IsWow64Process(WINDOWS::GetCurrentProcess(), (WINDOWS::PBOOL) &isWow64);
        isNativeOs32 = !isWow64;
    }

    return isNativeOs32;
}

/* ==================================================================== */
// Callback function to be executed when memory is accessed
/* ==================================================================== */

VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr)
{
    PinLocker locker;

    if (isWatchedAddress(insAddr) == WatchedType::NOT_WATCHED) return;

    std::wstringstream ss;

    ADDRINT RvaFrom = addr_to_rva(insAddr);
    
    // Check the accessed memory address for antidebug tricks
    if (addr == pebAddr + 2) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> PEB!BeingDebugged accessed";
    }
    else
    if (addr == 0x7ffe02d4) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> KUSER_SHARED_DATA accessd https://anti-debug.checkpoint.com/techniques/debug-flags.html#kuser_shared_data";
    } else
#ifdef _WIN64
    if (addr == pebAddr + 0xBC) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> PEB!NtGlobalFlag  accessed";
    } else
    if (addr == heapFlags || addr == heapForceFlags) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> Heap Flags accessed https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags";
    }
#else
    if (addr == pebAddr + 0x68) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> PEB!NtGlobalFlag  accessed";
    } else
    if (addr == heapFlags || addr == heapForceFlags) {
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] --> Heap Flags accessed https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags";
    } 
#endif

    if (!ss.str().empty()) {
        // Write out to log
        std::wstring argsLineW = ss.str();
        std::string s(argsLineW.begin(), argsLineW.end());
        traceLog.logLine(s);
    }
}

/* ==================================================================== */
// Process API calls (defined in params.txt)
/* ==================================================================== */

VOID AntidebugProcessFunctions(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10)
{
    std::wstringstream ss;

    ADDRINT RvaFrom = addr_to_rva(Address);

    ///////////////////////////////////////////////////////////////////////////////
    // Check known function names for antidebug tricks, then parameters (if needed)
    ///////////////////////////////////////////////////////////////////////////////
    // TODO: not sure if it's better to use isStrEqualI or strcmp
    if (strcmp(name, "IsDebuggerPresent") == 0) {
        // function kernel32!IsDebuggerPresent()
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!IsDebuggerPresent https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-isdebuggerpresent";
    } else
    if (strcmp(name, "CheckRemoteDebuggerPresent") == 0) {
        // function kernel32!CheckRemoteDebuggerPresent()
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!CheckRemoteDebuggerPresent https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checkremotedebuggerpresent";
    } else
    if (strcmp(name, "NtQueryInformationProcess") == 0) {
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 7 (ProcessDebugPort)
        if (int((size_t)arg2) == PROCESSDEBUGPORT) {
            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!NtQueryInformationProcess https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugport";
        } else
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1f (ProcessDebugFlags)
        if (int((size_t)arg2) == PROCESSDEBUGFLAGS) {
            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!NtQueryInformationProcess https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugflags";
        } else
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1e (ProcessDebugObjectHandle)
        if (int((size_t)arg2) == PROCESSDEBUGOBJECTHANDLE) {
            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!NtQueryInformationProcess https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle";
        }
    } else
    if (strcmp(name, "RtlQueryProcessHeapInformation") == 0) {
        // function ntdll!RtlQueryProcessHeapInformation()
        // FIXME possible improvement: check access to the buffer parameter of the function
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!RtlQueryProcessHeapInformation https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessheapinformation";
    } else
    if (strcmp(name, "RtlQueryProcessDebugInformation") == 0) {
        // function ntdll!RtlQueryProcessDebugInformation()
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!RtlQueryProcessDebugInformation https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessdebuginformation";
    } else
    if (strcmp(name, "NtQuerySystemInformation") == 0) {
        // function ntdll!NtQuerySystemInformation() with first parameter set to 0x23 (SystemKernelDebuggerInformation)
        if (int((size_t)arg1) == SYSTEMKERNELDEBUGGERINFORMATION) {
            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!NtQuerySystemInformation https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-ntquerysysteminformation";
        }
    } else
    if (strcmp(name, "HeapWalk") == 0) {
        // kernel32!HeapWalk() function to extract Heap blocks and check the tail
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!HeapWalk https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection";
    } else
    if (strcmp(name, "CsrGetProcessId") == 0) {
        // kernel32!OpenProcess() function on the csrss.exe - CsrGetProcessId get the csrss.exe PID
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!OpenProcess/CsrGetProcessId https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess";
    } else
    if (strcmp(name, "CreateFileA") == 0 || strcmp(name, "CreateFileW") == 0) {
        // kernel32!CreateFileX called on the module itself with Exclusive access, or on loaded libraries
        // Check only exclusive accesses for optimization
        if (int((size_t)arg3) == 0) {
            IMG img = IMG_FindByAddress(Address);
            if (IMG_Valid(img))
            {
                // Get the module name from image
                std::string moduleName = IMG_Name(img);
                // Get the module name from arguments
                std::wstring argStr = paramToStrSplit(arg1);
                // Convert from wide string for comparison
                std::string _argStr(argStr.begin(), argStr.end());
                // Check if open is done on module
                if (util::isStrEqualI(_argStr, moduleName)) {
                    ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!CreateFile on module https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile";
                }
                else {
                    // Check if open is done on loaded libraries
                    for (int i = 0; i < loadedLib.size(); i++)
                        if (util::isStrEqualI(_argStr, loadedLib[i])) {
                            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!CreateFile on loaded lib https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary";
                        }
                }
            }
        } 
    } else
    if (strcmp(name, "SetUnhandledExceptionFilter") == 0) {
        // kernel32!SetUnhandledExceptionFilter() function to set a specific handler
        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!SetUnhandledExceptionFilter https://anti-debug.checkpoint.com/techniques/exceptions.html#unhandledexceptionfilter";
    } else
    if (strcmp(name, "RaiseException") == 0) {
        // kernel32!RaiseException() with DBG_CONTROL_C or DBG_RIPEVENT
        if (int((size_t)arg1) == DBG_CONTROL_C || int((size_t)arg1) == DBG_RIPEVENT) {
            ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!RaiseException() https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception";
        }
    } else
    if (strcmp(name, "LoadLibraryA") == 0 || strcmp(name, "LoadLibraryW") == 0) {
        // Track LoadLibraryX to detect access to LOAD_DLL_DEBUG_INFO
        // Get the library name from argument
        std::wstring argStr = paramToStrSplit(arg1);
        // Convert from wide string for comparison
        std::string _argStr(argStr.begin(), argStr.end());
        loadedLib.push_back(_argStr);
    } else
    ////////////////////////////////////
    // If AntiDebug level is == 2 (Deep)
    ////////////////////////////////////
    if (m_Settings.antidebug > 1) {
        if (strcmp(name, "NtQueryObject") == 0) {
            // ntdll!NtQueryObject() to access DebugObject (with ObjectTypesInformation as 2nd argument)
            if (int((size_t)arg2) == OBJECTTYPESINFORMATION) {
                ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ ntdll!NtQueryObject (with ObjectAllTypesInformation) https://anti-debug.checkpoint.com/techniques/object-handles.html#ntqueryobject";
            }
        }
    }

    if (!ss.str().empty()) {
        // Write out to log
        std::wstring argsLineW = ss.str();
        std::string s(argsLineW.begin(), argsLineW.end());
        traceLog.logLine(s);
    }
}

/* ==================================================================== */
// Collect some infos at Thread start, to be used later in checks
/* ==================================================================== */

VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PinLocker locker;

    // Checks only the first thread
    if (threadid != 0) {
        return;
    }
#ifdef _WIN64
    // Read the value from the memory address pointed by GS:[60h] and save it in the global variable
    ADDRINT gsValue;
    PIN_GetContextRegval(ctxt, REG_SEG_GS_BASE, reinterpret_cast<UINT8*>(&gsValue));
    gsValue += 0x60;

    // Save PEB Address
    PIN_SafeCopy(&pebAddr, reinterpret_cast<VOID*>(gsValue), sizeof(pebAddr));

    // Get Heap flags addresses (https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags)
    ADDRINT heapBase;
    PIN_SafeCopy(&heapBase, reinterpret_cast<VOID*>(pebAddr + 0x30), sizeof(heapBase));
    ADDRINT heapFlagsOffset = WINDOWS::IsWindowsVistaOrGreater()
        ? 0x70
        : 0x14;
    ADDRINT heapForceFlagsOffset = WINDOWS::IsWindowsVistaOrGreater()
        ? 0x74
        : 0x18;
    heapFlags = heapBase + heapFlagsOffset;
    heapForceFlags = heapBase + heapForceFlagsOffset;
#else
    // Read the value from the memory address pointed by FS:[30h] and save it in the global variable
    ADDRINT fsValue;
    PIN_GetContextRegval(ctxt, REG_SEG_FS_BASE, reinterpret_cast<UINT8*>(&fsValue));
    fsValue += 0x30;

    // Save PEB Address
    PIN_SafeCopy(&pebAddr, reinterpret_cast<VOID*>(fsValue), sizeof(pebAddr));

    // Get Heap flags addresses (https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags)
    ADDRINT heapBase;
    ADDRINT heapBaseOffset = IsNativeOs32()
        ? 0x18
        : 0x1030;
    PIN_SafeCopy(&heapBase, reinterpret_cast<VOID*>(pebAddr + heapBaseOffset), sizeof(heapBase));
    ADDRINT heapFlagsOffset = WINDOWS::IsWindowsVistaOrGreater()
        ? 0x40
        : 0x0C;
    ADDRINT heapForceFlagsOffset = WINDOWS::IsWindowsVistaOrGreater()
        ? 0x44
        : 0x10;
    heapFlags = heapBase + heapFlagsOffset;
    heapForceFlags = heapBase + heapForceFlagsOffset;
#endif 
}

//* ==================================================================== */
// "CloseHandle" instrumentation, detects invalid handlers
/* ===================================================================== */

VOID AntidebugCloseHandle(ADDRINT Address, ADDRINT regGAX)
{
    PinLocker locker;

    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    if (regGAX == 0) {
        // Invalid closure
        std::wstringstream ss;
        ADDRINT RvaFrom = addr_to_rva(Address);

        ss << std::hex << RvaFrom << ";[ANTIDEBUG] -->^ kernel32!CloseHandle https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle";

        if (!ss.str().empty()) {
            // Write out to log
            std::wstring argsLineW = ss.str();
            std::string s(argsLineW.begin(), argsLineW.end());
            traceLog.logLine(s);
        }
    }
}

/* ==================================================================== */
// Add to monitored functions all the API needed for AntiDebug.
// Called by ImageLoad
/* ==================================================================== */

VOID AntidebugMonitorFunctions(IMG Image, FuncWatchList funcWatch)
{
    // API needed for Antidebug
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "ntdll")) {
        AntidebugMonitorAdd(Image, "CsrGetProcessId", 0, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "NtQueryInformationProcess", 5, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "RtlQueryProcessHeapInformation", 1, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "RtlQueryProcessDebugInformation", 3, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "NtQuerySystemInformation", 4, dllName, funcWatch);
        if (m_Settings.antidebug > 1) {
            // For Deep or above
            AntidebugMonitorAdd(Image, "NtQueryObject", 5, dllName, funcWatch);
        }
    }
    if (util::iequals(dllName, "kernel32")) {
        AntidebugMonitorAdd(Image, "LoadLibraryW", 1, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "LoadLibraryA", 1, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "GetProcAddress", 2, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "CreateFileW", 6, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "CreateFileA", 7, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "OpenProcess", 3, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "IsDebuggerPresent", 0, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "CheckRemoteDebuggerPresent", 2, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "HeapWalk", 2, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "CloseHandle", 1, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "SetUnhandledExceptionFilter", 1, dllName, funcWatch);
        AntidebugMonitorAdd(Image, "RaiseException", 4, dllName, funcWatch);
    }

    // CloseHandle return value hook
    RTN funcRtn = RTN_FindByName(Image, "CloseHandle");
    if (!RTN_Valid(funcRtn)) return; // failed

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn, IPOINT_AFTER, AFUNPTR(AntidebugCloseHandle),
        IARG_RETURN_IP,
        IARG_REG_VALUE,
        REG_GAX,
        IARG_END);

    RTN_Close(funcRtn);
}

/* ==================================================================== */
// Add single function
/* ==================================================================== */
bool AntidebugMonitorAdd(IMG Image, char* fName, uint32_t argNum, const std::string& dllName, FuncWatchList funcWatch)
{
    // Check if already in the list monitored
    for (size_t i = 0; i < funcWatch.funcs.size(); i++) {
        if (util::isStrEqualI(dllName, funcWatch.funcs[i].dllName) &&
            util::isStrEqualI(fName, funcWatch.funcs[i].funcName)) {
            return false;
        }
    }

    RTN funcRtn = RTN_FindByName(Image, fName);
    if (RTN_Valid(funcRtn)) {
        RTN_Open(funcRtn);

        RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(LogFunctionArgs),
            IARG_RETURN_IP,
            IARG_ADDRINT, fName,
            IARG_UINT32, argNum,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
            IARG_END
        );

        RTN_Close(funcRtn);
        return true;
    }

    return false;
}

/* ==================================================================== */
// Leveraging the existing paramToStr, extracts only the string after '->'
/* ==================================================================== */
std::wstring paramToStrSplit(VOID* arg1)
{
    if (arg1 == NULL) {
        return L"0";
    }

    std::wstring inStr = paramToStr(arg1);
    size_t arrowPos = inStr.find(L"->");
    if (arrowPos != 0) {
        // Extract the substring after the arrow symbol and contained in quotes
        std::wstring secondPart = inStr.substr(arrowPos + 3);
        size_t startPos = secondPart.find('"');
        if (startPos != std::string::npos) {
            size_t endPos = secondPart.rfind('"');
            if (endPos != std::string::npos) {
                secondPart = secondPart.substr(startPos + 1, endPos - startPos - 1);
            }
        }
        return secondPart;
    }
    return L"0";
}
