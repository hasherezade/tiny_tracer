#include "AntiDebug.h"

#include <iostream>
#include <sstream>

#include "ProcessInfo.h"
#include "Util.h"
#include "TraceLog.h"
#include "Settings.h"
#include "PinLocker.h"
#include "TinyTracer.h"

#include "win/win_paths.h"
#include "win/win_constants.h"

#define ANTIDBG_LABEL "[ANTIDEBUG] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiDebug
/* ================================================================== */
ADDRINT pebAddr = 0;
ADDRINT heapFlags = 0;
ADDRINT heapForceFlags = 0;
std::vector<std::string> loadedLib;

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

/* ==================================================================== */
// Wrappers for Windows functions
/* ==================================================================== */

BOOL WinIsNativeOs32(void)
{
    BOOL isNativeOs32 = FALSE;
#ifndef _WIN64
    {  // scope
        using namespace WINDOWS;

        WINDOWS::BOOL(WINAPI * _IsWow64Process)(HANDLE, WINDOWS::PBOOL) =
            (WINDOWS::BOOL(WINAPI*)(HANDLE, WINDOWS::PBOOL)) WINDOWS::GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
        if (!_IsWow64Process) {
            return TRUE;   //function not found -> 32-bit system
        }
        WINDOWS::BOOL isWow64 = FALSE;
        _IsWow64Process(WINDOWS::GetCurrentProcess(), &isWow64);
        isNativeOs32 = !isWow64;
    } // !scope
#endif
    return isNativeOs32;
}

BOOL WinIsWindowsVistaOrGreater(void)
{
    using namespace WINDOWS;

    DWORD dwVersion = WINDOWS::GetVersion();
    DWORD dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    DWORD dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

    if (dwMajorVersion >= 6) {
        return TRUE;
    }
    return FALSE;
}

/* ==================================================================== */
// Log info with antidebug label
/* ==================================================================== */

VOID LogAntiDbg(const ADDRINT RvaFrom, const char* msg)
{
    std::stringstream ss;
    ss << std::hex << RvaFrom << TraceLog::DELIMITER << ANTIDBG_LABEL << msg;
    traceLog.logLine(ss.str());
}

/* ==================================================================== */
// Callback function to be executed when memory is accessed
/* ==================================================================== */

VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr)
{
    PinLocker locker;

    if (isWatchedAddress(insAddr) == WatchedType::NOT_WATCHED) return;

    const ADDRINT RvaFrom = addr_to_rva(insAddr);

    // Check the accessed memory address for antidebug tricks
    if (addr == pebAddr + 2) {
        return LogAntiDbg(RvaFrom, "PEB!BeingDebugged accessed");
    }
    if (addr == 0x7ffe02d4) {
        return LogAntiDbg(RvaFrom, "KUSER_SHARED_DATA accessed https://anti-debug.checkpoint.com/techniques/debug-flags.html#kuser_shared_data");
    }
#ifdef _WIN64
    if (addr == pebAddr + 0xBC) {
        return LogAntiDbg(RvaFrom, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(RvaFrom, "Heap Flags accessed https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#else
    if (addr == pebAddr + 0x68) {
        return LogAntiDbg(RvaFrom, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(RvaFrom, "Heap Flags accessed https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#endif
}

/* ==================================================================== */
// Process API calls (related to AntiDebug techniques)
/* ==================================================================== */

VOID AntidebugProcessFunctions(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10)
{
    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    const ADDRINT RvaFrom = addr_to_rva(Address);

    ///////////////////////////////////////////////////////////////////////////////
    // Check known function names for antidebug tricks, then parameters (if needed)
    ///////////////////////////////////////////////////////////////////////////////
    // TODO: not sure if it's better to use isStrEqualI or strcmp
    if (strcmp(name, "IsDebuggerPresent") == 0) {
        // function kernel32!IsDebuggerPresent()
        return LogAntiDbg(RvaFrom, "^ kernel32!IsDebuggerPresent https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-isdebuggerpresent");
    }
    if (strcmp(name, "CheckRemoteDebuggerPresent") == 0) {
        // function kernel32!CheckRemoteDebuggerPresent()
        return LogAntiDbg(RvaFrom, "^ kernel32!CheckRemoteDebuggerPresent https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checkremotedebuggerpresent");
    }
    if (strcmp(name, "NtQueryInformationProcess") == 0) {
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 7 (ProcessDebugPort)
        if (int((size_t)arg2) == PROCESSDEBUGPORT) {
            return LogAntiDbg(RvaFrom, "^ ntdll!NtQueryInformationProcess (ProcessDebugPort) https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugport");
        }
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1f (ProcessDebugFlags)
        if (int((size_t)arg2) == PROCESSDEBUGFLAGS) {
            return LogAntiDbg(RvaFrom, "^ ntdll!NtQueryInformationProcess (ProcessDebugFlags) https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugflags");
        }
        // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1e (ProcessDebugObjectHandle)
        if (int((size_t)arg2) == PROCESSDEBUGOBJECTHANDLE) {
            return LogAntiDbg(RvaFrom, "^ ntdll!NtQueryInformationProcess (ProcessDebugObjectHandle) https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle");
        }
        return;
    }
    if (strcmp(name, "RtlQueryProcessHeapInformation") == 0) {
        // function ntdll!RtlQueryProcessHeapInformation()
        // FIXME possible improvement: check access to the buffer parameter of the function
        return LogAntiDbg(RvaFrom, "^ ntdll!RtlQueryProcessHeapInformation https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessheapinformation");
    }
    if (strcmp(name, "RtlQueryProcessDebugInformation") == 0) {
        // function ntdll!RtlQueryProcessDebugInformation()
        return LogAntiDbg(RvaFrom, "^ ntdll!RtlQueryProcessDebugInformation https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessdebuginformation");
    }
    if (strcmp(name, "NtQuerySystemInformation") == 0) {
        // function ntdll!NtQuerySystemInformation() with first parameter set to 0x23 (SystemKernelDebuggerInformation)
        if (int((size_t)arg1) == SYSTEMKERNELDEBUGGERINFORMATION) {
            return LogAntiDbg(RvaFrom, "^ ntdll!NtQuerySystemInformation (SystemKernelDebuggerInformation) https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-ntquerysysteminformation");
        }
        return;
    }
    if (strcmp(name, "HeapWalk") == 0) {
        // kernel32!HeapWalk() function to extract Heap blocks and check the tail
        return LogAntiDbg(RvaFrom, "^ kernel32!HeapWalk https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection");
    }
    if (strcmp(name, "CsrGetProcessId") == 0) {
        // kernel32!OpenProcess() function on the csrss.exe - CsrGetProcessId get the csrss.exe PID
        return LogAntiDbg(RvaFrom, "^ kernel32!OpenProcess/CsrGetProcessId https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess");
    }
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
                    return LogAntiDbg(RvaFrom, "^ kernel32!CreateFile on module https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile");
                }
                else {
                    // Check if open is done on loaded libraries
                    for (size_t i = 0; i < loadedLib.size(); i++)
                        if (util::isStrEqualI(_argStr, loadedLib[i])) {
                            return LogAntiDbg(RvaFrom, "^ kernel32!CreateFile on loaded lib https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary");
                        }
                }
            }
        }
        return;
    }
    if (strcmp(name, "SetUnhandledExceptionFilter") == 0) {
        // kernel32!SetUnhandledExceptionFilter() function to set a specific handler
        return LogAntiDbg(RvaFrom, "^ kernel32!SetUnhandledExceptionFilter https ://anti-debug.checkpoint.com/techniques/exceptions.html#unhandledexceptionfilter");
    }
    if (strcmp(name, "RaiseException") == 0) {
        // kernel32!RaiseException() with DBG_CONTROL_C or DBG_RIPEVENT
        if (int((size_t)arg1) == DBG_CONTROL_C || int((size_t)arg1) == DBG_RIPEVENT) {
            return LogAntiDbg(RvaFrom, "^ kernel32!RaiseException() https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception");
        }
        return;
    }
    if (strcmp(name, "LoadLibraryA") == 0 || strcmp(name, "LoadLibraryW") == 0) {
        // Track LoadLibraryX to detect access to LOAD_DLL_DEBUG_INFO
        // Get the library name from argument
        std::wstring argStr = paramToStrSplit(arg1);
        // Convert from wide string for comparison
        std::string _argStr(argStr.begin(), argStr.end());
        loadedLib.push_back(_argStr);
        return;
    }
    ////////////////////////////////////
    // If AntiDebug level is == 2 (Deep)
    ////////////////////////////////////
    if (m_Settings.antidebug > 1) {
        if (strcmp(name, "NtQueryObject") == 0) {
            // ntdll!NtQueryObject() to access DebugObject (with ObjectTypesInformation as 2nd argument)
            if (int((size_t)arg2) == OBJECTTYPESINFORMATION) {
                return LogAntiDbg(RvaFrom, "^ ntdll!NtQueryObject(with ObjectAllTypesInformation) https://anti-debug.checkpoint.com/techniques/object-handles.html#ntqueryobject");
            }
        }
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
    ADDRINT heapFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x70
        : 0x14;
    ADDRINT heapForceFlagsOffset = WinIsWindowsVistaOrGreater()
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
    ADDRINT heapBaseOffset = WinIsNativeOs32()
        ? 0x18
        : 0x1030;
    PIN_SafeCopy(&heapBase, reinterpret_cast<VOID*>(pebAddr + heapBaseOffset), sizeof(heapBase));
    ADDRINT heapFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x40
        : 0x0C;
    ADDRINT heapForceFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x44
        : 0x10;
    heapFlags = heapBase + heapFlagsOffset;
    heapForceFlags = heapBase + heapForceFlagsOffset;
#endif 
}

//* ==================================================================== */
// "CloseHandle" instrumentation, detects invalid handlers
/* ===================================================================== */

VOID AntidebugCloseHandle(ADDRINT Address, ADDRINT result)
{
    PinLocker locker;

    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    if (!result) {
        // Invalid closure
        const ADDRINT RvaFrom = addr_to_rva(Address);
        return LogAntiDbg(RvaFrom, "^ kernel32!CloseHandle https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle");
    }
}

/* ==================================================================== */
// Add single function
/* ==================================================================== */
bool AntidebugMonitorAdd(IMG Image, char* fName, uint32_t argNum, const std::string& dllName)
{
    RTN funcRtn = RTN_FindByName(Image, fName);
    if (RTN_Valid(funcRtn)) {
        RTN_Open(funcRtn);

        RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(AntidebugProcessFunctions),
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
// Add to monitored functions all the API needed for AntiDebug.
// Called by ImageLoad
/* ==================================================================== */

VOID AntidebugMonitorFunctions(IMG Image)
{
    // API needed for Antidebug
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "ntdll")) {
        AntidebugMonitorAdd(Image, "CsrGetProcessId", 0, dllName);
        AntidebugMonitorAdd(Image, "NtQueryInformationProcess", 5, dllName);
        AntidebugMonitorAdd(Image, "RtlQueryProcessHeapInformation", 1, dllName);
        AntidebugMonitorAdd(Image, "RtlQueryProcessDebugInformation", 3, dllName);
        AntidebugMonitorAdd(Image, "NtQuerySystemInformation", 4, dllName);
        if (m_Settings.antidebug > 1) {
            // For Deep or above
            AntidebugMonitorAdd(Image, "NtQueryObject", 5, dllName);
        }
    }
    if (util::iequals(dllName, "kernel32")) {
        AntidebugMonitorAdd(Image, "LoadLibraryW", 1, dllName);
        AntidebugMonitorAdd(Image, "LoadLibraryA", 1, dllName);
        AntidebugMonitorAdd(Image, "GetProcAddress", 2, dllName);
        AntidebugMonitorAdd(Image, "CreateFileW", 6, dllName);
        AntidebugMonitorAdd(Image, "CreateFileA", 7, dllName);
        AntidebugMonitorAdd(Image, "OpenProcess", 3, dllName);
        AntidebugMonitorAdd(Image, "IsDebuggerPresent", 0, dllName);
        AntidebugMonitorAdd(Image, "CheckRemoteDebuggerPresent", 2, dllName);
        AntidebugMonitorAdd(Image, "HeapWalk", 2, dllName);
        AntidebugMonitorAdd(Image, "CloseHandle", 1, dllName);
        AntidebugMonitorAdd(Image, "SetUnhandledExceptionFilter", 1, dllName);
        AntidebugMonitorAdd(Image, "RaiseException", 4, dllName);
    }

    // CloseHandle return value hook
    RTN funcRtn = RTN_FindByName(Image, "CloseHandle");
    if (!RTN_Valid(funcRtn)) return; // failed

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn, IPOINT_AFTER, AFUNPTR(AntidebugCloseHandle),
        IARG_RETURN_IP,
        IARG_FUNCRET_EXITPOINT_VALUE,
        IARG_END);

    RTN_Close(funcRtn);
}
