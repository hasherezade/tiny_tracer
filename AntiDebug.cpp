#include "AntiDebug.h"

#include <iostream>
#include <sstream>
#include <string>
#include <map>

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
std::map<std::string, std::string> funcToLink;

typedef VOID AntiDBGCallBack(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5);

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

VOID LogAntiDbg(const ADDRINT insAddr, const char* msg, const char *link=nullptr)
{
    if (!msg) return;

    const ADDRINT RvaFrom = addr_to_rva(insAddr);
    std::stringstream ss;
    ss << std::hex << RvaFrom << TraceLog::DELIMITER << ANTIDBG_LABEL << msg;
    if (link) {
        ss << TraceLog::DELIMITER << link;
    }
    traceLog.logLine(ss.str());
}

/* ==================================================================== */
// Callback function to be executed when memory is accessed
/* ==================================================================== */

VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr)
{
    PinLocker locker;

    if (isWatchedAddress(insAddr) == WatchedType::NOT_WATCHED) return;

    // Check the accessed memory address for antidebug tricks
    if (addr == pebAddr + 2) {
        return LogAntiDbg(insAddr, "PEB!BeingDebugged accessed");
    }
    if (addr == 0x7ffe02d4) {
        return LogAntiDbg(insAddr, "KUSER_SHARED_DATA accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#kuser_shared_data");
    }
#ifdef _WIN64
    if (addr == pebAddr + 0xBC) {
        return LogAntiDbg(insAddr, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(insAddr, "Heap Flags accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#else
    if (addr == pebAddr + 0x68) {
        return LogAntiDbg(insAddr, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(insAddr, "Heap Flags accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#endif
}

/* ==================================================================== */
// Process API calls (related to AntiDebug techniques)
/* ==================================================================== */

VOID AntiDbg_FuncLogOccurrence(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    PinLocker locker;

    std::stringstream ss;
    ss << "^ " << name;
    auto itr = funcToLink.find(name);
    if (itr != funcToLink.end()) {
        return LogAntiDbg(Address, ss.str().c_str(),
            itr->second.c_str());
    }
    return LogAntiDbg(Address, ss.str().c_str());
}

VOID AntiDbg_LoadLibrary(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;
    if (!arg1 || !PIN_CheckReadAccess(arg1)) return;

    // Track LoadLibraryX to detect access to LOAD_DLL_DEBUG_INFO
    // Get the library name from argument
    std::wstring argStr = paramToStrSplit(arg1);
    // Convert from wide string for comparison
    std::string _argStr(argStr.begin(), argStr.end());
    loadedLib.push_back(_argStr);
}

VOID AntiDbg_RaiseException(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    // RaiseException constants
    const int kDBG_CONTROL_C = 0x40010005;
    const int kDBG_RIPEVENT = 0x40010007;

    // kernel32!RaiseException() with DBG_CONTROL_C or DBG_RIPEVENT
    if (int((size_t)arg1) == kDBG_CONTROL_C || int((size_t)arg1) == kDBG_RIPEVENT) {
        return LogAntiDbg(Address, "^ kernel32!RaiseException()",
            "https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception");
    }
}

VOID AntiDbg_NtQuerySystemInformation(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    // function ntdll!NtQuerySystemInformation() with first parameter set to 0x23 (SystemKernelDebuggerInformation)
    if (int((size_t)arg1) == SYSTEMKERNELDEBUGGERINFORMATION) {
        return LogAntiDbg(Address, "^ ntdll!NtQuerySystemInformation (SystemKernelDebuggerInformation)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-ntquerysysteminformation");
    }
}

VOID AntiDbg_NtQueryInformationProcess(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 2) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 7 (ProcessDebugPort)
    if (int((size_t)arg2) == PROCESSDEBUGPORT) {
        return LogAntiDbg(Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugPort)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugport");
    }
    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1f (ProcessDebugFlags)
    if (int((size_t)arg2) == PROCESSDEBUGFLAGS) {
        return LogAntiDbg(Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugFlags)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugflags");
    }
    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1e (ProcessDebugObjectHandle)
    if (int((size_t)arg2) == PROCESSDEBUGOBJECTHANDLE) {
        return LogAntiDbg(Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugObjectHandle)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle");
    }
}

VOID AntiDbg_NtQueryObject(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 2) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    // ntdll!NtQueryObject() to access DebugObject (with ObjectTypesInformation as 2nd argument)
    if (int((size_t)arg2) == OBJECTTYPESINFORMATION) {
        return LogAntiDbg(Address, "^ ntdll!NtQueryObject (ObjectAllTypesInformation)",
            "https://anti-debug.checkpoint.com/techniques/object-handles.html#ntqueryobject");
    }
}

VOID AntiDbg_CreateFile(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 3) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    // kernel32!CreateFileX called on the module itself with Exclusive access, or on loaded libraries
    // Check only exclusive accesses for optimization
    if (int((size_t)arg3) == 0) {
        IMG img = IMG_FindByAddress(Address);
        if (!IMG_Valid(img)) return;
        if (!arg1 || !PIN_CheckReadAccess(arg1)) return;

        // Get the module name from image
        std::string moduleName = IMG_Name(img);
        // Get the module name from arguments
        std::wstring argStr = paramToStrSplit(arg1);
        // Convert from wide string for comparison
        std::string _argStr(argStr.begin(), argStr.end());
        // Check if open is done on module
        if (util::isStrEqualI(_argStr, moduleName)) {
            return LogAntiDbg(Address, "^ kernel32!CreateFile on module",
                "https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile");
        }

        // Check if open is done on loaded libraries
        for (size_t i = 0; i < loadedLib.size(); i++) {
            if (util::isStrEqualI(_argStr, loadedLib[i])) {
                return LogAntiDbg(Address, "^ kernel32!CreateFile on loaded lib",
                    "https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary");
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
        return LogAntiDbg(Address, "^ kernel32!CloseHandle (INVALID_HNDL_VAL)",
            "https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle");
    }
}

/* ==================================================================== */
// Add single function
/* ==================================================================== */

bool AntidebugMonitorAddCallback(IMG Image, char* fName, uint32_t argNum, AntiDBGCallBack callback)
{
    const size_t argMax = 5;
    if (argNum > argMax) argNum = argMax;

    RTN funcRtn = RTN_FindByName(Image, fName);
    if (RTN_Valid(funcRtn)) {
        RTN_Open(funcRtn);

        RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(callback),
            IARG_RETURN_IP,
            IARG_ADDRINT, fName,
            IARG_UINT32, argNum,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
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
    funcToLink["IsDebuggerPresent"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-isdebuggerpresent";
    funcToLink["CheckRemoteDebuggerPresent"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checkremotedebuggerpresent";
    funcToLink["RtlQueryProcessHeapInformation"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessheapinformation";
    funcToLink["RtlQueryProcessDebugInformation"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessdebuginformation";
    funcToLink["HeapWalk"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection";
    funcToLink["CsrGetProcessId"] = "https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess";
    funcToLink["SetUnhandledExceptionFilter"] = "https://anti-debug.checkpoint.com/techniques/exceptions.html#unhandledexceptionfilter";
    funcToLink["RaiseException"] = "https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception";

    // API needed for Antidebug
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "ntdll")) {
        AntidebugMonitorAddCallback(Image, "CsrGetProcessId", 0, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "RtlQueryProcessHeapInformation", 1, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "RtlQueryProcessDebugInformation", 3, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "NtQueryInformationProcess", 5, AntiDbg_NtQueryInformationProcess);
        AntidebugMonitorAddCallback(Image, "NtQuerySystemInformation", 4, AntiDbg_NtQuerySystemInformation);

        ////////////////////////////////////
        // If AntiDebug level is == 2 (Deep)
        ////////////////////////////////////
        if (m_Settings.antidebug > 1) {
            // For Deep or above
            AntidebugMonitorAddCallback(Image, "NtQueryObject", 5, AntiDbg_NtQueryObject);
        }
    }
    if (util::iequals(dllName, "kernel32")) {
        AntidebugMonitorAddCallback(Image, "LoadLibraryW", 1, AntiDbg_LoadLibrary);
        AntidebugMonitorAddCallback(Image, "LoadLibraryA", 1, AntiDbg_LoadLibrary);
        AntidebugMonitorAddCallback(Image, "CreateFileW", 5, AntiDbg_CreateFile);
        AntidebugMonitorAddCallback(Image, "CreateFileA", 5, AntiDbg_CreateFile);
        AntidebugMonitorAddCallback(Image, "IsDebuggerPresent", 0, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "CheckRemoteDebuggerPresent", 2, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "HeapWalk", 2, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "SetUnhandledExceptionFilter", 1, AntiDbg_FuncLogOccurrence);
        AntidebugMonitorAddCallback(Image, "RaiseException", 4, AntiDbg_RaiseException);
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
