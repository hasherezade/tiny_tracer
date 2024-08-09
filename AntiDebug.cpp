#include "AntiDebug.h"

#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <set>

#include "ProcessInfo.h"
#include "Util.h"
#include "TraceLog.h"
#include "Settings.h"
#include "PinLocker.h"
#include "TinyTracer.h"
#include "ModuleInfo.h"

#ifdef USE_WINDOWS_HDR
#include "win/win_paths.h"
#endif

#define ANTIDBG_LABEL "[ANTIDEBUG] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiDebug
/* ================================================================== */
namespace AntiDbg
{
    ADDRINT pebAddr = 0;
    ADDRINT heapFlags = 0;
    ADDRINT heapForceFlags = 0;
    std::vector<std::string> loadedLib;
    std::map<std::string, std::string> funcToLink;

}; // namespace AntiDebug


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
// System information
/* ==================================================================== */

BOOL WinIsNativeOs32(void)
{
    BOOL isNativeOs32 = FALSE;
#ifndef _WIN64
    OS_HOST_CPU_ARCH_TYPE arch = OS_HOST_CPU_ARCH_TYPE_INVALID;
    OS_RETURN_CODE code = OS_GetHostCPUArch(&arch);
    if (code.generic_err != OS_RETURN_CODE_NO_ERROR) {
        return TRUE; // assume 32 bit
    }
    if (arch == OS_HOST_CPU_ARCH_TYPE_IA32) {
        isNativeOs32 = TRUE;
    }
#endif
    return isNativeOs32;
}

BOOL WinIsWindowsVistaOrGreater(void)
{
    const USIZE buf_size = 300;
    CHAR buf[buf_size] = { 0 };
    OS_RETURN_CODE code = OS_GetKernelRelease(buf, buf_size);
    if (code.generic_err != OS_RETURN_CODE_NO_ERROR) {
        return TRUE; // assume greater than Vista
    }
    std::vector<std::string> args;
    util::splitList(buf, '.', args);
    if (args.size() >= 2) {
        int dwMajorVersion = util::loadInt(args[0], false);
        if (dwMajorVersion >= 6) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ==================================================================== */
// Log info with antidebug label
/* ==================================================================== */

VOID LogAntiDbg(const WatchedType wType, const ADDRINT Address, const char* msg, const char *link=nullptr)
{
    LogMsgAtAddress(wType, Address, ANTIDBG_LABEL, msg, link);
}

/* ==================================================================== */
// Callback function to be executed when memory is accessed
/* ==================================================================== */

VOID AntiDbg::WatchMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr)
{
    PinLocker locker;

    const WatchedType wType = isWatchedAddress(insAddr);
    if (wType == WatchedType::NOT_WATCHED) return;

    if (!pebAddr) return;
    // Check the accessed memory address for antidebug tricks
    if (addr == pebAddr + 2) {
        return LogAntiDbg(wType, insAddr, "PEB!BeingDebugged accessed");
    }
    if (addr == 0x7ffe02d4) {
        return LogAntiDbg(wType, insAddr, "KUSER_SHARED_DATA accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#kuser_shared_data");
    }
#ifdef _WIN64
    if (addr == pebAddr + 0xBC) {
        return LogAntiDbg(wType, insAddr, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(wType, insAddr, "Heap Flags accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#else
    if (addr == pebAddr + 0x68) {
        return LogAntiDbg(wType, insAddr, "PEB!NtGlobalFlag accessed");
    }
    if (addr == heapFlags || addr == heapForceFlags) {
        return LogAntiDbg(wType, insAddr, "Heap Flags accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
#endif
}

/* ==================================================================== */
// Callback function to be executed when a compare is executed
/* ==================================================================== */

std::map<ADDRINT, size_t> cmpOccurrences;
VOID AntiDbg::WatchCompareSoftBrk(ADDRINT Address, UINT64 immVal)
{
    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    bool isSet = false;
    const size_t kMinOccur = 3;
    const UINT8 val = immVal & 0xFF;
    if (val == 0xCC) {
        cmpOccurrences[Address]++;
        if (cmpOccurrences[Address] == kMinOccur) isSet = true;
    }

    if (isSet) {
        LogAntiDbg(wType, Address, "Software Breakpoint comparison",
            "https://anti-debug.checkpoint.com/techniques/process-memory.html#anti-step-over");
    }
}

namespace AntiDbg {
    std::set<THREADID> popfThreads;
}; // namespace AntiDbg

#define CLEAR_TRAP
VOID AntiDbg::FlagsCheck(const CONTEXT* ctxt, THREADID tid)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    ADDRINT pushedVal = UNKNOWN_ADDR;
    const ADDRINT* stackPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctxt, REG_STACK_PTR));
    size_t copiedSize = PIN_SafeCopy(&pushedVal, stackPtr, sizeof(pushedVal));
    if (copiedSize != sizeof(pushedVal)) {
        return;
    }
    const bool isTrap = (pushedVal & 0x100) ? true : false;
    if (!isTrap) return;

    LogAntiDbg(wType, Address, "Trap Flag set",
        "https://anti-debug.checkpoint.com/techniques/assembly.html#popf_and_trap_flag");

#ifdef CLEAR_TRAP
    pushedVal ^= 0x100;
    ::memcpy((void*)stackPtr, &pushedVal, sizeof(pushedVal));
    popfThreads.insert(tid);
#endif
}

VOID AntiDbg::FlagsCheck_after(const CONTEXT* ctxt, THREADID tid, ADDRINT eip)
{
    {
        PinLocker locker;

        if (popfThreads.find(tid) == popfThreads.end()) {
            return; // trap flag wasn't set in this thread
        }
        popfThreads.erase(tid); // erase the stored TID
    }
    EXCEPTION_INFO exc;
    PIN_InitWindowsExceptionInfo(&exc, 0x80000004L, eip); // NTSTATUS_STATUS_SINGLE_STEP
    PIN_RaiseException(ctxt, tid, &exc);
}

VOID AntiDbg::InterruptCheck(const CONTEXT* ctxt)
{
    PinLocker locker;
    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;
    
    int interruptID = 0;
    if (!fetchInterruptID(Address, interruptID)) return;

    if (interruptID == 1) {
        LogAntiDbg(wType, Address, "INT1",
            "https://anti-debug.checkpoint.com/techniques/assembly.html#ice");
    }
    if (interruptID == 3) {
        LogAntiDbg(wType, Address, "INT3",
            "https://anti-debug.checkpoint.com/techniques/assembly.html#int3");
    }
    if (interruptID == 0x2d) {
        LogAntiDbg(wType, Address, "INT2D",
            "https://anti-debug.checkpoint.com/techniques/assembly.html#int2d");
    }
}

/* ==================================================================== */
// Process API calls (related to AntiDebug techniques)
/* ==================================================================== */

VOID AntiDbgLogFuncOccurrence(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    PinLocker locker;

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    std::stringstream ss;
    ss << "^ " << name;
    auto itr = AntiDbg::funcToLink.find(name);
    if (itr != AntiDbg::funcToLink.end()) {
        return LogAntiDbg(wType, Address, ss.str().c_str(),
            itr->second.c_str());
    }
    return LogAntiDbg(wType, Address, ss.str().c_str());
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
    AntiDbg::loadedLib.push_back(_argStr);
}

size_t BlockInputOccurrences = 0;
VOID AntiDbg_BlockInput(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    // Check if BlockInput is called more than one time
    BlockInputOccurrences++;
    if (BlockInputOccurrences > 1) {
        return LogAntiDbg(wType, Address, "^ user32!BlockInput()",
            "https://anti-debug.checkpoint.com/techniques/interactive.html#blockinput");
    }
}

VOID AntiDbg_NtSetInformationThread(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum ThreadInformationClass { ThreadHideFromDebugger = 0x11 };
    uint32_t NtCurrentThread = -2;

    // Check if NtSetInformationThread has been called with parameter ThreadHideFromDebugger
    if (int((size_t)arg1) == NtCurrentThread &&
        int((size_t)arg2) == ThreadInformationClass::ThreadHideFromDebugger) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtSetInformationThread()",
            "https://anti-debug.checkpoint.com/techniques/interactive.html#ntsetinformationthread");
    }
}

VOID AntiDbg_RaiseException(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    // RaiseException constants
    enum ExceptionCode { kDBG_CONTROL_C = 0x40010005, kDBG_RIPEVENT = 0x40010007 };
    // kernel32!RaiseException() with DBG_CONTROL_C or DBG_RIPEVENT
    if (int((size_t)arg1) == ExceptionCode::kDBG_CONTROL_C || int((size_t)arg1) == ExceptionCode::kDBG_RIPEVENT) {
        return LogAntiDbg(wType, Address, "^ kernel32!RaiseException()",
            "https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception");
    }
}

VOID AntiDbg_NtQuerySystemInformation(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum SystemInformationClass { SystemKernelDebuggerInformation = 0x23 };
    // function ntdll!NtQuerySystemInformation() with first parameter set to 0x23 (SystemKernelDebuggerInformation)
    if (int((size_t)arg1) == SystemInformationClass::SystemKernelDebuggerInformation) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQuerySystemInformation (SystemKernelDebuggerInformation)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-ntquerysysteminformation");
    }
}

VOID AntiDbg_NtQueryInformationProcess(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 2) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum ProcessInformationClass { ProcessDebugPort = 0x7, ProcessDebugFlags = 0x1f, ProcessDebugObjectHandle = 0x1e };

    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 7 (ProcessDebugPort)
    if (int((size_t)arg2) == ProcessInformationClass::ProcessDebugPort) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugPort)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugport");
    }
    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1f (ProcessDebugFlags)
    if (int((size_t)arg2) == ProcessInformationClass::ProcessDebugFlags) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugFlags)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugflags");
    }
    // function ntdll!NtQueryInformationProcess with ProcessInformationClass == 0x1e (ProcessDebugObjectHandle)
    if (int((size_t)arg2) == ProcessInformationClass::ProcessDebugObjectHandle) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQueryInformationProcess (ProcessDebugObjectHandle)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle");
    }
}

VOID AntiDbg_NtQueryObject(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 2) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum ObjectInformationClass { ObjectAllTypesInformation = 3 };
    // ntdll!NtQueryObject() to access DebugObject (with ObjectAllTypesInformation as 2nd argument)
    if (int((size_t)arg2) == ObjectInformationClass::ObjectAllTypesInformation) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQueryObject (ObjectAllTypesInformation)",
            "https://anti-debug.checkpoint.com/techniques/object-handles.html#ntqueryobject");
    }
}

VOID AntiDbg_CreateFile(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (argCount < 3) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

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
            return LogAntiDbg(wType, Address, "^ kernel32!CreateFile on module",
                "https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile");
        }

        // Check if open is done on loaded libraries
        for (size_t i = 0; i < AntiDbg::loadedLib.size(); i++) {
            if (util::isStrEqualI(_argStr, AntiDbg::loadedLib[i])) {
                return LogAntiDbg(wType, Address, "^ kernel32!CreateFile on loaded lib",
                    "https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary");
            }
        }
    }
}

/* ==================================================================== */
// Collect some infos at Thread start, to be used later in checks
/* ==================================================================== */

BOOL getPEB(CONTEXT* ctxt, ADDRINT& pebAddr)
{
    BOOL is_ok = FALSE;
#ifdef _WIN64
    // Read the value from the memory address pointed by GS:[60h] and save it in the global variable
    ADDRINT gsValue;
    PIN_GetContextRegval(ctxt, REG_SEG_GS_BASE, reinterpret_cast<UINT8*>(&gsValue));
    gsValue += 0x60;
    // Save PEB Address
    if (PIN_SafeCopy(&pebAddr, reinterpret_cast<VOID*>(gsValue), sizeof(pebAddr)))is_ok = TRUE;
#else
    // Read the value from the memory address pointed by FS:[30h] and save it in the global variable
    ADDRINT fsValue;
    PIN_GetContextRegval(ctxt, REG_SEG_FS_BASE, reinterpret_cast<UINT8*>(&fsValue));
    fsValue += 0x30;

    // Save PEB Address
    if (PIN_SafeCopy(&pebAddr, reinterpret_cast<VOID*>(fsValue), sizeof(pebAddr))) is_ok = TRUE;
#endif
    return is_ok;
}

VOID AntiDbg::WatchThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PinLocker locker;

    // Checks only the first thread
    if (threadid != 0) {
        return;
    }
#ifdef _WIN64
    // Read the value from the memory address pointed by GS:[60h] and save it in the global variable
    if (!getPEB(ctxt, pebAddr)) return;

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
    if (!getPEB(ctxt, pebAddr)) return;

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

VOID AntiDbg_After_CloseHandle(ADDRINT Address, ADDRINT result)
{
    PinLocker locker;

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    if (!result) {
        // Invalid closure
        return LogAntiDbg(wType, Address, "^ kernel32!CloseHandle (INVALID_HNDL_VAL)",
            "https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle");
    }
}

/* ==================================================================== */
// Add single function
/* ==================================================================== */

bool AntiDbgAddCallbackBefore(IMG Image, char* fName, uint32_t argNum, AntiDBGCallBack callback)
{
    const size_t argMax = 5;
    if (argNum > argMax) argNum = argMax;

    RTN funcRtn = find_by_unmangled_name(Image, fName);
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

VOID AntiDbg::MonitorAntiDbgFunctions(IMG Image)
{
    funcToLink["IsDebuggerPresent"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-isdebuggerpresent";
    funcToLink["CheckRemoteDebuggerPresent"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checkremotedebuggerpresent";
    funcToLink["RtlQueryProcessHeapInformation"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessheapinformation";
    funcToLink["RtlQueryProcessDebugInformation"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-rtlqueryprocessdebuginformation";
    funcToLink["HeapWalk"] = "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection";
    funcToLink["CsrGetProcessId"] = "https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess";
    funcToLink["SetUnhandledExceptionFilter"] = "https://anti-debug.checkpoint.com/techniques/exceptions.html#unhandledexceptionfilter";
    funcToLink["RaiseException"] = "https://anti-debug.checkpoint.com/techniques/exceptions.html#raiseexception";
    funcToLink["DebugActiveProcess"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#self-debugging";
    funcToLink["DbgUiDebugActiveProcess"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#self-debugging";
    funcToLink["NtDebugActiveProcess"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#self-debugging";
    funcToLink["GenerateConsoleCtrlEvent"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#generateconsolectrlevent";
    funcToLink["GetWindowTextA"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#suspendthread";
    funcToLink["GetWindowTextW"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#suspendthread";
    funcToLink["SwitchDesktop"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#switchdesktop";
    funcToLink["OutputDebugStringA"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#outputdebugstring";
    funcToLink["OutputDebugStringW"] = "https://anti-debug.checkpoint.com/techniques/interactive.html#outputdebugstring";

    // API needed for Antidebug
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "ntdll")) {
        AntiDbgAddCallbackBefore(Image, "CsrGetProcessId", 0, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "RtlQueryProcessHeapInformation", 1, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "RtlQueryProcessDebugInformation", 3, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "NtQueryInformationProcess", 5, AntiDbg_NtQueryInformationProcess);
        AntiDbgAddCallbackBefore(Image, "NtQuerySystemInformation", 4, AntiDbg_NtQuerySystemInformation);
        AntiDbgAddCallbackBefore(Image, "DbgUiDebugActiveProcess", 1, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "NtDebugActiveProcess", 2, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "NtSetInformationThread", 4, AntiDbg_NtSetInformationThread);

        ////////////////////////////////////
        // If AntiDebug level is Deep
        ////////////////////////////////////
        if (m_Settings.antidebug >= ANTIDEBUG_DEEP) {
            AntiDbgAddCallbackBefore(Image, "NtQueryObject", 5, AntiDbg_NtQueryObject);
        }
    }
    if (util::iequals(dllName, "kernel32")) {
        AntiDbgAddCallbackBefore(Image, "LoadLibraryW", 1, AntiDbg_LoadLibrary);
        AntiDbgAddCallbackBefore(Image, "LoadLibraryA", 1, AntiDbg_LoadLibrary);
        AntiDbgAddCallbackBefore(Image, "CreateFileW", 5, AntiDbg_CreateFile);
        AntiDbgAddCallbackBefore(Image, "CreateFileA", 5, AntiDbg_CreateFile);
        AntiDbgAddCallbackBefore(Image, "IsDebuggerPresent", 0, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "CheckRemoteDebuggerPresent", 2, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "HeapWalk", 2, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "SetUnhandledExceptionFilter", 1, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "RaiseException", 4, AntiDbg_RaiseException);
        AntiDbgAddCallbackBefore(Image, "DebugActiveProcess", 1, AntiDbgLogFuncOccurrence);
        AntiDbgAddCallbackBefore(Image, "GenerateConsoleCtrlEvent", 2, AntiDbgLogFuncOccurrence);

        ////////////////////////////////////
        // If AntiDebug level is Deep
        ////////////////////////////////////
        if (m_Settings.antidebug >= ANTIDEBUG_DEEP) {
            AntiDbgAddCallbackBefore(Image, "OutputDebugStringA", 1, AntiDbgLogFuncOccurrence);
            AntiDbgAddCallbackBefore(Image, "OutputDebugStringW", 1, AntiDbgLogFuncOccurrence);
        }
    }
    if (util::iequals(dllName, "user32")) {
        AntiDbgAddCallbackBefore(Image, "BlockInput", 1, AntiDbg_BlockInput);
        AntiDbgAddCallbackBefore(Image, "SwitchDesktop", 1, AntiDbgLogFuncOccurrence);

        ////////////////////////////////////
        // If AntiDebug level is Deep
        ////////////////////////////////////
        if (m_Settings.antidebug >= ANTIDEBUG_DEEP) {
            AntiDbgAddCallbackBefore(Image, "GetWindowTextA", 3, AntiDbgLogFuncOccurrence);
            AntiDbgAddCallbackBefore(Image, "GetWindowTextW", 3, AntiDbgLogFuncOccurrence);
        }
    }

    // CloseHandle return value hook
    RTN funcRtn = find_by_unmangled_name(Image, "CloseHandle");
    if (!RTN_Valid(funcRtn)) return; // failed

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn, IPOINT_AFTER, AFUNPTR(AntiDbg_After_CloseHandle),
        IARG_RETURN_IP,
        IARG_FUNCRET_EXITPOINT_VALUE,
        IARG_END);

    RTN_Close(funcRtn);
}
