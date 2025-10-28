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

#include "EvasionWatch.h"

#define ANTIDBG_LABEL "[ANTIDEBUG] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiDebug
/* ================================================================== */

namespace AntiDbg
{
    ADDRINT m_pebAddr = 0;
    ADDRINT m_heapFlags = 0;
    ADDRINT m_heapForceFlags = 0;
    std::vector<std::string> loadedLib;
}; // namespace AntiDebug

class AntiDbgWatch : public EvasionWatch
{
public:
    AntiDbgWatch() { Init(); }
    virtual BOOL Init();

    std::map<std::string, std::string> funcToLink;
};

AntiDbgWatch m_AntiDbg;

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

    if (!m_pebAddr) return;
    // Check the accessed memory address for antidebug tricks
    if (addr == m_pebAddr + 2) {
        return LogAntiDbg(wType, insAddr, "PEB!BeingDebugged accessed");
    }
    if (addr == 0x7ffe02d4) {
        return LogAntiDbg(wType, insAddr, "KUSER_SHARED_DATA!KdDebuggerEnabled accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#kuser_shared_data");
    }
#ifdef _WIN64
    ADDRINT globalFlagOffset = 0xBC;
#else
    ADDRINT globalFlagOffset = 0x68;
#endif
    if (addr == m_pebAddr + globalFlagOffset) {
        return LogAntiDbg(wType, insAddr, "PEB!NtGlobalFlag accessed");
    }
    if (addr == m_heapFlags || addr == m_heapForceFlags) {
        return LogAntiDbg(wType, insAddr, "Heap Flags accessed",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags");
    }
}

/* ==================================================================== */
// Callback function to be executed when a compare is executed
/* ==================================================================== */
namespace AntiDbg {
    std::map<ADDRINT, size_t> cmpOccurrences;
}; // namespace AntiDbg

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
    std::map<THREADID, int> popfThreads;

    VOID FlagsCheck(const CONTEXT* ctxt, THREADID tid)
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

        pushedVal ^= 0x100;
        PIN_SafeCopy((VOID*)stackPtr, (const VOID*)&pushedVal, sizeof(pushedVal));

        if (m_Settings.emulateSingleStep) {
            popfThreads[tid] = 0;
        }
    }

    VOID FlagsCheck_after(const CONTEXT* ctxt, THREADID tid, ADDRINT eip)
    {
        bool throwExcept = false;

        {
            PinLocker locker;
            auto itr = popfThreads.find(tid);
            if (itr == popfThreads.end()) {
                return; // trap flag wasn't set in this thread
            }
            if (itr->second == 1) {
                popfThreads.erase(tid); // erase the stored TID
                throwExcept = true;
            }
            else {
                itr->second++;
            }
        }

        if (throwExcept) {
            EXCEPTION_INFO exc;
            exc.Init(EXCEPTCODE_DBG_SINGLE_STEP_TRAP, eip);
            PIN_RaiseException(ctxt, tid, &exc);
        }

    }
}; // namespace AntiDbg

VOID AntiDbg::InstrumentFlagsCheck(INS ins)
{
#ifdef _WIN64
    const char* POPF_MNEM = "popfq";
#else
    const char* POPF_MNEM = "popfd";
#endif

    if (util::isStrEqualI(INS_Mnemonic(ins), POPF_MNEM))
    {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)FlagsCheck,
            IARG_CONTEXT,
            IARG_THREAD_ID,
            IARG_END
        );
    }
    else {
        if (m_Settings.emulateSingleStep) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)FlagsCheck_after,
                IARG_CONTEXT,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_END
            );
        }
    }
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

VOID AntiDbgLogFuncOccurrence(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    PinLocker locker;

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    std::stringstream ss;
    ss << "^ " << name;
    auto itr = m_AntiDbg.funcToLink.find(name);
    if (itr != m_AntiDbg.funcToLink.end()) {
        return LogAntiDbg(wType, Address, ss.str().c_str(),
            itr->second.c_str());
    }
    return LogAntiDbg(wType, Address, ss.str().c_str());
}

VOID AntiDbg_LoadLibrary(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;
    if (!arg1 || !isValidReadPtr(arg1)) return;

    // Track LoadLibraryX to detect access to LOAD_DLL_DEBUG_INFO
    // Get the library name from argument
    std::wstring argStr = paramToStrSplit(arg1);
    // Convert from wide string for comparison
    std::string _argStr(argStr.begin(), argStr.end());
    AntiDbg::loadedLib.push_back(_argStr);
}

VOID AntiDbg_BlockInput(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    static size_t BlockInputOccurrences = 0;
    // Check if BlockInput is called more than one time
    BlockInputOccurrences++;
    if (BlockInputOccurrences > 1) {
        return LogAntiDbg(wType, Address, "^ user32!BlockInput()",
            "https://anti-debug.checkpoint.com/techniques/interactive.html#blockinput");
    }
}

VOID AntiDbg_NtSetInformationThread(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum ThreadInformationClass { ThreadHideFromDebugger = 0x11 };
    const uint32_t NtCurrentThread = -2;

    // Check if NtSetInformationThread has been called with parameter ThreadHideFromDebugger
    if (int((size_t)arg1) == NtCurrentThread &&
        int((size_t)arg2) == ThreadInformationClass::ThreadHideFromDebugger) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtSetInformationThread (NtCurrentThread -> ThreadHideFromDebugger)",
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

VOID AntiDbg_NtQuerySystemInformation(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    enum SystemInformationClass {
        SystemKernelDebuggerInformation = 0x23
    };
    // function ntdll!NtQuerySystemInformation() with first parameter set to 0x23 (SystemKernelDebuggerInformation)
    if (int((size_t)arg1) == SystemInformationClass::SystemKernelDebuggerInformation) {
        return LogAntiDbg(wType, Address, "^ ntdll!NtQuerySystemInformation (SystemKernelDebuggerInformation)",
            "https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checks-ntquerysysteminformation");
    }
}

VOID AntiDbg_NtQueryInformationProcess(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
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

VOID AntiDbg_NtQueryObject(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
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

VOID AntiDbg_CreateFile(const ADDRINT Address, const THREADID tid, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
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
        if (!arg1 || !isValidReadPtr(arg1)) return;

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

//* ==================================================================== */
// "CloseHandle" instrumentation, detects invalid handlers
/* ===================================================================== */

VOID AntiDbg_CloseHandle_after(ADDRINT Address, THREADID threadid, const CHAR* name, ADDRINT result)
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

//* ==================================================================== */
// "GetTickCount" instrumentation
/* ===================================================================== */

template <class TICK_T>
VOID AntiDbg_GetTickCount_after(ADDRINT Address, THREADID threadid, const CHAR* name, const BOOL modify, TICK_T* result)
{
    PinLocker locker;
    static TICK_T emTick = 0;
    static TICK_T prevTick = 0;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    std::stringstream ss;
    ss << "^ kernel32!" << name;
    if (modify && result) {
        TICK_T curr = (*result);
        if (emTick) {
            TICK_T diff = 1;
            if (curr > prevTick) {
                diff = ((curr - prevTick) / 10);
            }
            (*result) = emTick + diff;
            ss << " -> NewTick: " << std::dec << (*result);
        }
        emTick = (*result);
        prevTick = curr;
    }

    return LogAntiDbg(wType, Address, ss.str().c_str(),
        "https://anti-debug.checkpoint.com/techniques/timing.html#gettickcount");
}


/* ==================================================================== */
// Collect some infos at Thread start, to be used later in checks
/* ==================================================================== */

BOOL getPEB(CONTEXT* ctxt, ADDRINT& pebAddr)
{
    BOOL is_ok = FALSE;
    ADDRINT sValue = 0;
#ifdef _WIN64
    // Read the value from the memory address pointed by GS:[60h]
    PIN_GetContextRegval(ctxt, REG_SEG_GS_BASE, reinterpret_cast<UINT8*>(&sValue));
    sValue += 0x60;
#else
    // Read the value from the memory address pointed by FS:[30h]
    PIN_GetContextRegval(ctxt, REG_SEG_FS_BASE, reinterpret_cast<UINT8*>(&sValue));
    sValue += 0x30;
#endif
    // Save PEB Address
    if (PIN_SafeCopy(&pebAddr, reinterpret_cast<VOID*>(sValue), sizeof(pebAddr)) == sizeof(pebAddr)) {
        is_ok = TRUE;
    }
    return is_ok;
}

VOID AntiDbg::WatchThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PinLocker locker;

    // Checks only the first thread
    if (threadid != 0) {
        return;
    }

    // Read the PEB address and save it in the global variable
    if (!getPEB(ctxt, m_pebAddr)) return;

    ADDRINT heapBase = 0;
#ifdef _WIN64
    ADDRINT heapBaseOffset = 0x30;
    ADDRINT heapFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x70
        : 0x14;
    ADDRINT heapForceFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x74
        : 0x18;
#else
    ADDRINT heapBaseOffset = WinIsNativeOs32()
        ? 0x18
        : 0x1030;
    ADDRINT heapFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x40
        : 0x0C;
    ADDRINT heapForceFlagsOffset = WinIsWindowsVistaOrGreater()
        ? 0x44
        : 0x10;
#endif

    // Get Heap flags addresses (https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags)
    if (PIN_SafeCopy(&heapBase, reinterpret_cast<VOID*>(m_pebAddr + heapBaseOffset), sizeof(heapBase)) != sizeof(heapBase)) {
        return;
    }
    m_heapFlags = heapBase + heapFlagsOffset;
    m_heapForceFlags = heapBase + heapForceFlagsOffset;
}

/* ==================================================================== */
// Add to monitored functions all the API needed for AntiDebug.
/* ==================================================================== */

BOOL AntiDbgWatch::Init()
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
    funcToLink["GetSystemTime"] = "https://anti-debug.checkpoint.com/techniques/timing.html#getsystemtime";
    funcToLink["GetLocalTime"] = "https://anti-debug.checkpoint.com/techniques/timing.html#getlocaltime";

    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "CsrGetProcessId", 0));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "RtlQueryProcessHeapInformation", 1));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "RtlQueryProcessDebugInformation", 3));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "DbgUiDebugActiveProcess", 1));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "NtQueryInformationProcess", 5, AntiDbg_NtQueryInformationProcess));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "NtQuerySystemInformation", 4, AntiDbg_NtQuerySystemInformation));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "NtDebugActiveProcess", 2));
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "NtSetInformationThread", 4, AntiDbg_NtSetInformationThread));

    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "LoadLibraryW", 1, AntiDbg_LoadLibrary));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "LoadLibraryA", 1, AntiDbg_LoadLibrary));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "CreateFileW", 5, AntiDbg_CreateFile));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "CreateFileA", 5, AntiDbg_CreateFile));

    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "CloseHandle", 1, nullptr, AntiDbg_CloseHandle_after));

    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "IsDebuggerPresent", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "CheckRemoteDebuggerPresent", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "HeapWalk", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "SetUnhandledExceptionFilter", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "RaiseException", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "DebugActiveProcess", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "GenerateConsoleCtrlEvent", 5));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "GetSystemTime", 1));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "GetLocalTime", 1));

    watchedFuncs.appendFunc(EvasionFuncInfo("user32", "BlockInput", 1, AntiDbg_BlockInput));
    watchedFuncs.appendFunc(EvasionFuncInfo("user32", "SwitchDesktop", 1, AntiDbgLogFuncOccurrence));

    ////////////////////////////////////
    // If AntiDebug level is Deep
    ////////////////////////////////////
    watchedFuncs.appendFunc(EvasionFuncInfo("ntdll", "NtQueryObject", 5, AntiDbg_NtQueryObject, nullptr, WATCH_DEEP));

    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "OutputDebugStringA", 5, nullptr, nullptr, WATCH_DEEP));
    watchedFuncs.appendFunc(EvasionFuncInfo("kernel32", "OutputDebugStringA", 5, nullptr, nullptr, WATCH_DEEP));

    watchedFuncs.appendFunc(EvasionFuncInfo("user32", "GetWindowTextA", 3, nullptr, nullptr, WATCH_DEEP));
    watchedFuncs.appendFunc(EvasionFuncInfo("user32", "GetWindowTextW", 3, nullptr, nullptr, WATCH_DEEP));

    isInit = TRUE;
    return isInit;
}

namespace AntiDbg {

    template <class TICK_T>
    VOID _InstrumentGetTickCount(IMG Image, const char* fName, bool modify)
    {
        RTN funcRtn = find_by_unmangled_name(Image, fName);
        if (RTN_Valid(funcRtn)) {
            RTN_Open(funcRtn);

            RTN_InsertCall(funcRtn, IPOINT_AFTER, (AFUNPTR)AntiDbg_GetTickCount_after<TICK_T>,
                IARG_RETURN_IP,
                IARG_THREAD_ID,
                IARG_ADDRINT, fName,
                IARG_BOOL, modify,
                IARG_REG_REFERENCE,
                REG_GAX,
                IARG_END);

            RTN_Close(funcRtn);
        }
    }

    VOID InstrumentTimeChecks(IMG Image, t_watch_level maxLevel)
    {
        if (!IMG_Valid(Image)) return;

        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (!util::iequals(dllName, "kernel32") && !util::iequals(dllName, "kernelbase")) {
            return;
        }

        const bool modify = (maxLevel == t_watch_level::WATCH_DEEP) ? true : false;
        
        _InstrumentGetTickCount<UINT32>(Image, "GetTickCount", modify);
        _InstrumentGetTickCount<UINT64>(Image, "GetTickCount64", modify);
    }
};

VOID AntiDbg::MonitorAntiDbgFunctions(IMG Image)
{
    if (m_Settings.antidebug == WATCH_DISABLED) return;

    m_AntiDbg.installCallbacks(Image, AntiDbgLogFuncOccurrence, m_Settings.antidebug);
    AntiDbg::InstrumentTimeChecks(Image, m_Settings.antidebug);
}

VOID AntiDbg::MonitorSyscallEntry(const THREADID tid, const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address)
{
    EvasionFuncInfo* wfunc = m_AntiDbg.fetchSyscallFuncInfo(name, m_Settings.antidebug);
    if (!wfunc) return;

    EvasionWatchBeforeCallBack* callbackBefore = wfunc->callbackBefore;
    if (!callbackBefore && !wfunc->callbackAfter) {
        callbackBefore = AntiDbgLogFuncOccurrence;
    }
    if (!callbackBefore) return;

    const size_t argCount = wfunc->paramCount;
    const size_t args_max = 5;
    VOID* syscall_args[args_max] = { 0 };

    for (size_t i = 0; i < args_max; i++) {
        if (i == argCount) break;
        syscall_args[i] = reinterpret_cast<VOID*>(PIN_GetSyscallArgument(ctxt, std, i));
    }
    callbackBefore(Address,
        tid,
        name, argCount,
        syscall_args[0],
        syscall_args[1],
        syscall_args[2],
        syscall_args[3],
        syscall_args[4]);
}
