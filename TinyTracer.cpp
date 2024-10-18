/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Documentation: https://github.com/hasherezade/tiny_tracer/wiki
*/
#include "pin.H"

#include <iostream>
#include <string>
#include <set>
#include <sstream>

#include "TinyTracer.h"

#include "ProcessInfo.h"
#include "TraceLog.h"
#include "PinLocker.h"
#include "DisasmCache.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "2.8.2"

#include "Util.h"
#include "Settings.h"
#define LOGGED_ARGS_MAX 11

#define USE_ANTIDEBUG
#define USE_ANTIVM

#ifndef _WIN32
#undef USE_ANTIDEBUG // works only for Windows!
#undef USE_ANTIVM
#endif

#ifdef USE_ANTIDEBUG
#include "AntiDebug.h"
#endif

#ifdef USE_ANTIVM
#include "AntiVm.h"
#endif

#define TEST
/* ================================================================== */
// Global variables 
/* ================================================================== */

Settings m_Settings;
ProcessInfo pInfo;
TraceLog traceLog;

// last shellcode to which the transition got redirected:
std::set<ADDRINT> m_tracedShellc;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "Specify file name for the output");

KNOB<std::string> KnobIniFile(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Specify the settings file");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

KNOB<std::string> KnobWatchListFile(KNOB_MODE_WRITEONCE, "pintool",
    "b", "", "A list of watched functions (dump parameters before the execution)");

KNOB<std::string> KnobSyscallsTable(KNOB_MODE_WRITEONCE, "pintool",
    "l", "", "Syscall table: a CSV file mapping a syscall ID (in hex) to a function name");

KNOB<std::string> KnobExcludedListFile(KNOB_MODE_WRITEONCE, "pintool",
    "x", "", "A list of functions excluded from watching");

KNOB<std::string> KnobStopOffsets(KNOB_MODE_WRITEONCE, "pintool",
    "p", "", "A list of stop offsets: RVAs of the traced module where the execution should pause");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11);


/*!
*  Print out help message.
*/
INT32 Usage()
{
    std::cerr << "This tool prints out : " << std::endl <<
        "Addresses of redirections into to a new sections. Called API functions.\n" << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

/* ===================================================================== */
// Analysis utilities
/* ===================================================================== */

BOOL isInTracedShellc(const ADDRINT addr)
{
    if (addr == UNKNOWN_ADDR) {
        return FALSE;
    }
    const ADDRINT regionBase = query_region_base(addr);
    if (regionBase == UNKNOWN_ADDR) {
        return FALSE;
    }
    if (m_tracedShellc.find(regionBase) != m_tracedShellc.end()) {
        return TRUE;
    }
    return FALSE;
}

WatchedType isWatchedAddress(const ADDRINT Address)
{
    if (Address == UNKNOWN_ADDR) {
        return WatchedType::NOT_WATCHED;
    }
    const IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        return WatchedType::WATCHED_MY_MODULE;
    }
    const BOOL isShellcode = !IMG_Valid(currModule);
    if (m_Settings.followShellcode && isShellcode) {
        if (m_Settings.followShellcode == SHELLC_FOLLOW_ANY) {
            return WatchedType::WATCHED_SHELLCODE;
        }
        if (isInTracedShellc(Address)){
            return WatchedType::WATCHED_SHELLCODE;
        }
    }
    return WatchedType::NOT_WATCHED;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

inline ADDRINT getReturnFromTheStack(const CONTEXT* ctx)
{
    if (!ctx) return UNKNOWN_ADDR;

    ADDRINT retAddr = UNKNOWN_ADDR;
    const ADDRINT* stackPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctx, REG_STACK_PTR));
    size_t copiedSize = PIN_SafeCopy(&retAddr, stackPtr, sizeof(retAddr));
    if (copiedSize != sizeof(retAddr)) {
        return UNKNOWN_ADDR;
    }
    return retAddr;
}

VOID SaveHeavensGateTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, ADDRINT seg, const CONTEXT* ctx = NULL)
{
    PinLocker locker;
    const WatchedType wType = isWatchedAddress(addrFrom);
    if (wType == WatchedType::NOT_WATCHED) {
        return;
    }
    ADDRINT pageFrom = 0;
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        pageFrom = query_region_base(addrFrom);
    }
    ADDRINT RvaFrom = addr_to_rva(addrFrom);
    std::stringstream ss;
    if (seg == 0x33) {
        ss << "Heaven's Gate -> switch to 64 bit : ";
    }
    else if (seg == 0x23) {
        ss << "Heaven's Gate -> switch to 32 bit : ";
    }
    else {
        ss << "Unknown Far transition ";
        if (seg) ss << "seg: " << std::hex << seg << " : ";
    }
    if (addrTo) ss << std::hex << addrTo;
 
    traceLog.logInstruction(pageFrom, RvaFrom, ss.str());
    PIN_WriteErrorMessage("ERROR: Cannot trace after the far transition", 1000, PIN_ERR_SEVERITY_TYPE::PIN_ERR_FATAL, 0);

}

VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, BOOL isIndirect, const CONTEXT* ctx = NULL)
{
    const WatchedType fromWType = isWatchedAddress(addrFrom); // is the call from the traced area?

    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    IMG targetModule = IMG_FindByAddress(addrTo);
    IMG callerModule = IMG_FindByAddress(addrFrom);
    const bool isCallerPeModule = IMG_Valid(callerModule);
    const bool isTargetPeModule = IMG_Valid(targetModule);


    /**
    is it a transition from the traced module to a foreign module?
    */
    if (fromWType == WatchedType::WATCHED_MY_MODULE
        && !isTargetMy)
    {
        ADDRINT RvaFrom = addr_to_rva(addrFrom);
        if (isTargetPeModule) {
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            if (m_Settings.excludedFuncs.contains(dll_name, func)) {
                return;
            }
            traceLog.logCall(0, RvaFrom, true, dll_name, func);
        }
        else {
            //not in any of the mapped modules:
            const ADDRINT pageTo = query_region_base(addrTo);
            m_tracedShellc.insert(pageTo); //save the beginning of this area
            traceLog.logCall(0, RvaFrom, pageTo, addrTo);
        }
    }

    /**
    trace calls from witin a shellcode:
    */
    if (fromWType == WatchedType::WATCHED_SHELLCODE) {

        const ADDRINT pageFrom = query_region_base(addrFrom);
        const ADDRINT pageTo = query_region_base(addrTo);

        if (isTargetPeModule) { // it is a call to a module
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            if (m_Settings.excludedFuncs.contains(dll_name, func)) {
                return;
            }
            traceLog.logCall(pageFrom, addrFrom, false, dll_name, func);
        }
        else if (pageFrom != pageTo) // it is a call to another shellcode
        {
            // add the new shellcode to the set of traced
            if (m_Settings.followShellcode == SHELLC_FOLLOW_RECURSIVE) {
                m_tracedShellc.insert(pageTo);
            }

            // register the transition
            if (m_Settings.logShelcTrans) {
                // save the transition from one shellcode to the other
                ADDRINT base = get_base(addrFrom);
                ADDRINT RvaFrom = addrFrom - base;
                traceLog.logCall(base, RvaFrom, pageTo, addrTo);
            }
        }

    }

    /**
    save the transition when a shellcode returns to a traced area from an API call:
    */
    if (fromWType == WatchedType::NOT_WATCHED && !isCallerPeModule // from an untraced shellcode...
        && isTargetPeModule // ...into an API call
        && ctx //the context was passed: we can check the return
        )
    {
        // was the shellcode a proxy for making an API call?
        const ADDRINT returnAddr = getReturnFromTheStack(ctx);
        const WatchedType toWType = isWatchedAddress(returnAddr); // does it return into the traced area?
        if (toWType != WatchedType::NOT_WATCHED) {
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            if (m_Settings.excludedFuncs.contains(dll_name, func)) {
                return;
            }
            const ADDRINT pageRet = get_base(returnAddr);
            const ADDRINT RvaFrom = addr_to_rva(addrFrom);
            const ADDRINT base = isTargetMy ? 0 : get_base(addrFrom);

            traceLog.logCallRet(base, RvaFrom, pageRet, returnAddr, dll_name, func);
        }
    }
    /**
    trace indirect calls to your own functions
    */
    if (fromWType == WatchedType::WATCHED_MY_MODULE
        && isTargetMy && m_Settings.logIndirect && isIndirect)
    {
        const ADDRINT baseTo = get_base(addrTo);
        ADDRINT base = get_base(addrFrom);
        if (base != UNKNOWN_ADDR && baseTo != UNKNOWN_ADDR) {
            const ADDRINT RvaFrom = addrFrom - base;
            const ADDRINT calledRVA = addrTo - baseTo;
            traceLog.logIndirectCall(0, RvaFrom, true, baseTo, calledRVA);
        }
    }

    /**
    trace transitions between the sections of the traced module:
    */
    if (isTargetMy) {
        ADDRINT rva = addr_to_rva(addrTo); // convert to RVA

        // is it a transition from one section to another?
        if (pInfo.updateTracedModuleSection(rva)) {
            if (m_Settings.logSectTrans) {
                const s_module* sec = pInfo.getSecByAddr(rva);
                std::string curr_name = (sec) ? sec->name : "?";
                if (isCallerMy) {
                    ADDRINT rvaFrom = addr_to_rva(addrFrom); // convert to RVA
                    const s_module* prev_sec = pInfo.getSecByAddr(rvaFrom);
                    std::string prev_name = (prev_sec) ? prev_sec->name : "?";
                    traceLog.logNewSectionCalled(rvaFrom, prev_name, curr_name);
                }
                traceLog.logSectionChange(rva, curr_name);
            }
        }
    }
}

VOID SaveTransitions(const ADDRINT prevVA, const ADDRINT Address, BOOL isIndirect, const CONTEXT* ctx)
{
    PinLocker locker;
    _SaveTransitions(prevVA, Address, isIndirect, ctx);
}

VOID LogMsgAtAddress(const WatchedType wType, const ADDRINT Address, const char* label, const char* msg, const char* link)
{
    if (!msg) return;
    if (wType == WatchedType::NOT_WATCHED) return;

    std::stringstream ss;
    ADDRINT rva = UNKNOWN_ADDR;
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        rva = addr_to_rva(Address); // convert to RVA
    }
    else if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            ss << "> " << std::hex << start << "+";
        }
    }
    if (rva == UNKNOWN_ADDR) return;
    ss << std::hex << rva << TraceLog::DELIMITER;
    if (label) {
        ss << label;
    }
    ss << msg;
    if (link) {
        ss << TraceLog::DELIMITER << link;
    }
    traceLog.logLine(ss.str());
}

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    LogMsgAtAddress(wType, Address, nullptr, "RDTSC", nullptr);
}

VOID PauseAtOffset(const CONTEXT* ctxt)
{
    PinLocker locker;
    if (!m_Settings.stopOffsets.size()) return;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType != WatchedType::WATCHED_MY_MODULE) return;

    const ADDRINT rva = addr_to_rva(Address); // convert to RVA

    auto itr = m_Settings.stopOffsets.find(StopOffset(rva));
    if (itr == m_Settings.stopOffsets.end()) {
        return;
    }
    {//log info
        std::stringstream ss;
        ss << "# Stop offset reached: RVA = 0x" << std::hex << rva << ". Sleeping " << std::dec << m_Settings.stopOffsetTime << " s.";
        if (itr->times) {
            ss << " Hits remaining: " << (itr->times - 1);
        }
        traceLog.logLine(ss.str());
        std::cerr << ss.str() << std::endl;
    }

    StopOffset &so = const_cast<StopOffset &>(*itr);
    if (so.times != 0) { // if the StopOffset with times 0 is on the list, it means it should be executed infinite number of times
        so.times--;
        if (so.times == 0) {
            m_Settings.stopOffsets.erase(itr); //erase
        }
    }
    const int sleepMs = m_Settings.stopOffsetTime * 1000;
    PIN_Sleep(sleepMs);

    {//log info
        std::stringstream ss;
        ss.clear();
        ss << "# Resuming execution";
        traceLog.logLine(ss.str());
        std::cerr << ss.str() << std::endl;
    }
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PinLocker locker;
    const std::string mnem = "CPUID";

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logInstruction(0, rva, mnem, Param);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logInstruction(start, rva, mnem, Param);
        }
    }
}

BOOL fetchInterruptID(const ADDRINT Address, int &intID)
{
    unsigned char copyBuf[2] = { 0 };
    int fetchedSize = 1;
    std::string mnem;
    if (!PIN_FetchCode(copyBuf, (const void*)Address, fetchedSize, NULL)) return FALSE;

    if (copyBuf[0] == 0xCD) { // INT
        fetchedSize = 2;
        if (!PIN_FetchCode(copyBuf, (const void*)Address, fetchedSize, NULL)) return FALSE;
    }
    switch (copyBuf[0]) {
        case 0xCC:
            intID = 3; break;
        case 0xCE:
            intID = 4; break;
        case 0xF1:
            intID = 1; break;
        case 0xCD:
        {
            intID = (unsigned int)copyBuf[1];
            break;
        }
    }
    return TRUE;
}

VOID InterruptCalled(const CONTEXT* ctxt)
{
    PinLocker locker;
    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) {
        return;
    }
    int interruptID = 0;
    if (!fetchInterruptID(Address, interruptID)) return;

    const std::string mnem = "INT";
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logInstruction(0, rva, mnem, interruptID);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logInstruction(start, rva, mnem, interruptID);
        }
    }
}

VOID LogSyscallsArgs(const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address, uint32_t argCount)
{
    const size_t args_max = LOGGED_ARGS_MAX;
    VOID* syscall_args[args_max] = { 0 };

    for (size_t i = 0; i < args_max; i++) {
        if (i == argCount) break;
        syscall_args[i] = reinterpret_cast<VOID*>(PIN_GetSyscallArgument(ctxt, std, i));
    }
    _LogFunctionArgs(Address,
        name, argCount,
        syscall_args[0],
        syscall_args[1],
        syscall_args[2],
        syscall_args[3],
        syscall_args[4],
        syscall_args[5],
        syscall_args[6],
        syscall_args[7],
        syscall_args[8],
        syscall_args[9],
        syscall_args[10]);
}

BOOL _fetchSyscallData(CONTEXT* ctxt, SYSCALL_STANDARD &std, ADDRINT &address)
{
#ifdef _WIN64
    // Since Windows 10 TH2, NTDLL's syscall routines have changed: syscalls can
    // now be performed with the SYSCALL instruction, and with the INT 2E
    // instruction. The ABI is the same in both cases.
    if (std == SYSCALL_STANDARD_WINDOWS_INT) {
        const auto* insPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctxt, REG_INST_PTR));
        uint16_t instruction = 0;
        PIN_SafeCopy(&instruction, insPtr, sizeof(instruction));
        if (instruction != 0x2ECD) { // INT 2E
            // Not a relevant interrupt, return now.
            return FALSE;
        }
        std = SYSCALL_STANDARD_IA32E_WINDOWS_FAST;
    }
#endif

    const auto _address = [&]() -> ADDRINT {
        if (std == SYSCALL_STANDARD_WOW64) {
            // Note: In this case, the current instruction address is in a 64-bit
            // code portion. The address that we're interested in is the return
            // address, which is in a 32-bit code portion.
            return getReturnFromTheStack(ctxt);
        }
        return PIN_GetContextReg(ctxt, REG_INST_PTR);
    }();

    if (_address == UNKNOWN_ADDR) return FALSE; //invalid
    address = _address;
    return TRUE;
}

//---
struct SyscallInfo
{
    ADDRINT ssid;
    ADDRINT addrFrom;

    SyscallInfo(ADDRINT _ssid = UNKNOWN_ADDR, ADDRINT _addrFrom = UNKNOWN_ADDR)
        : ssid(_ssid), addrFrom(_addrFrom) {}

    SyscallInfo(const SyscallInfo& other)
        : ssid(other.ssid), addrFrom(other.addrFrom) { }

    void fill(ADDRINT _ssid, ADDRINT _addrFrom )
    {
        this->ssid = _ssid;
        this->addrFrom = _addrFrom;
    }

    void reset()
    {
        this->fill(UNKNOWN_ADDR, UNKNOWN_ADDR);
    }
};

std::map<THREADID, SyscallInfo> syscallFromThread;

VOID SyscallCalled(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    PinLocker locker;

    syscallFromThread[tid] = SyscallInfo(); // reset just in case
    ADDRINT address = UNKNOWN_ADDR;
    if (!_fetchSyscallData(ctxt, std, address)) {
        return;
    }
    const WatchedType wType = isWatchedAddress(address);
    if (wType == WatchedType::NOT_WATCHED) return;
    
    const ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
    if (syscallNum == UNKNOWN_ADDR) return; //invalid

    syscallFromThread[tid].fill(syscallNum, address);

    std::string funcName = m_Settings.syscallsTable.getName(syscallNum);

    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(address); // convert to RVA
        traceLog.logSyscall(0, rva, syscallNum, funcName);
    }
    else if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(address);
        ADDRINT rva = address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logSyscall(start, rva, syscallNum, funcName);
        }
    }

    // Log arguments if needed:
    // 
    // check if it is watched by the syscall number:
    const auto& it = m_Settings.funcWatch.syscalls.find(syscallNum);
    if (it != m_Settings.funcWatch.syscalls.end()) {
        LogSyscallsArgs(WSyscallInfo::formatSyscallName(syscallNum).c_str(), ctxt, std, address, it->second.paramCount);
        return;
    }
#ifdef _WIN32 // supported only for Windows
    // check if it is watched by the function name:
    std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
    for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
        if (util::iequals("ntdll", m_Settings.funcWatch.funcs[i].dllName)
            || util::iequals("win32u", m_Settings.funcWatch.funcs[i].dllName))
        {
            std::string funcName = SyscallsTable::convertNameToNt(m_Settings.funcWatch.funcs[i].funcName);
            if (syscallFuncName == funcName) {
                LogSyscallsArgs(funcName.c_str(), ctxt, std, address, m_Settings.funcWatch.funcs[i].paramCount);
                break;
            }
        }
    }
#ifdef USE_ANTIDEBUG
    if (m_Settings.antidebug != WATCH_DISABLED) {
        AntiDbg::MonitorSyscallEntry(tid, syscallFuncName.c_str(), ctxt, std, address);
    }
#endif //USE_ANTIDEBUG

#ifdef USE_ANTIVM
    if (m_Settings.antivm != WATCH_DISABLED) {
        AntiVm::MonitorSyscallEntry(tid, syscallFuncName.c_str(), ctxt, std, address);
    }
#endif //USE_ANTIVM

#endif //_WIN32
}

VOID SyscallCalledAfter(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    PinLocker locker;

    auto itr = syscallFromThread.find(tid);
    if (itr == syscallFromThread.end() || itr->second.ssid == UNKNOWN_ADDR) {
        return;
    }

    const ADDRINT syscallNum = itr->second.ssid;
    const ADDRINT address = itr->second.addrFrom;

    itr->second.reset(); // sycall completed, erase the stored info

    if (address == UNKNOWN_ADDR) {
        return;
    }
    const std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
#ifdef USE_ANTIVM
    if (m_Settings.antivm != WATCH_DISABLED) {
        AntiVm::MonitorSyscallExit(tid, syscallFuncName.c_str(), ctxt, std, address);
    }
#endif //USE_ANTIVM
}

ADDRINT _setTimer(const CONTEXT* ctxt, bool isEax)
{
    static UINT64 Timer = 0;
    UINT64 result = 0;

    if (Timer == 0) {
        ADDRINT edx = (ADDRINT)PIN_GetContextReg(ctxt, REG_GDX);
        ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
        Timer = (UINT64(edx) << 32) | eax;
    }
    else {
        Timer += 100;
    }

    if (isEax) {
        result = (Timer << 32) >> 32;
    }
    else {
        result = (Timer) >> 32;
    }
    return (ADDRINT)result;
}

ADDRINT AlterRdtscValueEdx(const CONTEXT* ctxt)
{
    PinLocker locker;
    return _setTimer(ctxt, false);
}

ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt)
{
    PinLocker locker;
    return _setTimer(ctxt, true);
}

/* ===================================================================== */
// Instrument functions arguments
/* ===================================================================== */

BOOL isValidReadPtr(VOID* arg1)
{
    const ADDRINT start = query_region_base((ADDRINT)arg1);
    const BOOL isReadableAddr = (start != UNKNOWN_ADDR && start != 0) && PIN_CheckReadAccess(arg1);
    return isReadableAddr;
}

std::wstring paramToStr(VOID *arg1)
{
    if (arg1 == NULL) {
        return L"0";
    }
    std::wstringstream ss;

    if (!isValidReadPtr(arg1)) {
        // single value
        ss << std::hex << (arg1)
            << " = "
            << std::dec << ((size_t)arg1);
        return ss.str();
    }
    // possible pointer:
    ss << "ptr " << std::hex << (arg1);
    //
    // Check if UNICODE_STRING
    //
    typedef struct _T_UNICODE_STRING {
        uint16_t Length;
        uint16_t MaximumLength;
        wchar_t* Buffer;
    } T_UNICODE_STRING;

    T_UNICODE_STRING* unicodeS = reinterpret_cast<T_UNICODE_STRING*>(arg1);

    const size_t kMaxStr = 300;

    if (PIN_CheckReadAccess(&unicodeS->Buffer) 
        && (unicodeS->MaximumLength < kMaxStr) && (unicodeS->Length <= unicodeS->MaximumLength)// check if the length makes sense
        && isValidReadPtr(unicodeS->Buffer))
    {
        const size_t aLen = util::getAsciiLen(reinterpret_cast<char*>(unicodeS->Buffer), 2); // take minimal sample of ASCII string
        if (aLen == 1) {
            // Must be wide string
            size_t wLen = util::getAsciiLenW(unicodeS->Buffer, unicodeS->MaximumLength);
            if (wLen >= 1) {
                if ((unicodeS->Length / sizeof(wchar_t)) == wLen && unicodeS->MaximumLength >= unicodeS->Length) { // An extra check, just to make sure
                    ss << " -> ";
                    ss << "U\"" << unicodeS->Buffer << "\""; // Just made the U up to denote a UNICODE_STRING
                    return ss.str();
                }
            }
        }
    }

    bool isString = false;
    const char* val = reinterpret_cast<char*>(arg1);
    size_t len = util::getAsciiLen(val, kMaxStr);
    if (len > 0) {
        ss << " -> ";
    }
    if (len == 1) { // Possible wideString
        wchar_t* val = reinterpret_cast<wchar_t*>(arg1);
        size_t wLen = util::getAsciiLenW(val, kMaxStr);
        if (wLen >= len) {
            ss << "L\"" << val << "\"";
            isString = true;
        }
    }
    else if (len > 1) { // ASCII string
        ss << "\"" << val << "\"";
        isString = true;
    }
    if (!isString) {
        ss << " -> {";
ss << util::hexdump(reinterpret_cast<const uint8_t*>(val), m_Settings.hexdumpSize);
ss << "}";
    }
    return ss.str();
}

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11)
{
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    const size_t argsMax = LOGGED_ARGS_MAX;
    VOID* args[argsMax] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11 };
    std::wstringstream ss;
    ss << name << ":\n";
    for (size_t i = 0; i < argCount && i < argsMax; i++) {
        ss << "\tArg[" << i << "] = ";
        ss << paramToStr(args[i]);
        ss << "\n";
    }

    std::wstring argsLineW = ss.str();
    std::string s(argsLineW.begin(), argsLineW.end());
    traceLog.logLine(s);
}

VOID LogFunctionArgs(const ADDRINT Address, CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11)
{
    if (argCount == 0) return;

    PinLocker locker;
    _LogFunctionArgs(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
}

VOID MonitorFunctionArgs(IMG Image, const WFuncInfo& funcInfo)
{
    const size_t argsMax = LOGGED_ARGS_MAX;
    const CHAR* fName = funcInfo.funcName.c_str();
    size_t argNum = funcInfo.paramCount;
    if (argNum > argsMax) argNum = argsMax;

    RTN funcRtn = find_by_unmangled_name(Image, fName);
    if (!RTN_Valid(funcRtn) || !funcInfo.isValid()) return; // failed

    std::cout << "Watch " << IMG_Name(Image) << ": " << fName << " [" << argNum << "]\n";
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
}

DisasmCache m_disasmCache;

#ifdef TEST
int getValIndx(ADDRINT rax)
{
    char str[] = "0123456789ABCDEFabcdefghijklmopq";
    const size_t len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (rax == ADDRINT(str[i])) return i;
    }
    return (-1);
}
#endif //TEST

void printDifference(std::stringstream &mS, const ADDRINT& changedTracked, const ADDRINT& changed)
{
    std::stringstream s1;
    if (!changedTracked) {
        return;
    }
    s1 << std::hex;
    s1 << " UNK: " << "#[";
    if ((int64_t)changed > (int64_t)changedTracked) {
        ADDRINT diff = (int64_t)changed - (int64_t)changedTracked;
        s1 << " res += 0x" << diff;
    }
    else {
        ADDRINT diff = (int64_t)changedTracked - (int64_t)changed;
        s1 << " res -= 0x" << diff;
    }
    s1 << " ; ";
    ADDRINT diff = (int64_t)changed ^ (int64_t)changedTracked;
    s1 << " res ^= 0x" << diff;
    s1 << " ] ";
    mS << s1.str();
    
    traceLog.logListingLine(s1.str());
}

std::string dumpContext(const std::string &disasm, const CONTEXT* ctx)
{
    std::stringstream ss;
    const char *reg_names[] = {
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "rbx",
        "rdx",
        "rcx",
        "rax",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    };
    const REG regs[] =
    {
        REG_GDI,
        REG_GSI,
        REG_GBP,
        REG_STACK_PTR,
        REG_GBX,
        REG_GDX,
        REG_GCX,
        REG_GAX,
        REG_R8,
        REG_R9,
        REG_R10,
        REG_R11,
        REG_R12,
        REG_R13,
        REG_R14,
        REG_R15
    };
    const size_t regsCount = sizeof(regs) / sizeof(regs[0]);
    static ADDRINT values[regsCount] = { 0 };
    static ADDRINT spVal = 0;

    static bool wasLastMul = false;
    static ADDRINT trackedMulRes = 0;
    static ADDRINT trackedRes = 0;
    static bool hasTrackedRes = false;
    static REG trackedReg = REG_STACK_PTR;
    static ADDRINT changedTracked = 0;
    static size_t mulCntr = 0;


    ADDRINT Address = getReturnFromTheStack(ctx);
    if (Address != spVal) {
        ss << "[rsp] -> " << std::hex << Address << "; ";
        spVal = Address;
    }
    bool _hasTrackedRes = false;
    REG changedReg = REG_STACK_PTR; //last changed
    for (size_t i = 0; i < regsCount; i++) {
        REG reg = regs[i];
        const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctx, reg);
        if (values[i] == Address) continue;
        if (trackedRes && Address == trackedRes) {
            _hasTrackedRes = true;
            trackedReg = reg;
        }
        values[i] = Address;
        changedReg = reg;
        ss << reg_names[i] << " = " << std::hex << Address << " ";
    }
    if (_hasTrackedRes != hasTrackedRes) {
        
        if (_hasTrackedRes) {
            ss << " TRACKED_CHANGED ";
            ss << "BY: " << disasm;
            std::stringstream s1;
            s1 << std::hex <<" #[ ";
            if (disasm.find("sub") != std::string::npos) s1 << "res -= m";
            if (disasm.find("add") != std::string::npos) s1 << "res += m";
            if (disasm.find("xor") != std::string::npos) s1 << "res ^= m";
            s1 << " ] ";
            ss << s1.str();
            traceLog.logListingLine(s1.str());
            changedTracked = 0;
        }
        else {
            changedTracked = (ADDRINT)PIN_GetContextReg(ctx, trackedReg);
            ss << " TRACKED_CHANGED ";
            ss << " -> VAL: " << changedTracked;
        }
    }
    hasTrackedRes = _hasTrackedRes;

    if (wasLastMul) {
        trackedMulRes = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
        ss << " !!! MUL_RES: " << std::hex << trackedMulRes;
        wasLastMul = false;
    }

    if (disasm.find("test ") != std::string::npos) {
        ss << " TRACKED_TEST ";
        for (size_t i = 0; i < regsCount; i++) {
            if (disasm.find(reg_names[i]) != std::string::npos) {
                REG reg = regs[i];
                const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctx, reg);
                ss << reg_names[i] << " = " << std::hex << Address;
                printDifference(ss, changedTracked, Address);
                changedTracked = Address;
                mulCntr = 0;
                traceLog.logListingLine("###");
            }
        }
    }

    if (disasm.find("mul ") != std::string::npos) {
        const ADDRINT rax = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
        ADDRINT changed = 0;
        if (changedReg != REG_STACK_PTR) {
            mulCntr++;
            changed = (ADDRINT)PIN_GetContextReg(ctx, changedReg);
        }
        bool showDiff = true;
        ADDRINT m = rax * spVal;

        ss << " !!! TRACKED_MULTIPLYING: ";

        std::stringstream s1;
        s1 << std::hex << mulCntr << "#[ ";
        //if (mulCntr == 1) {
        //    s1 << "res += 0x" << changed - trackedMulRes << " ";
        //}

        if (mulCntr == 0) 
            s1 << "res";
        else 
            s1 << "m";

        s1 << " = ";

#ifdef TEST
        int indx = getValIndx(rax);
        s1 << "x_" << std::dec << indx << " ";
#else
        s1 << std::hex << rax;
#endif
        s1 << std::hex << " * 0x" << spVal << " ] ";
        traceLog.logListingLine(s1.str());
        ss << s1.str();
        //ss << " = " << std::hex << m;

        if (showDiff && mulCntr > 1) {
            printDifference(ss, changedTracked, changed);
        }
        trackedRes = changed;
        wasLastMul = true;
        
        if (mulCntr == 1) {
            std::stringstream s1;
            s1 << std::hex << " #[ ";
            s1 << "res += 0x" << changed - trackedMulRes;
            s1 << " ]";
            traceLog.logListingLine(s1.str());

            ss << s1.str();
        }
        ss << "// [CNTR: " << mulCntr << "] ";
    }
    
    std::string out = ss.str();
    if (out.length()) {
        return "{ " + out + " }";
    }
    return "";
}

VOID LogInstruction(const CONTEXT* ctxt, THREADID tid, const char* disasm)
{
    if (!disasm) return;

    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);

    if (wType == WatchedType::NOT_WATCHED) {
        return;
    }

    ADDRINT rva = UNKNOWN_ADDR;
    ADDRINT base = UNKNOWN_ADDR;
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        rva = addr_to_rva(Address); // convert to RVA
        base = 0;
    }
    if (rva == UNKNOWN_ADDR || rva < m_Settings.disasmStart || rva > m_Settings.disasmStop) {
        return;
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        base = query_region_base(Address);
        rva = Address - base;
    }
    if (base != UNKNOWN_ADDR && rva != UNKNOWN_ADDR) {
        std::stringstream ss;
        ss << "[" << std::dec << tid << "] ";
        ss << disasm;
        traceLog.logLine("\t\t\t\t" + dumpContext(disasm, ctxt));
        traceLog.logInstruction(base, rva, ss.str());
    }
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


VOID InstrumentInstruction(INS ins, VOID *v)
{
    const IMG pImg = IMG_FindByAddress(INS_Address(ins));
    const BOOL isMyImg = pInfo.isMyImg(pImg);
    BOOL inWatchedModule = isMyImg;
    if (m_Settings.followShellcode != t_shellc_options::SHELLC_DO_NOT_FOLLOW
        && !IMG_Valid(pImg))
    {
        inWatchedModule = TRUE;
    }
    // only the main module or shellcodes:
    if (inWatchedModule && m_Settings.disasmStart) {
        const char* disasm = m_disasmCache.put(INS_Disassemble(ins));
        if (disasm) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)LogInstruction,
                IARG_CONTEXT,
                IARG_THREAD_ID,
                IARG_PTR, disasm,
                IARG_END
            );
        }
    }

    //---
    // trace the control flow regardless of the module:
    const BOOL isFar = INS_IsFarCall(ins) || INS_IsFarJump(ins) || INS_IsFarRet(ins);
    if (isFar) {
        UINT16 segs = 0;
        UINT32 disp = 0;
        if (INS_IsDirectFarJump(ins)) {
            INS_GetFarPointer(ins, segs, disp);
        }
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)SaveHeavensGateTransitions,
            IARG_INST_PTR,
            IARG_ADDRINT, disp,
            IARG_ADDRINT, segs,
            IARG_CONTEXT,
            IARG_END
        );
    }

    if (INS_IsControlFlow(ins) && !isFar){
        const BOOL isIndirect = INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins);
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_BOOL, isIndirect,
            IARG_CONTEXT,
            IARG_END
        );
    }

    // after this point, we trace only the module of interest:
    if (!inWatchedModule) return;

    // only in the main traced module:
    if (isMyImg && m_Settings.stopOffsets.size() > 0 && m_Settings.stopOffsetTime) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)PauseAtOffset,
            IARG_CONTEXT,
            IARG_END
        );
    }

    // the main module or shellcodes:
    if (util::isStrEqualI(INS_Mnemonic(ins), "cpuid")) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)CpuidCalled,
            IARG_CONTEXT,
            IARG_END
        );
#ifdef USE_ANTIVM
        // ANTIVM: Register Function instrumentation needed for AntiVm
        if (m_Settings.antivm != WATCH_DISABLED) {
            AntiVm::InstrumentCPUIDCheck(ins);
        }
#endif
    }

    if (m_Settings.traceINT) {
        if (INS_IsInterrupt(ins)) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)InterruptCalled,
                IARG_CONTEXT,
                IARG_END
            );
        }
    }

    if (INS_IsRDTSC(ins)) {
        if (m_Settings.traceRDTSC) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)RdtscCalled,
                IARG_CONTEXT,
                IARG_END
            );
        }

        INS_InsertCall(
            ins,
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEdx,
            IARG_CONTEXT,
            IARG_RETURN_REGS,
            REG_GDX,
            IARG_END);

        INS_InsertCall(ins,
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEax,
            IARG_CONTEXT,
            IARG_RETURN_REGS,
            REG_GAX,
            IARG_END);
    }
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: memory read instrumentation
    
    ////////////////////////////////////
    // If AntiDebug level is Standard
    ////////////////////////////////////
    if (m_Settings.antidebug != WATCH_DISABLED) {
        if (INS_IsMemoryRead(ins)) {
            // Insert the callback function before memory read instructions
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AntiDbg::WatchMemoryAccess),
                IARG_MEMORYREAD_EA,   // Effective address for memory read
                IARG_MEMORYREAD_SIZE, // Size of memory read
                IARG_INST_PTR,        // Instruction address
                IARG_END);
        }

#ifdef _WIN64
        const char *POPF_MNEM = "popfq";
#else
        const char *POPF_MNEM = "popfd";
#endif
        if (util::isStrEqualI(INS_Mnemonic(ins), POPF_MNEM))
        {
            AntiDbg::InstrumentFlagsCheck(ins);
        }

        if (INS_IsInterrupt(ins)) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)AntiDbg::InterruptCheck,
                IARG_CONTEXT,
                IARG_END
            );
        }
        
        ////////////////////////////////////
        // If AntiDebug level is Deep
        ////////////////////////////////////
        if (m_Settings.antidebug >= WATCH_DEEP) {
            // Check all comparison for 0xCC byte (anti stepinto/stepover checks)
            const UINT32 opIdx = 1;
            if (INS_Opcode(ins) == XED_ICLASS_CMP 
                && INS_OperandCount(ins) >= (opIdx + 1) 
                && INS_OperandIsImmediate(ins, opIdx)
                && INS_OperandWidth(ins, opIdx) == (sizeof(UINT8)*8))
            {
                UINT64 imm = INS_OperandImmediate(ins, opIdx);
                INS_InsertCall(
                    ins,
                    IPOINT_BEFORE, (AFUNPTR)AntiDbg::WatchCompareSoftBrk,
                    IARG_INST_PTR,
                    IARG_UINT64, imm,
                    IARG_END);
            }
        }
    }
#endif
}

/* ===================================================================== */

VOID HookNtDelayExecution(const CHAR* name, UINT64* sleepTimePtr)
{
    PinLocker locker;

    if (PIN_CheckReadAccess(sleepTimePtr)) {

        INT64 sleepVal = (m_Settings.sleepTime != 0) ? (m_Settings.sleepTime * 10000) : 1;
        sleepVal = -(sleepVal);
        std::stringstream ss;
        ss << "\t"<< name <<" hooked. Overwriting DelayInterval: " << std::hex << (*sleepTimePtr) << " -> " << sleepVal << std::endl;
        traceLog.logLine(ss.str());
        (*sleepTimePtr) = sleepVal;
    }
}

/* ===================================================================== */


VOID ImageLoad(IMG Image, VOID *v)
{
    PinLocker locker;

    pInfo.addModule(Image);
    for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (util::iequals(dllName, m_Settings.funcWatch.funcs[i].dllName)) {
            MonitorFunctionArgs(Image, m_Settings.funcWatch.funcs[i]);
        }
    }
    if (m_Settings.hookSleep) {
        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (util::iequals(dllName, "ntdll")) {
            const CHAR *SLEEP = "NtDelayExecution";
            RTN sleepRtn = find_by_unmangled_name(Image, SLEEP);
            if (RTN_Valid(sleepRtn)) {
                RTN_Open(sleepRtn);
                RTN_InsertCall(sleepRtn, IPOINT_BEFORE, (AFUNPTR)HookNtDelayExecution,
                    IARG_PTR, SLEEP,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                    IARG_END);
                RTN_Close(sleepRtn);
            }
        }
    }
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: Register Function instrumentation needed for AntiDebug
    if (m_Settings.antidebug != WATCH_DISABLED) {
        // Register functions
        AntiDbg::MonitorAntiDbgFunctions(Image);
    }
#endif
#ifdef USE_ANTIVM
    // ANTIVM: Register Function instrumentation needed for AntiVm
    if (m_Settings.antivm) {
        // Register functions
        AntiVm::MonitorAntiVmFunctions(Image);
    }
#endif
}

static void OnCtxChange(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT *ctxtFrom,
    CONTEXT *ctxtTo,
    INT32 info,
    VOID *v)
{
    if (ctxtTo == NULL || ctxtFrom == NULL) return;

    PinLocker locker;

    const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
    _SaveTransitions(addrFrom, addrTo, FALSE);
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    
    std::string app_name = KnobModuleName.Value();
    if (app_name.length() == 0) {
        // init App Name:
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                app_name = argv[i + 1];
                break;
            }
        }
    }

    pInfo.init(app_name);

    const std::string iniFilename = KnobIniFile.ValueString();
    if (!m_Settings.loadINI(iniFilename)) {
        std::cerr << "Coud not load the INI file: " << iniFilename << std::endl;
        m_Settings.saveINI(iniFilename);
    }

    // select mode in which symbols should be initialized
    SYMBOL_INFO_MODE mode = EXPORT_SYMBOLS;
    if (m_Settings.useDebugSym) {
        std::cout << "Using debug symbols (if available)\n";
        mode = DEBUG_OR_EXPORT_SYMBOLS;
    }
    PIN_InitSymbolsAlt(mode);

    if (KnobStopOffsets.Enabled()) {
        std::string stopOffsetsFile = KnobStopOffsets.ValueString();
        if (stopOffsetsFile.length()) {
            const size_t loaded = Settings::loadOffsetsList(stopOffsetsFile.c_str(), m_Settings.stopOffsets);
            std::cout << "Loaded " << loaded << " stop offsets\n";
        }
    }
    if (KnobExcludedListFile.Enabled()) {
        std::string excludedList = KnobExcludedListFile.ValueString();
        if (excludedList.length()) {
            m_Settings.excludedFuncs.loadList(excludedList.c_str());
            std::cout << "Excluded " << m_Settings.excludedFuncs.funcs.size() << " functions\n";
        }
    }

    if (KnobWatchListFile.Enabled()) {
        std::string watchListFile = KnobWatchListFile.ValueString();
        if (watchListFile.length()) {
            m_Settings.funcWatch.loadList(watchListFile.c_str(), &m_Settings.excludedFuncs);
            std::cout << "Watch " << m_Settings.funcWatch.funcs.size() << " functions\n";
            std::cout << "Watch " << m_Settings.funcWatch.syscalls.size() << " syscalls\n";
        }
    }

    if (KnobSyscallsTable.Enabled()) {
        std::string syscallsTableFile = KnobSyscallsTable.ValueString();
        if (syscallsTableFile.length()) {
            m_Settings.syscallsTable.load(syscallsTableFile);
            std::cout << "SyscallTable size: " << m_Settings.syscallsTable.count() << "\n";
        }
    }

    // init output file:
    traceLog.init(KnobOutputFile.Value(), m_Settings.shortLogging);

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: collect some info on thread start
    if (m_Settings.antidebug != WATCH_DISABLED) {
        PIN_AddThreadStartFunction(AntiDbg::WatchThreadStart, 0);
    }
#endif
    if (m_Settings.traceSYSCALL) {
        // Register function to be called before every syscall instruction
        // (i.e., syscall, sysenter, int 2Eh)
        PIN_AddSyscallEntryFunction(SyscallCalled, NULL);
        PIN_AddSyscallExitFunction(SyscallCalledAfter, NULL);
    }

    // Register context changes
    PIN_AddContextChangeFunction(OnCtxChange, NULL);

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
    std::cerr << "Tracing module: " << app_name << std::endl;
    if (!KnobOutputFile.Value().empty())
    {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
