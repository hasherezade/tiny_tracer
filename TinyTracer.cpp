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
#include <bitset>

#include "TinyTracer.h"

#include "ProcessInfo.h"
#include "TraceLog.h"
#include "PinLocker.h"
#include "DisasmCache.h"
#include "TrackReturns.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "3.1"

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

#ifdef _WIN32
#include "ExportsInfo.h"
#endif //_WIN32

bool g_IsIndirectSyscall = false;

/* ================================================================== */
// Global variables 
/* ================================================================== */

Settings m_Settings;
ProcessInfo pInfo;
TraceLog traceLog;

// last shellcode to which the transition got redirected:
std::set<ADDRINT> m_tracedShellc;

// Full pin path
std::string pinPath;

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


VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PinLocker locker;
    RetTracker::InitTrackerForThread(tid);
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

std::string flagsToStr(ADDRINT oldFlags, ADDRINT flags)
{
    const int flag[] = {
        0x1,
        0x4,
        0x10,
        0x40,
        0x80,
        0x100,
        0x200,
        0x400,
        0x800
    };
    const char flagName[] = {
        'C', 'P', 'A', 'Z', 'S', 'T', 'I', 'D', 'O'
    };
    const size_t max = sizeof(flag) / sizeof(flag[0]);
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < max; i++) {
        ADDRINT flagSet = flags & flag[i];
        if (flagSet != (oldFlags & flag[i])) {
            ss << " " << flagName[i] << "=" << (flagSet != 0);
        }
    }
    ss << " ]";
    return ss.str();
}

std::string dumpContext(const std::string& disasm, const CONTEXT* ctx)
{
    const char* reg_names[] = {
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
        "flags"
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
#ifdef _WIN64
        REG_R8,
        REG_R9,
        REG_R10,
        REG_R11,
        REG_R12,
        REG_R13,
        REG_R14,
        REG_R15,
#endif
        REG_GFLAGS
    };
    const size_t regsCount = sizeof(regs) / sizeof(regs[0]);
    static ADDRINT values[regsCount] = { 0 };
    static ADDRINT spVal = 0;

    std::stringstream ss;

    ADDRINT Address = getReturnFromTheStack(ctx);
    if (Address != spVal) {
        ss << "[rsp] -> 0x" << std::hex << Address << "; ";
        spVal = Address;
    }
    ADDRINT prev = 0;
    for (size_t i = 0; i < regsCount; i++) {
        REG reg = regs[i];
        const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctx, reg);
        if (values[i] == Address) {
            continue;
        }
        // update saved:
        prev = values[i];
        values[i] = Address;

        ss << reg_names[i] << " = 0x" << std::hex << Address;
        if (reg == REG_GFLAGS) {
            ss << " " << flagsToStr(prev, Address);
        }
        ss << "; ";
    }
    std::string out = ss.str();
    if (!out.empty()) {
        return "{ " + out + "}";
    }
    return "";
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

std::string resolve_func_name(const ADDRINT addrTo, const std::string& dll_name, const CONTEXT* ctx)
{
    ADDRINT diff = 0;
    const std::string name = get_func_at(addrTo, diff);
    if (!diff) {
        // simple case, return the name
        return name;
    }
    // it doesn't start at the beginning of the routine:
    std::ostringstream sstr;
    sstr << "[" << name << "+" << std::hex << diff << "]*";
#ifdef _WIN32
    if (ctx
        && SyscallsTable::isSyscallFuncName(name)
        && SyscallsTable::isSyscallDll(util::getDllName(dll_name))
        )
    {
        //possibly a proxy to the indirect syscall
        g_IsIndirectSyscall = true;
        const ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
        const std::string realName = m_Settings.syscallsTable.getName(eax);
        sstr << " -> ";
        if (realName.length()) {
            sstr << realName;
        }
        else {
            sstr << "SYSCALL:0x" << eax;
        }
    }
#endif //_WIN32
    return sstr.str();
}

bool isExcludedDll(const std::string &dll_name)
{
    const std::string shortDll = util::getDllName(dll_name);
    for (auto itr = m_Settings.excludedDll.begin(); itr != m_Settings.excludedDll.end(); ++itr) {
        const std::string excludedDLL = *itr;
        if (util::iequals(excludedDLL, shortDll)) {
            return true;
        }
    }
    return false;
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
            const std::string dll_name = IMG_Name(targetModule);
            if (isExcludedDll(dll_name)) {
                return;
            }
            const std::string func = resolve_func_name(addrTo, dll_name, ctx);
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
            const std::string dll_name = IMG_Name(targetModule);
            const std::string func = resolve_func_name(addrTo, dll_name, ctx);
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
            const std::string dll_name = IMG_Name(targetModule);
            const std::string func = resolve_func_name(addrTo, dll_name, ctx);
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
    trace transitions within the traced module:
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
        // is it a call to the custom function?
        const auto found = m_Settings.customDefs.find(rva);
        if (found != m_Settings.customDefs.end()) {
            traceLog.logInstruction(0, rva, found->second);
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

    if (m_Settings.logReturn) {
        RetTracker::LogCallDetails(Address,
            const_cast<CHAR*>(name),
            argCount,
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

    //reset just in case:
    syscallFromThread[tid] = SyscallInfo();
    ADDRINT address = UNKNOWN_ADDR;

    if (!_fetchSyscallData(ctxt, std, address)) {
        return;
    }
    const WatchedType wType = isWatchedAddress(address);
    if (wType == WatchedType::NOT_WATCHED && !g_IsIndirectSyscall) {
        return;
    }
    ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
    if (syscallNum == UNKNOWN_ADDR) return; //invalid
    syscallNum &= MAX_WORD;

    syscallFromThread[tid].fill(syscallNum, address);

    const std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(address); // convert to RVA
        traceLog.logSyscall(0, rva, syscallNum, syscallFuncName);
    }
    else if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(address);
        ADDRINT rva = address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logSyscall(start, rva, syscallNum, syscallFuncName);
        }
    }
    // Log arguments if needed:
    // 
    // check if it is watched by the syscall number:
#ifdef _WIN32 // used only on Windows
    bool argsDumped = false;
#endif //_WIN32
    const auto& it = m_Settings.funcWatch.syscalls.find(syscallNum);
    if (it != m_Settings.funcWatch.syscalls.end()) {
        LogSyscallsArgs(WSyscallInfo::formatSyscallName(syscallNum).c_str(), ctxt, std, address, it->second.paramCount);
#ifdef _WIN32 // used only on Windows
        argsDumped = true;
#endif //_WIN32
    }
#ifdef _WIN32 // supported only for Windows
    // check if it is watched by the function name:
    if (!argsDumped) {
        for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
            if (SyscallsTable::isSyscallDll(m_Settings.funcWatch.funcs[i].dllName)) {
                std::string watchFuncName = SyscallsTable::convertNameToNt(m_Settings.funcWatch.funcs[i].funcName);
                if (util::iequals(syscallFuncName, watchFuncName)) {
                    LogSyscallsArgs(watchFuncName.c_str(), ctxt, std, address, m_Settings.funcWatch.funcs[i].paramCount);
                    argsDumped = true;
                    break;
                }
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
    g_IsIndirectSyscall = false; //reset

    auto itr = syscallFromThread.find(tid);
    if (itr == syscallFromThread.end() || itr->second.ssid == UNKNOWN_ADDR) {
        return;
    }
#ifdef USE_ANTIVM
    const ADDRINT syscallNum = itr->second.ssid;
#endif //USE_ANTIVM

    const ADDRINT address = itr->second.addrFrom;

    // Retrieve the syscall return value
    RetTracker::HandleFunctionReturn(tid, address, PIN_GetSyscallReturn(ctxt, std));

    itr->second.reset(); // sycall completed, erase the stored info

    if (address == UNKNOWN_ADDR) {
        return;
    }
#ifdef USE_ANTIVM
    if (m_Settings.antivm != WATCH_DISABLED) {
        const std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
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


size_t getReadableMemSize(VOID* addr)
{
    const ADDRINT start = query_region_base((ADDRINT)addr);
    if (start == UNKNOWN_ADDR || start == 0) {
        return 0;
    }
    OS_MEMORY_AT_ADDR_INFORMATION memInfo;
    OS_RETURN_CODE result = OS_QueryMemory(PIN_GetPid(), addr, &memInfo);

    if (result.generic_err != OS_RETURN_CODE_NO_ERROR || !memInfo.MapSize) {
        return 0;
    }
    if (memInfo.Protection == OS_PAGE_PROTECTION_TYPE_NOACCESS) {
        return 0;
    }
    size_t memSize = memInfo.MapSize;
    const VOID* base = memInfo.BaseAddress;
    if ((ADDRINT)addr < (ADDRINT)base || (ADDRINT)addr >= ((ADDRINT)base + memSize)) {
        return 0; // failed boundary check
    }
    if (base != 0 && base < addr) {
        size_t pos = (ADDRINT)addr - (ADDRINT)base;
        memSize -= pos;
    }
    return (memInfo.Protection & OS_PAGE_PROTECTION_TYPE_READ) ? memSize : 0;
}

BOOL isValidReadPtr(VOID* ptr)
{
    return getReadableMemSize(ptr) != 0 ? TRUE : FALSE;
}

std::wstring paramToStr(VOID *arg1)
{
    if (arg1 == NULL) {
        return L"0";
    }
    std::wstringstream ss;
    const size_t rSize = getReadableMemSize(arg1);

    if (!rSize) {
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

    if (rSize >= sizeof(T_UNICODE_STRING)) {

        T_UNICODE_STRING* unicodeS = reinterpret_cast<T_UNICODE_STRING*>(arg1);
        const size_t bufSize = getReadableMemSize(unicodeS->Buffer);
        const size_t bufSizeW = bufSize / sizeof(wchar_t);
        if (bufSize != 0
            && (unicodeS->MaximumLength < bufSizeW)
            && (unicodeS->Length <= unicodeS->MaximumLength) // check if the length makes sense
            )
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
    }

    bool isString = false;
    const char* val = reinterpret_cast<char*>(arg1);
    const size_t len = util::getAsciiLen(val, rSize);

    if (len == 1) { // Possible wideString
        wchar_t* val = reinterpret_cast<wchar_t*>(arg1);
        size_t wLen = util::getAsciiLenW(val, rSize);
        if (wLen >= len) {
            ss << " -> ";
            ss << "L\"" << val << "\"";
            isString = true;
        }
    }
    else if (len > 1) { // ASCII string
        ss << " -> ";
        ss << "\"" << val << "\"";
        isString = true;
    }
    if (!isString) {
        ss << " -> {";
        const size_t dumpSize = (rSize < m_Settings.hexdumpSize) ? rSize : m_Settings.hexdumpSize;
        ss << util::hexdump(reinterpret_cast<const uint8_t*>(val), dumpSize);
        ss << "}";
    }
    return ss.str();
}

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11)
{
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
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;
    _LogFunctionArgs(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);

    if (m_Settings.logReturn) {
        RetTracker::LogCallDetails(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
    }
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

VOID LogInstruction(const CONTEXT* ctxt, THREADID tid, const char* disasm)
{
    if (!disasm) return;

    PinLocker locker;

    static BOOL traceStarted = FALSE;

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
        const t_disasm_status dStat = m_Settings.findInDisasmRange(rva);
        if (dStat == DISASM_START) {
            traceStarted = TRUE;
        }
    }
    if (!traceStarted) {
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
        const t_disasm_status dStat = m_Settings.findInDisasmRange(rva);
        if (!base && dStat == DISASM_START) {
            ss << " # disasm start";
        }
        if (!base && dStat == DISASM_STOP) {
            ss << " # disasm end";
        }
        if (m_Settings.disasmCtx) {
            const std::string ctxStr = dumpContext(disasm, ctxt);
            if (!ctxStr.empty()) {
                traceLog.logLine("\t\t\t\t" + ctxStr);
            }
        }
        traceLog.logInstruction(base, rva, ss.str());
    }
    const t_disasm_status dStat = m_Settings.findInDisasmRange(rva);
    if (wType == WatchedType::WATCHED_MY_MODULE && dStat == DISASM_STOP) {
        traceStarted = FALSE;
    }
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID HandleFunctionReturn(const THREADID tid, const ADDRINT ip, const ADDRINT retVal)
{
    PinLocker locker;
    return RetTracker::HandleFunctionReturn(tid, ip, retVal);
}

VOID InstrumentInstruction(INS ins, VOID *v)
{
    if (m_Settings.logReturn) {
        // Insert callback for function returns
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleFunctionReturn,
            IARG_THREAD_ID,        // Thread ID for TLS
            IARG_INST_PTR,         // Instruction pointer
            IARG_REG_VALUE, REG_GAX, // Return value in EAX/RAX
            IARG_END);
    }
    const IMG pImg = IMG_FindByAddress(INS_Address(ins));
    const BOOL isMyImg = pInfo.isMyImg(pImg);
    BOOL inWatchedModule = isMyImg;
    if (m_Settings.followShellcode != t_shellc_options::SHELLC_DO_NOT_FOLLOW
        && !IMG_Valid(pImg))
    {
        inWatchedModule = TRUE;
    }
    // only the main module or shellcodes:
    if (inWatchedModule && m_Settings.disasmRanges.size()) {
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
        
        AntiDbg::InstrumentFlagsCheck(ins);

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

VOID InstrumentSleep(IMG Image)
{
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "ntdll")) {
        const CHAR* funcName = "NtDelayExecution";
        RTN sleepRtn = find_by_unmangled_name(Image, funcName);
        if (RTN_Valid(sleepRtn)) {
            RTN_Open(sleepRtn);
            RTN_InsertCall(sleepRtn, IPOINT_BEFORE, (AFUNPTR)HookNtDelayExecution,
                IARG_PTR, funcName,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
            RTN_Close(sleepRtn);
        }
    }
}

/* ===================================================================== */
std::map<THREADID, VOID*> volumeSerialPtrs;

VOID Mod_GetVolumeInformation_before(const ADDRINT Address, const THREADID tid, const CHAR* name, VOID* volumeSerialPtr)
{
    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    if (!volumeSerialPtr) return;
    volumeSerialPtrs[tid] = volumeSerialPtr;
}

VOID Mod_GetVolumeInformation_after(const ADDRINT Address, const THREADID tid, const CHAR* name, UINT32 volumeID, ADDRINT status)
{
    PinLocker locker;
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    auto itr = volumeSerialPtrs.find(tid);
    if (itr == volumeSerialPtrs.end()) {
        return;
    }
    VOID* ptr = itr->second;

    if (status && ptr) {
        PIN_SafeCopy(ptr, &volumeID, sizeof(volumeID));
    }
    volumeSerialPtrs.erase(itr);

    std::stringstream ss;
    ss << "Volume ID replaced: " << std::hex << volumeID;
    LogMsgAtAddress(wType, Address, "[MOD] --> ", ss.str().c_str());
}

VOID InstrumentVolumeInfo(IMG Image, uint32_t volumeID)
{
    if (!volumeID) return;
    if (!IMG_Valid(Image)) return;

    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (!util::iequals(dllName, "kernel32") && !util::iequals(dllName, "kernelbase")) {
        return;
    }
    const size_t functionsCount = 2;
    const char* functions[functionsCount] = {
        "GetVolumeInformationA",
        "GetVolumeInformationW"
    };
    for (size_t i = 0; i < functionsCount; i++)
    {
        const char* fName = functions[i];
        RTN funcRtn = find_by_unmangled_name(Image, fName);
        if (RTN_Valid(funcRtn)) {
            RTN_Open(funcRtn);

            RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(Mod_GetVolumeInformation_before),
                IARG_RETURN_IP,
                IARG_THREAD_ID,
                IARG_ADDRINT, fName,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_END
            );

            RTN_InsertCall(funcRtn, IPOINT_AFTER, AFUNPTR(Mod_GetVolumeInformation_after),
                IARG_RETURN_IP,
                IARG_THREAD_ID,
                IARG_ADDRINT, fName,
                IARG_UINT32, volumeID,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_Close(funcRtn);
        }
    }
}
/* ===================================================================== */

VOID AddCustomFunctions(IMG img, const std::map<ADDRINT, std::string> &customDefs)
{
    if (!pInfo.isMyImg(img)) {
        return;
    }
    ADDRINT base = IMG_LoadOffset(img);
    if (base == 0) {
        base = IMG_LowAddress(img);
    }
    for (auto itr = customDefs.begin(); itr != customDefs.end(); ++itr) {
        ADDRINT funcVA = base + itr->first;
        RTN rtn = RTN_FindByAddress(funcVA);

        if (RTN_Address(rtn) != funcVA) {
            RTN_CreateAt(funcVA, itr->second);
#ifdef _DEBUG
            std::cerr << "Created named routine at: " << std::hex << funcVA  << " : " << itr->second << std::endl;
#endif //_DEBUG
        }
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    PinLocker locker;

    pInfo.addModule(Image);
#ifdef _WIN32
    if (m_Settings.parseExports) {
        ExportsInfo::addFromFile(Image);
    }
#endif // _WIN32
    
    AddCustomFunctions(Image, m_Settings.customDefs);

    for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (util::iequals(dllName, m_Settings.funcWatch.funcs[i].dllName)) {
            MonitorFunctionArgs(Image, m_Settings.funcWatch.funcs[i]);
        }
    }

#ifdef _WIN32
    if (m_Settings.hookSleep) {
        InstrumentSleep(Image);
    }
    if (m_Settings.volumeID) {
        InstrumentVolumeInfo(Image, m_Settings.volumeID);
    }
#endif // _WIN32

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

BOOL FollowChild(CHILD_PROCESS childProcess, VOID* userData)
{
    if (!m_Settings.followChildprocesses) {
#ifdef _DEBUG
        std::cerr << "Following child process is disabled\n";
#endif
        return FALSE;
    }
    OS_PROCESS_ID childPid = CHILD_PROCESS_GetId(childProcess);
    std::cerr << "Following Subprocess: " << childPid << std::endl;

    // Get child process command line
    INT childArgc;
    CHAR const* const* childArgv;
    CHILD_PROCESS_GetCommandLine(childProcess, &childArgc, &childArgv);
    // Set Pin's command line for child process, rebuilding with the same options updated
    INT pinArgc = 0;
    const INT pinArgcMax = 40;
    CHAR const* pinArgv[pinArgcMax];

    pinArgv[pinArgc++] = pinPath.c_str();
    pinArgv[pinArgc++] = "-follow_execv";
    pinArgv[pinArgc++] = "-t";
    pinArgv[pinArgc++] = PIN_ToolFullPath();
    pinArgv[pinArgc++] = "-o";
    pinArgv[pinArgc++] = KnobOutputFile.Value().c_str();
    pinArgv[pinArgc++] = "-s";
    pinArgv[pinArgc++] = KnobIniFile.Value().c_str();
    pinArgv[pinArgc++] = "-b";
    pinArgv[pinArgc++] = KnobWatchListFile.Value().c_str();
    pinArgv[pinArgc++] = "-x";
    pinArgv[pinArgc++] = KnobExcludedListFile.Value().c_str();
    pinArgv[pinArgc++] = "-p";
    pinArgv[pinArgc++] = KnobStopOffsets.Value().c_str();
    pinArgv[pinArgc++] = "-l";
    pinArgv[pinArgc++] = KnobSyscallsTable.Value().c_str();
    pinArgv[pinArgc++] = "-m";
    pinArgv[pinArgc++] = childArgv[0];
    pinArgv[pinArgc++] = "--";
    // Now copy the child command line
    for (int i = 0; i < childArgc && pinArgc < pinArgcMax; i++) {
        pinArgv[pinArgc++] = childArgv[i];
    }
    CHILD_PROCESS_SetPinCommandLine(childProcess, pinArgc, pinArgv);
    return TRUE;
}

std::string addPidToFilename(const std::string& filename, int pid)
{
    std::stringstream fnamestr;
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos || pos >= filename.length()) {
        fnamestr << filename << "." << pid;
    }
    else {
        fnamestr << filename.substr(0, pos) << "." << pid << '.' << filename.substr(pos + 1);
    }
    return fnamestr.str();
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
    
    pinPath = argv[0];
    std::string targetModule = KnobModuleName.Value();
    if (targetModule.length() == 0) {
        // init App Name:
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                targetModule = argv[i + 1];
                break;
            }
        }
    }

    pInfo.init(targetModule);

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
            m_Settings.loadExcluded(excludedList.c_str());
            std::cout << "Excluded " << m_Settings.excludedFuncs.funcs.size() << " functions\n";
            std::cout << "Excluded " << m_Settings.excludedDll.size() << " DLLs\n";
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
    std::string outDir = "";
    if (KnobOutputFile.Enabled() && !KnobOutputFile.Value().empty()){
        outDir = util::getDirectory(KnobOutputFile.Value());
    }
    std::string filename = util::makePath(outDir, targetModule, "tag");
    if (m_Settings.followChildprocesses) {
        filename = addPidToFilename(filename, PIN_GetPid());
    }
    traceLog.init(filename, m_Settings.shortLogging);

    std::string customDefsPath = util::makePath(outDir, targetModule, "func.csv");
    Settings::loadCustomDefs(customDefsPath.c_str(), m_Settings.customDefs);
    if (m_Settings.customDefs.size()) {
        std::cout << "Custom definitions: " << m_Settings.customDefs.size() << std::endl;
    }

    if (m_Settings.disasmRanges.size()) {
        std::cout << "Disasm ranges: " << m_Settings.disasmRanges.size() << std::endl;
    }

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

    if (m_Settings.logReturn) {
        RetTracker::InitTracker();

        // Register the ThreadStart callback
        PIN_AddThreadStartFunction(ThreadStart, NULL);
    }

    // Register the callback function for child processes
    PIN_AddFollowChildProcessFunction(FollowChild, 0);

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
    std::cerr << "Tracing module: " << targetModule << std::endl;
    if (!filename.empty())
    {
        std::cerr << "See file " << filename << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
