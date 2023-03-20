/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m    <module_name> ; Analysed module name (by default same as app name)
* -o    <output_path> Output file
*
*/
#include "pin.H"

#include <iostream>
#include <string>
#include <set>

#include "ProcessInfo.h"
#include "TraceLog.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "2.3"

#include "Util.h"
#include "Settings.h"

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

/* ===================================================================== */
// Utilities
/* ===================================================================== */

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10);

/*!
*  A locker class.
*/
class PinLocker
{
public:
    PinLocker()
    {
        PIN_LockClient();
    }

    ~PinLocker()
    {
        PIN_UnlockClient();
    }
};

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

// compare strings, ignore case
bool isStrEqualI(const std::string &str1, const std::string &str2)
{
    if (str1.length() != str2.length()) {
        return false;
    }
    for (size_t i = 0; i < str1.length(); i++) {
        if (tolower(str1[i]) != tolower(str2[i])) {
            return false;
        }
    }
    return true;
}


/* ===================================================================== */
// Analysis utilities
/* ===================================================================== */

BOOL isInTracedShellc(ADDRINT addr)
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

enum class WatchedType {
    NOT_WATCHED = 0,
    WATCHED_MY_MODULE,
    WATCHED_SHELLCODE
};

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
    return WatchedType::NOT_WATCHED;;
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

VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, BOOL isIndirect, const CONTEXT* ctx = NULL)
{
    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    const WatchedType fromWType = isWatchedAddress(addrFrom); // is the call from the traced area?

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

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logRdtsc(0, rva);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logRdtsc(start, rva);
        }
    }
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logCpuid(0, rva, Param);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logCpuid(start, rva, Param);
        }
    }
}

VOID LogSyscallsArgs(const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address, uint32_t argCount)
{
    const size_t args_max = 10;
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
        syscall_args[9]);
}

std::string formatSyscallName(int syscallID)
{
    std::stringstream ss;
    ss << "SYSCALL:0x" << std::hex << (syscallID);
    return ss.str();
}

VOID SyscallCalled(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    PinLocker locker;
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
            return;
        }
        std = SYSCALL_STANDARD_IA32E_WINDOWS_FAST;
    }
#endif

    const auto address = [&]() -> ADDRINT {
        if (std == SYSCALL_STANDARD_WOW64) {
            // Note: In this case, the current instruction address is in a 64-bit
            // code portion. The address that we're interested in is the return
            // address, which is in a 32-bit code portion.
            return getReturnFromTheStack(ctxt);
        }
        return PIN_GetContextReg(ctxt, REG_INST_PTR);
    }();
    
    const WatchedType wType = isWatchedAddress(address);
    if (wType == WatchedType::NOT_WATCHED) return;
    
    const ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
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

    // Log arguments if needed
    bool isSyscallWatched = false;
    // check if it is watched by the syscall number:
    const auto& it = m_Settings.funcWatch.syscalls.find(syscallNum);
    if (it != m_Settings.funcWatch.syscalls.end()) {
        LogSyscallsArgs(formatSyscallName(syscallNum).c_str(), ctxt, std, address, it->second.paramCount);
        isSyscallWatched = true;
    }

    if (!isSyscallWatched) {
        // check if it is watched by the function name:
        std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
        for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
            if (util::iequals("ntdll", m_Settings.funcWatch.funcs[i].dllName)
                || util::iequals("win32u", m_Settings.funcWatch.funcs[i].dllName))
            {
                std::string funcName = SyscallsTable::convertNameToNt(m_Settings.funcWatch.funcs[i].funcName);
                if (syscallFuncName == funcName) {
                    LogSyscallsArgs(funcName.c_str(), ctxt, std, address, m_Settings.funcWatch.funcs[i].paramCount);
                    isSyscallWatched = true;
                    break;
                }
            }
        }
    }
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

std::wstring paramToStr(VOID *arg1)
{
    if (arg1 == NULL) {
        return L"0";
    }
    const size_t kMaxStr = 300;
    const BOOL isReadableAddr = PIN_CheckReadAccess(arg1);
    std::wstringstream ss;

    if (!isReadableAddr) {
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

    T_UNICODE_STRING unicodeS = *(T_UNICODE_STRING*)arg1;
    if (PIN_CheckReadAccess(unicodeS.Buffer)) {
        size_t len = util::getAsciiLen((char*)unicodeS.Buffer, kMaxStr);
        if (len == 1) {
            // Must be wide string
            size_t wLen = util::getAsciiLenW(unicodeS.Buffer, kMaxStr);
            if (wLen >= len) {
                if ((unicodeS.Length / sizeof(wchar_t)) == wLen && unicodeS.MaximumLength >= unicodeS.Length) { // An extra check, just to make sure
                    ss << " -> ";
                    ss << "U\"" << unicodeS.Buffer << "\""; // Just made the U up to denote a UNICODE_STRING
                    return ss.str();
                }
            }
        }
    }

    bool isString = false;
    const char* val = (char*)arg1;
    size_t len = util::getAsciiLen(val, kMaxStr);
    if (len > 0) {
        ss << " -> ";
    }
    if (len == 1) { // Possible wideString
        wchar_t* val = (wchar_t*)arg1;
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
        ss << util::hexdump((const uint8_t*)val, m_Settings.hexdumpSize);
        ss << "}";
    }
    return ss.str();
}

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR *name, uint32_t argCount, VOID *arg1, VOID *arg2, VOID *arg3, VOID *arg4, VOID *arg5, VOID *arg6, VOID *arg7, VOID *arg8, VOID *arg9, VOID *arg10)
{
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    const size_t argsMax = 10;
    VOID* args[argsMax] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10 };
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

VOID LogFunctionArgs(const ADDRINT Address, CHAR *name, uint32_t argCount, VOID *arg1, VOID *arg2, VOID *arg3, VOID *arg4, VOID *arg5, VOID *arg6, VOID *arg7, VOID *arg8, VOID *arg9, VOID *arg10)
{
    PinLocker locker;
    _LogFunctionArgs(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

VOID MonitorFunctionArgs(IMG Image, const WFuncInfo &funcInfo)
{
    const CHAR* fName = funcInfo.funcName.c_str();
    size_t argNum = funcInfo.paramCount;
    RTN funcRtn = RTN_FindByName(Image, fName);
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

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID InstrumentInstruction(INS ins, VOID *v)
{
    if (isStrEqualI(INS_Mnemonic(ins), "cpuid")) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)CpuidCalled,
            IARG_CONTEXT,
            IARG_END
        );
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

    if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
        BOOL isIndirect = INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins);
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
            RTN sleepRtn = RTN_FindByName(Image, SLEEP);
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

    PIN_InitSymbols();
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

    if (KnobWatchListFile.Enabled()) {
        std::string watchListFile = KnobWatchListFile.ValueString();
        if (watchListFile.length()) {
            m_Settings.funcWatch.loadList(watchListFile.c_str());
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

    if (m_Settings.traceSYSCALL) {
        // Register function to be called before every syscall instruction
        // (i.e., syscall, sysenter, int 2Eh)
        PIN_AddSyscallEntryFunction(SyscallCalled, NULL);
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
