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
#include "FuncWatch.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "1.7"

#include "Util.h"
#include "Settings.h"


/* ================================================================== */
// Global variables 
/* ================================================================== */

Settings m_Settings;
ProcessInfo pInfo;
TraceLog traceLog;

FuncWatchList g_Watch;

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

/* ===================================================================== */
// Utilities
/* ===================================================================== */

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
// Analysis routines
/* ===================================================================== */

BOOL isTracedShellc(ADDRINT addr)
{
    if (m_tracedShellc.find(addr) != m_tracedShellc.end()) {
        return TRUE;
    }
    return FALSE;
}

VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo)
{
    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    IMG targetModule = IMG_FindByAddress(addrTo);
    IMG callerModule = IMG_FindByAddress(addrFrom);

    //is it a transition from the traced module to a foreign module?
    if (isCallerMy && !isTargetMy) {
        ADDRINT RvaFrom = addr_to_rva(addrFrom);
        if (IMG_Valid(targetModule)) {
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
    // trace calls from witin a shellcode:
    if (m_Settings.followShellcode && !IMG_Valid(callerModule)) {

        const ADDRINT pageFrom = query_region_base(addrFrom);
        const ADDRINT callerPage = pageFrom;
        if (callerPage != UNKNOWN_ADDR) {

            if (m_Settings.followShellcode == SHELLC_FOLLOW_ANY
                || isTracedShellc(callerPage))
            {
                const ADDRINT pageTo = query_region_base(addrTo);
                if (IMG_Valid(targetModule)) { // it is a call to a module

                    const std::string func = get_func_at(addrTo);
                    const std::string dll_name = IMG_Name(targetModule);
                    traceLog.logCall(callerPage, addrFrom, false, dll_name, func);
                }
                else if (pageFrom != pageTo) // it is a call to another shellcode
                {
                    // add the new shellcode to the set of traced
                    if (m_Settings.followShellcode != SHELLC_FOLLOW_FIRST) {
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
        }
    }

    // is the address within the traced module?
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

VOID SaveTransitions(const ADDRINT prevVA, const ADDRINT Address)
{
    PIN_LockClient();
    _SaveTransitions(prevVA, Address);
    PIN_UnlockClient();
}

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logRdtsc(0, rva);
    }
    if (m_Settings.followShellcode && !IMG_Valid(currModule)) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logRdtsc(start, rva);
        }
    }

    PIN_UnlockClient();
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);

    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logCpuid(0, rva, Param);
    }
    if (m_Settings.followShellcode && !IMG_Valid(currModule)) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logCpuid(start, rva, Param);
        }
    }

    PIN_UnlockClient();
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
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, false);
    PIN_UnlockClient();

    return result;
}

ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt)
{
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, true);
    PIN_UnlockClient();

    return result;
}

/* ===================================================================== */
// Instrument functions arguments
/* ===================================================================== */

bool isWatchedAddress(const ADDRINT Address)
{
    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        return true;
    }
    const BOOL isShellcode = !IMG_Valid(currModule);
    if (m_Settings.followShellcode && isShellcode) {
        if (m_Settings.followShellcode == SHELLC_FOLLOW_ANY) {
            return true;
        }
        const ADDRINT callerRegion = query_region_base(Address);
        // trace calls from the monitored shellcode only:
        if (callerRegion != UNKNOWN_ADDR && isTracedShellc(callerRegion)) {
            return true;
        }
    }
    return false;
}

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
            << std::dec << ((uint64_t)arg1);
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

VOID _LogFunctionArgs(const ADDRINT Address, CHAR *name, uint32_t argCount, VOID *arg1, VOID *arg2, VOID *arg3, VOID *arg4, VOID *arg5, VOID *arg6, VOID *arg7, VOID *arg8, VOID *arg9, VOID *arg10)
{
    if (!isWatchedAddress(Address)) return;

    const size_t argsMax = 10;
    VOID* args[argsMax] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10 };
    std::wstringstream ss;
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
    PIN_LockClient();
    _LogFunctionArgs(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
    PIN_UnlockClient();
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
        INS_InsertCall(
            ins, 
            IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_END
        );
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    PIN_LockClient();
    pInfo.addModule(Image);
    for (size_t i = 0; i < g_Watch.funcs.size(); i++) {
        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (util::iequals(dllName, g_Watch.funcs[i].dllName)) {
            MonitorFunctionArgs(Image, g_Watch.funcs[i]);
        }
    }
    PIN_UnlockClient();
}

static void OnCtxChange(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT *ctxtFrom,
    CONTEXT *ctxtTo,
    INT32 info,
    VOID *v)
{
    if (ctxtTo == NULL || ctxtFrom == NULL) return;

    PIN_LockClient();
    const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
    _SaveTransitions(addrFrom, addrTo);
    PIN_UnlockClient();
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
            size_t loaded = g_Watch.loadList(watchListFile.c_str());
            std::cout << "Watch " << loaded << " functions\n";
        }
    }

    // init output file:
    traceLog.init(KnobOutputFile.Value(), m_Settings.shortLogging);

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);

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
