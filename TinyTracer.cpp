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
* saves PID in <output_file>.pid
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>

#include "ProcessInfo.h"
#include "TraceLog.h"

#define TOOL_NAME "TinyTracer"
#ifndef PAGE_SIZE
    #define PAGE_SIZE 0x1000
#endif

/* ================================================================== */
// Global variables 
/* ================================================================== */

ProcessInfo pInfo;
TraceLog traceLog;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "specify file name for the output");

KNOB<string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
    cerr << "This tool prints out : " << endl <<
        "Addresses of redirections into to a new sections. Called API functions." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
* This function is called for every basic block when it is about to be executed.
* @param[in]   numInstInBbl    number of instructions in the basic block
* @note use atomic operations for multi-threaded applications
*/

VOID SaveTranitions(ADDRINT Address, UINT32 numInstInBbl)
{
    PIN_LockClient();
    static s_module *prev_mod = NULL;
    static bool is_prevMy = false;
    static ADDRINT prevAddr = UNKNOWN_ADDR;

    const s_module *mod_ptr = pInfo.getModByAddr(Address);
    bool is_currMy = pInfo.isMyAddress(Address);

    //is it a transition from the traced module to a foreign module?
    if (!is_currMy && is_prevMy && prevAddr != UNKNOWN_ADDR) {
        if (!mod_ptr) {
            //not in any of the mapped modules:
            traceLog.logCall(prevAddr, Address);
        } else {
            IMG pImg = IMG_FindByAddress(Address);
            RTN rtn = RTN_FindByAddress(Address);

            if (IMG_Valid(pImg) && RTN_Valid(rtn)) {
                const string func = RTN_Name(rtn);
                traceLog.logCall(prevAddr, mod_ptr->name, func);
            }
            else {
                traceLog.logCall(prevAddr, mod_ptr->name);
            }
        }

    }
    //is the address within the traced module?
    if (is_currMy) {
        ADDRINT addr = Address - mod_ptr->start; // substract module's ImageBase
        const s_module* sec = pInfo.getSecByAddr(addr);
        // is it a transition from one section to another?
        if (pInfo.isSectionChanged(addr)) {
            std::string name = (sec) ? sec->name : "?";
            traceLog.logSectionChange(addr, name);
        }
        prevAddr = addr; /* update saved */
    }

    /* update saved */
    is_prevMy = is_currMy;
    prev_mod = (s_module*)mod_ptr;

    PIN_UnlockClient();
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
* Insert call to the SaveTranitions() analysis routine before every basic block
* of the trace.
* This function is called every time a new trace is encountered.
* @param[in]   trace    trace to be instrumented
* @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
*                       function call
*/
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to SaveTranitions() before every basic block
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)SaveTranitions,
                IARG_INST_PTR,
                IARG_UINT32, BBL_NumIns(bbl), IARG_END);
        }
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    pInfo.addModule(Image);
    //---
    //MonitorFunction1Arg(Image, "LoadLibraryA");
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

    // init output file:
    traceLog.init(KnobOutputFile.Value());

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by " << TOOL_NAME << endl;
    cerr << "Tracing module: " << app_name << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

