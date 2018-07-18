/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m	<module_name> ; Analysed module name (by default same as app name)
* -o	<output_path> Output file
*
* saves PID in <output_file>.pid
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>

#define TOOL_NAME "TinyTracer"
#ifndef PAGE_SIZE
    #define PAGE_SIZE 0x1000
#endif
#define UNKNOWN_ADDR (-1)

/* ================================================================== */
// Global variables 
/* ================================================================== */

std::string m_AnalysedApp;
std::string m_Param;
FILE *m_BlocksFile = NULL;	// output

INT m_myPid = 0;		//PID of application
std::string m_PidFileName;

std::set<ADDRINT> m_blocks;	// set of unique blocks addresses

struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
};

std::map<ADDRINT, s_module> m_Modules;
std::map<ADDRINT, s_module> m_Sections;

const s_module* getModuleByAddr(ADDRINT Address, std::map<ADDRINT, s_module> &modules)
{
    std::map<ADDRINT, s_module>::iterator bound = modules.upper_bound(Address);
    std::map<ADDRINT, s_module>::iterator itr = modules.begin();

    for (; itr != bound; itr++) {
        s_module &mod = itr->second;
        if (Address >= mod.start && Address < mod.end) {
            return &mod;
        }
    }
    return NULL;
}

const bool isPageChanged(ADDRINT Address /* without imagebase */)
{
    static ADDRINT prevPageAddr = UNKNOWN_ADDR;

    ADDRINT currPageAddr = (Address / PAGE_SIZE);
    if (prevPageAddr == UNKNOWN_ADDR || prevPageAddr != currPageAddr) { // execution in different memory page!
        prevPageAddr = currPageAddr;
        return true;
    }
    return false;
}

const bool isSectionChanged(ADDRINT Address /* without imagebase */)
{
    static s_module* prevModule = NULL;
    const s_module* currModule = getModuleByAddr(Address, m_Sections);

    if (prevModule != currModule) {
        prevModule = (s_module*)currModule;
        return true;
    }
    return false;
}

bool isMyModule(const s_module* mod, std::string name)
{
    if (!mod) return false;
    std::size_t found = mod->name.find(name);
    if (found != std::string::npos) {
        return true;
    }
    return false;
}

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
        "Addresses of redirections into to a new section." << endl << endl;

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

    const s_module *mod_ptr = getModuleByAddr(Address, m_Modules);
    bool is_currMy = isMyModule(mod_ptr, m_AnalysedApp);

    if (is_currMy == false && is_prevMy == true && prevAddr != UNKNOWN_ADDR) {
        if (mod_ptr) {
            fprintf(m_BlocksFile, "%p;called module: %s:", prevAddr, mod_ptr->name.c_str());

            //PIN_LockClient();
            IMG pImg = IMG_FindByAddress(Address);
            RTN rtn = RTN_FindByAddress(Address);
            //PIN_UnlockClient();

            if (IMG_Valid(pImg) && RTN_Valid(rtn)) {
                const string func = RTN_Name(rtn);
                fprintf(m_BlocksFile, "%s", func.c_str());
            }
            fprintf(m_BlocksFile, "\n");

        }
        else {
            fprintf(m_BlocksFile, "%p;called module: ?? [%p];\n", prevAddr, Address);
        }
        fflush(m_BlocksFile);
    }

    if (is_currMy) {
        ADDRINT addr = Address - mod_ptr->start; // substract module's ImageBase
        const s_module* sec = getModuleByAddr(addr, m_Sections);
        if (isSectionChanged(addr)) {
            std::string name = (sec != NULL) ? sec->name : "?";
            fprintf(m_BlocksFile, "%p;sec: %s\n", addr, name.c_str());
            fflush(m_BlocksFile);
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

VOID BeforeFunction1Arg(CHAR * name, CHAR * filename)
{
    if (filename == NULL) return;
    //>
    PIN_LockClient();
    fprintf(m_BlocksFile, "arg: %s\n", filename);
    fflush(m_BlocksFile);
    PIN_UnlockClient();
    //<
}

VOID MonitorFunction1Arg(IMG Image, const char* funcName)
{
    RTN cfwRtn = RTN_FindByName(Image, funcName);
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);
        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)BeforeFunction1Arg,
            IARG_ADDRINT, funcName,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END
        );
        RTN_Close(cfwRtn);
    }
}


VOID ImageLoad(IMG Image, VOID *v)
{
    // Add module into a global map
    s_module mod;
    mod.name = std::string(IMG_Name(Image));
    mod.start = IMG_LowAddress(Image);
    mod.end = IMG_HighAddress(Image);
    m_Modules[mod.start] = mod;

    if (m_myPid == 0 && isMyModule(&mod, m_AnalysedApp)) {
        FILE *pidFile = fopen(m_PidFileName.c_str(), "w");
        if (pidFile) {
            m_myPid = PIN_GetPid();
            fprintf(pidFile, "%d\n", m_myPid);
            fclose(pidFile);
        }

        // enumerate sections within the analysed module
        for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {

            s_module section;
            section.name = SEC_Name(sec);
            section.start = SEC_Address(sec) - mod.start;
            section.end = section.start + SEC_Size(sec);
            m_Sections[section.start] = section;
        }
    }
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

    m_AnalysedApp = KnobModuleName.Value();
    if (m_AnalysedApp.length() == 0) {
        // init App Name (m_AnalysedApp):
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                m_AnalysedApp = argv[i + 1];
                if (i + 2 < argc) {
                    m_Param = argv[i + 2];
                }
                break;
            }
        }
    }
    // init output file:
    string fileName = KnobOutputFile.Value();
    if (fileName.empty()) fileName = "output.txt";

    m_BlocksFile = fopen(fileName.c_str(), "w");
    m_PidFileName = fileName + ".pid";

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by " << TOOL_NAME << endl;
    cerr << "Tracing module: " << m_AnalysedApp << endl;
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

