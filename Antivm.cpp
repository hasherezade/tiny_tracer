#include "AntiVm.h"

#include <iostream>
#include <sstream>
#include <string>
#include <map>

#include "Util.h"

#include "win/win_paths.h"

#define ANTIVM_LABEL "[ANTIVM] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiVm
/* ================================================================== */

typedef VOID AntiVmCallBack(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5);

/* ==================================================================== */
// Process API calls (related to AntiVm techniques)
/* ==================================================================== */


VOID AntiVm_WmiQueries(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* junk, VOID* query, VOID* flags, VOID* var, VOID* type)
{
    if (!argCount) return;
}

/* ==================================================================== */
// Add single hooking function
/* ==================================================================== */

bool AntiVmAddCallbackBefore(IMG Image, char* fName, uint32_t argNum, AntiVmCallBack callback)
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
// Add to monitored functions all the API calls or WMI queries needed for AntiVM.
// Called by ImageLoad
/* ==================================================================== */

VOID AntiVm::MonitorAntiVmFunctions(IMG Image)
{
	// API needed to trace WMI queries
	const std::string dllName = util::getDllName(IMG_Name(Image));
	if (util::iequals(dllName, "fastprox")) {
		AntiVmAddCallbackBefore(Image, "?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z", 0, AntiVm_WmiQueries);
	}
}