#include "AntiDebug.h"

#include <iostream>
#include <sstream>
#include <string>
#include <map>

#include "win/win_paths.h"

#define ANTIVM_LABEL "[ANTIVM] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiVm
/* ================================================================== */

/* ==================================================================== */
// Add to monitored functions all the API calls or WMI queries needed for AntiVM.
// Called by ImageLoad
/* ==================================================================== */

VOID AntiDbg::MonitorAntiDbgFunctions(IMG Image)
{
}