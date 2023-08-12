#pragma once

#include "pin.H"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */

VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr);
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v);
VOID AntidebugMonitorFunctions(IMG Image);
VOID FlagsCheck(const CONTEXT* ctxt);
