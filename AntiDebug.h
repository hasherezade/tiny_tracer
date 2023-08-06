#pragma once

#include "pin.H"
#include "FuncWatch.h"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */

VOID AntidebugProcessFunctions(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10);
VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr);
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v);
VOID AntidebugMonitorFunctions(IMG Image, FuncWatchList funcWatch);
