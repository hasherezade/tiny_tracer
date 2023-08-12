#pragma once

#include "pin.H"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */
namespace AntiDbg {
	VOID WatchMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr);
	VOID WatchThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v);
	VOID MonitorAntiDbgFunctions(IMG Image);
	VOID FlagsCheck(const CONTEXT* ctxt);
	VOID InterruptCheck(const CONTEXT* ctxt);
};
