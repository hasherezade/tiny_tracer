#pragma once

#include "pin.H"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */
namespace AntiDbg {
	VOID WatchMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr);
	VOID WatchThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v);
	VOID WatchCompareSoftBrk(ADDRINT Address, UINT64 immVal);
	VOID MonitorAntiDbgFunctions(IMG Image);
	VOID MonitorSyscallEntry(const THREADID tid, const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address);
	VOID InterruptCheck(const CONTEXT* ctxt);
	VOID InstrumentFlagsCheck(INS ins);
};
