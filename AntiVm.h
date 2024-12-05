#pragma once

#include "pin.H"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */
namespace AntiVm {
	VOID MonitorAntiVmFunctions(IMG Image);
	VOID MonitorSyscallEntry(THREADID tid, const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address);
	VOID MonitorSyscallExit(THREADID tid, const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address);
	VOID InstrumentCPUIDCheck(INS ins);
};
