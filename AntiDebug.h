#pragma once

#include <iostream>

#include "FuncWatch.h"

//* ==================================================================== */
// Prototypes
/* ===================================================================== */

BOOL IsNativeOs32(void);
VOID AntidebugProcessFunctions(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10);
VOID AntidebugMemoryAccess(ADDRINT addr, UINT32 size, const ADDRINT insAddr);
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v);
std::wstring paramToStrSplit(VOID* arg1);
VOID AntidebugCloseHandle(ADDRINT Address, ADDRINT regGAX);
bool AntidebugMonitorAdd(IMG Image, char* fName, uint32_t argNum, const std::string& dllName, FuncWatchList funcWatch);
VOID AntidebugMonitorFunctions(IMG Image, FuncWatchList funcWatch);

//* ==================================================================== */
// Windows Constants. Not always defined in standard Headers
/* ===================================================================== */

// _PROCESSINFOCLASS
#define PROCESSDEBUGPORT			0x7
#define PROCESSDEBUGFLAGS			0x1f
#define PROCESSDEBUGOBJECTHANDLE 	0x1e

// _SYSTEM_INFORMATION_CLASS
#define SYSTEMKERNELDEBUGGERINFORMATION		0x23

// _OBJECT_INFORMATION_CLASS
#define OBJECTTYPESINFORMATION		0x3

// RaiseException constants
#define DBG_CONTROL_C				0x40010005
#define DBG_RIPEVENT				0x40010007