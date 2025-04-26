#pragma once
#include "pin.H"

/* ===================================================================== */
// Utilities for tracking API/system calls and returns 
/* ===================================================================== */

namespace RetTracker
{
    VOID InitTracker();

    VOID InitTrackerForThread(THREADID tid);

    VOID LogCallDetails(const ADDRINT Address, const CHAR* name, uint32_t argCount,
        VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
        VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
        VOID* arg9, VOID* arg10, VOID* arg11
    );

    VOID CheckIfFunctionReturned(const THREADID tid, const ADDRINT ip, const ADDRINT retVal);

    VOID LogAllTrackedCalls();

    VOID SaveReturnValue(const THREADID tid, const ADDRINT address, const ADDRINT returnValue);
};
