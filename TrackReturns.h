#pragma once
#include "pin.H"

struct CallInfo
{
    uint64_t callNumber = 0;                            // Unique (incremented) identifier for each call (per thread)
    ADDRINT returnAddress;                          // Return address of the call
    std::string functionName;                       // Name of the API
    uint32_t argCount;                              // Number of arguments
    std::vector<std::wstring> args;                 // Stored arguments values (result of paramToStr)
    std::vector<VOID*> argPointers;                 // Stored args pointers (empty if args is not a pointer)
    std::vector<std::vector<uint8_t>> argSnapshots; // Memory snapshots for arguments
    std::wstring returnValue;                       // Stored return value (ret of paramToStr)
    ADDRINT returnPtr;                              // Stored return Ptr if return value is ptr
    std::vector<uint8_t> returnSnapshot;            // Exists if return is ptr. Memory snapshot for return value
    std::vector<bool> argChangeLogged;              // Track whether changes were logged for each argument (track only one change)
    bool returnChangeLogged = false;                // Track whether return value change was logged (track only one change)
};

void CheckAndLogChanges(CallInfo& callInfo);

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v);

VOID InitTracker();

VOID InitTrackerForThread(THREADID tid);

VOID LogCallDetails(const ADDRINT Address, CHAR* name, uint32_t argCount,
    VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
    VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
    VOID* arg9, VOID* arg10, VOID* arg11);

VOID CheckIfFunctionReturned(const THREADID tid, const ADDRINT ip, const ADDRINT retVal);

VOID LogAllTrackedCalls();

VOID SaveReturnValue(const THREADID tid, const ADDRINT address, const ADDRINT returnValue);
