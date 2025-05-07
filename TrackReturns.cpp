#include "TrackReturns.h"

#include "TinyTracer.h"
#include "ModuleInfo.h"
#include <stack>

#define MEM_SNAPSHOT_SIZE 8

struct CallInfo
{
    ADDRINT returnAddress = UNKNOWN_ADDR;           // Return address of the call
    std::string functionName;                       // Name of the API
    size_t argCount = 0;                            // Number of arguments
    std::vector<std::wstring> args;                 // Stored arguments values (result of paramToStr)
    std::vector<VOID*> argPointers;                 // Stored args pointers (empty if args is not a pointer)
    std::vector<std::vector<uint8_t>> argSnapshots; // Memory snapshots for arguments
    std::wstring returnValue;                       // Stored return value (ret of paramToStr)
    ADDRINT returnPtr = UNKNOWN_ADDR;               // Stored return Ptr if return value is ptr
};

//---

// Convert to string and log
void LogBuffer(const std::wstringstream& ss)
{
    if (!ss.str().empty()) {
        const std::wstring wstr = ss.str();
        const std::string s(wstr.begin(), wstr.end());
        traceLog.logLine(s);
    }
}

struct FunctionTracker
{
    std::map<THREADID, std::vector<CallInfo>> threadCalls;  // Stores all calls grouped by thread
    std::map<THREADID, uint64_t> threadCallCounts;          // Per-thread sequential call counters

}; //struct FunctionTracker

//---

namespace RetTracker {

    PIN_LOCK globalLock;
    static TLS_KEY tlsKey;

    VOID InitTracker()
    {
        // Create the TLS key 
        RetTracker::tlsKey = PIN_CreateThreadDataKey(NULL);
    }

    // Init the thread-local call stack
    VOID InitTrackerForThread(THREADID tid)
    {
        const std::stack<CallInfo>* newStack = new std::stack<CallInfo>();
        PIN_SetThreadData(RetTracker::tlsKey, newStack, tid);
    }

    // Retrieve the thread-local call stack
    std::stack<CallInfo>* GetCallStackForThread(const THREADID tid)
    {
        return static_cast<std::stack<CallInfo>*>(PIN_GetThreadData(RetTracker::tlsKey, tid));
    }

    // Copy memory content into the snapshot
    bool MakeMemorySnapshot(const ADDRINT addr, std::vector<uint8_t>& vec, const size_t size)
    {
        if (!addr || addr == UNKNOWN_ADDR) return false;

        vec.clear();
        uint8_t* ptr = (uint8_t*)addr;
        for (size_t i = 0; i < size; i++) {
            uint8_t* cPtr = ptr + i;
            if (!isValidReadPtr(cPtr)) break;
            vec.push_back(*cPtr);
        }
        return vec.size() ? true : false;
    }

    // Compare the current memory with the stored snapshot
    bool IsMemorySame(const ADDRINT addr, const std::vector<uint8_t>& snapshot)
    {
        if (!addr || addr == UNKNOWN_ADDR) {
            if (snapshot.empty()) return true;
            return false;
        }
        uint8_t* ptr = (uint8_t*)addr;
        for (size_t i = 0; i < snapshot.size(); i++) {
            uint8_t* cPtr = ptr + i;
            if (!isValidReadPtr(cPtr)) {
                return false;
            }
            if (snapshot.at(i) != (*cPtr)) {
                return false;
            }
        }
        return true;
    }

    void CheckAndLogChanges(CallInfo& callInfo)
    {
        std::wstringstream ss;

        // Check argument changes
        for (size_t i = 0; i < callInfo.argCount; i++) {

            if (callInfo.argSnapshots[i].empty()) continue;

            // Should be always true because previous condition checks if argSnapshots is not empty
            // .ie a corresponding valid pointer exists as it is used to do the snapshot
            if (callInfo.argPointers[i] == nullptr) continue;

            if (!IsMemorySame((ADDRINT)callInfo.argPointers[i], callInfo.argSnapshots[i])) {
                ss << callInfo.functionName.c_str()
                    << L", Arg[" << i << L"] = " << std::hex << callInfo.argPointers[i] << L" changed:\n"
                    << L"\tOld: " << callInfo.args[i] << L"\n"
                    << L"\tNew: " << paramToStr(callInfo.argPointers[i])
                    << L"\n";
            }
        }
        LogBuffer(ss);
    }
}; // namespace RetTracker

// Log any change in logged args
VOID RetTracker::LogCallDetails(const ADDRINT Address, const CHAR* name, uint32_t argCount,
    VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
    VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
    VOID* arg9, VOID* arg10, VOID* arg11)
{
    const THREADID tid = PIN_ThreadId();

    // Retrieve the thread-local call stack
    auto* callStack = GetCallStackForThread(tid);
    if (!callStack) return;

    // Initialize CallInfo
    CallInfo info;
    info.returnAddress = Address;
    info.argCount = argCount;
    info.functionName = name ? name : "?";

    // Prepare arguments to log their value (paramToStr result)
    VOID* args[] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11 };

    for (size_t i = 0; i < argCount; i++) {
        info.args.push_back(paramToStr(args[i]));   // Convert and store arguments

        // Take memory snapshot for pointers
        if (isValidReadPtr(args[i])) {
            info.argPointers.push_back(args[i]);    // Store the raw address

            std::vector<uint8_t> snapshot;
            MakeMemorySnapshot((ADDRINT)args[i], snapshot, MEM_SNAPSHOT_SIZE);
            info.argSnapshots.push_back(snapshot);  // Add the snapshot to the vector
        }
        else {
            info.argSnapshots.push_back(std::vector<uint8_t>()); // Push an empty vector for non-pointers
            info.argPointers.push_back(nullptr); // Push empty vector
        }
    }

    // Store function call info in call stack
    callStack->push(info);
}

VOID RetTracker::CheckIfFunctionReturned(const THREADID tid, const ADDRINT ip, const ADDRINT retVal)
{
    auto* callStack = GetCallStackForThread(tid);
    if (!callStack || callStack->empty()) return;

    CallInfo& topCall = callStack->top();

    // Only proceed if the IP matches the expected return address
    if (topCall.returnAddress != ip) return;

    CallInfo info = topCall;
    callStack->pop();

    std::wstring retStr = paramToStr(reinterpret_cast<VOID*>(retVal));

    std::wstringstream ss;
    ss << info.functionName.c_str() << L"\n";
    ss << L"\treturned: " << retStr << L"\n";

    // Check and log changes to arguments and return memory
    RetTracker::CheckAndLogChanges(info);

    LogBuffer(ss);
}

VOID RetTracker::SaveReturnValue(const THREADID tid, const ADDRINT address, const ADDRINT returnValue)
{
    auto* callStack = GetCallStackForThread(tid);
    if (!callStack || callStack->empty()) return;

    CallInfo& topCall = callStack->top();

    // Validate the return address matches what we expect
    if (topCall.returnAddress != address) return;

    std::wstringstream ss;
    topCall.returnValue = paramToStr(reinterpret_cast<VOID*>(returnValue));
    ss << topCall.functionName.c_str() << L"\n";
    ss << L"\treturned: " << topCall.returnValue << L"\n";


    LogBuffer(ss);
}
