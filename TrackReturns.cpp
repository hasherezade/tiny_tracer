#include "TrackReturns.h"
#include "Settings.h"
#include "TinyTracer.h"
#include "ModuleInfo.h"

#include <string>
#include <vector>
#include <stack>
#include <iostream>

#define MEM_SNAPSHOT_SIZE 8

struct CallInfo
{
    ADDRINT returnAddress = UNKNOWN_ADDR;           // Return addr of the call / Addr of syscall 
    std::string functionName;                       // Name of the API
    size_t argCount = 0;                            // Number of arguments
    std::vector<std::wstring> args;                 // Stored arguments values (result of paramToStr)
    std::vector<VOID*> argPointers;                 // Stored args pointers (empty if args is not a pointer)
    std::vector<std::vector<uint8_t>> argSnapshots; // Memory snapshots for arguments
    std::wstring returnValue;                       // Stored return value (ret of paramToStr)
    ADDRINT returnPtr = UNKNOWN_ADDR;               // Stored return Ptr if return value is ptr
};

struct CallStack
{
public:
    std::stack<CallInfo> callStack;
};

static void deleteCallstack(void* arg) noexcept
{
    auto* threadStack = static_cast<CallStack*>(arg);
    delete threadStack;
}

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
//---

namespace RetTracker {

    static TLS_KEY tlsKey = static_cast<TLS_KEY>(-1); // INVALID by convention

    VOID InitTracker()
    {
        // Create the TLS key 
        RetTracker::tlsKey = PIN_CreateThreadDataKey(deleteCallstack);
        if (tlsKey == static_cast<TLS_KEY>(-1)) {
            // handle error -> you’ve exhausted TLS keys
            std::cerr << "Exhausted TLS keys!\n";
            PIN_ExitProcess(1);
        }
    }

    // Init the thread-local call stack
    VOID InitTrackerForThread(THREADID tid)
    {
        const CallStack* newStack = new CallStack();
        PIN_SetThreadData(RetTracker::tlsKey, newStack, tid);
    }

    // Retrieve the thread-local call stack
    CallStack* GetCallStackForThread(const THREADID tid)
    {
        return static_cast<CallStack*>(PIN_GetThreadData(RetTracker::tlsKey, tid));
    }

    // Copy memory content into the snapshot
    bool MakeMemorySnapshot(const ADDRINT addr, std::vector<uint8_t>& vec, const size_t size)
    {
        if (!addr || addr == UNKNOWN_ADDR || !size) return false;
        vec.clear();

        uint8_t* inPtr = (uint8_t*)addr;
        const size_t maxSize = getReadableMemSize(inPtr);
        if (!maxSize) return false;

        size_t snapSize = (maxSize > size) ? size : maxSize;
        vec.resize(snapSize);
        uint8_t* outPtr = (uint8_t*)&vec[0];
        size_t res = PIN_SafeCopy(outPtr, inPtr, snapSize);
        if (res != snapSize) {
            vec.resize(res);
        }
        return res ? true : false;
    }

    // Compare the current memory with the stored snapshot
    bool IsMemorySame(const ADDRINT addr, const std::vector<uint8_t>& snapshot)
    {
        if (!addr || addr == UNKNOWN_ADDR) {
            if (snapshot.empty()) return true;
            return false;
        }
        const size_t snapSize = snapshot.size();
        std::vector<uint8_t> snap2;
        if (!MakeMemorySnapshot(addr, snap2, snapshot.size())) {
            return false;
        }
        if (snap2.size() != snapSize) {
            return false;
        }
        for (size_t i = 0; i < snapSize; i++) {
            if (snap2.at(i) != snapshot.at(i)) {
                return false;
            }
        }
        return true;
    }

    void CheckAndLogChanges(CallInfo& callInfo)
    {
        std::wstringstream ss;
        ss << callInfo.functionName.c_str() << " changed:\n";
        // Check argument changes
        bool isChanged = false;
        for (size_t i = 0; i < callInfo.argCount; i++) {

            if (callInfo.argSnapshots[i].empty()) continue;

            // Should be always true because previous condition checks if argSnapshots is not empty
            // .ie a corresponding valid pointer exists as it is used to do the snapshot
            if (callInfo.argPointers[i] == nullptr) continue;

            if (!IsMemorySame((ADDRINT)callInfo.argPointers[i], callInfo.argSnapshots[i])) {
                isChanged = true;
                ss  << L"\tArg[" << i << L"] = " << paramToStr(callInfo.argPointers[i]) << L"\n";
            }
        }
        if (isChanged) {
            LogBuffer(ss);
        }  
    }
}; // namespace RetTracker

VOID RetTracker::LogCallDetails(const ADDRINT Address, const CHAR* name, uint32_t argCount,
    VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
    VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
    VOID* arg9, VOID* arg10, VOID* arg11)
{
    const THREADID tid = PIN_ThreadId();

    // Retrieve the thread-local call stack
    auto* c = GetCallStackForThread(tid);
    if (!c) return;

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
    c->callStack.push(info);
}

VOID RetTracker::HandleFunctionReturn(const THREADID tid, const ADDRINT returnIp, const ADDRINT rawRetVal) 
{
    auto* c = GetCallStackForThread(tid);
    if (!c || c->callStack.empty()) return;

    CallInfo& topCall = c->callStack.top();
    if (topCall.returnAddress != returnIp) return;

    // Copy before popping so we can log after
    CallInfo info = topCall;
    c->callStack.pop();

    std::wstring retStr = paramToStr(reinterpret_cast<VOID*>(rawRetVal));
    info.returnValue = retStr;
    info.returnPtr   = rawRetVal;

    std::wstringstream ss;
    ss << info.functionName.c_str() << L" returned:\n";
    ss << L"\t" << retStr << L"\n";

    if (m_Settings.followArgReturn) {
        RetTracker::CheckAndLogChanges(info);
    }
    LogBuffer(ss);
}
