#include "TrackReturns.h"

#include "TinyTracer.h"

/* ===================================================================== */
// Utilities for tracking API/system calls and returns 
/* ===================================================================== */

struct FunctionTracker
{
    std::map<THREADID, std::vector<CallInfo>> threadCalls;  // Stores all calls grouped by thread
    std::map<THREADID, uint64_t> threadCallCounts;          // Per-thread sequential call counters

    // Add a function call for global tracking per thread
    void addCall(THREADID tid, CallInfo& callInfo) 
    {
        if (threadCallCounts.find(tid) == threadCallCounts.end()) {
            threadCallCounts[tid] = 0; // Initialize the counter for this thread
        }

        // Assign a sequential call number
        callInfo.callNumber = threadCallCounts[tid]++;

        // Initialize argChangeLogged
        callInfo.argChangeLogged.resize(callInfo.argCount, false); // Initialize all values to `false`

        // Add the function call to the thread list
        threadCalls[tid].push_back(callInfo);
    }

    // Log all stored function calls and their details
    void logAll() const
   {
        for (const auto& thread : threadCalls) {
            THREADID tid = thread.first;
            const auto& calls = thread.second;

            std::wstringstream ss;
            ss << L" " << L"\n";
            ss << L"Display the call tracker struct for debugging purpose\n";
            ss << L"Thread ID: " << tid << L"\n";
            for (const auto& call : calls) {
                ss << L"  Call #" << call.callNumber << L", Function: " << call.functionName.c_str() << L"\n";
                ss << L"    Return Address: 0x" << std::hex << call.returnAddress << std::dec << L"\n";
                ss << L"    Arguments (" << call.argCount << L"):\n";

                for (size_t i = 0; i < call.args.size(); ++i) {
                    ss << L"      Arg[" << i << L"]: " << call.args[i] << L"\n";
                }

                if (!call.returnValue.empty()) {
                    ss << L"    Return Value: " << call.returnValue << L"\n";
                }

                ss << L"  -----\n";
            }

            // Convert to string and log
            std::wstring wstr = ss.str();
            std::string s(wstr.begin(), wstr.end());
            traceLog.logLine(s);
        }
    }
}; //struct FunctionTracker

//---

FunctionTracker globalCallTracker;
PIN_LOCK globalLock;
static TLS_KEY tlsKey;

VOID InitTracker()
{
    // Create the TLS key 
    tlsKey = PIN_CreateThreadDataKey(NULL);
}

VOID InitTrackerForThread(THREADID tid)
{
    std::map<ADDRINT, CallInfo>* newMap = new std::map<ADDRINT, CallInfo>();
    PIN_SetThreadData(tlsKey, newMap, tid);
}

void CheckAndLogChanges(CallInfo& callInfo)
{
    std::wstringstream ss;

    // Check argument changes
    for (size_t i = 0; i < callInfo.argCount; i++) {

        if (callInfo.argChangeLogged[i] || callInfo.argSnapshots[i].empty()) continue;

        // Should be always true because previous condition checks if argSnapshots is not empty
        // .ie a corresponding valid pointer exists as it is used to do the snapshot
        if (callInfo.argPointers[i] == nullptr) continue;

        const uint8_t* currentData = reinterpret_cast<const uint8_t*>(callInfo.argPointers[i]);

        // Compare the current memory with the stored snapshot
        if (memcmp(currentData, &callInfo.argSnapshots[i][0], callInfo.argSnapshots[i].size()) != 0) {
            ss << callInfo.functionName.c_str()
                << L", Arg[" << i << L"] Pointer: " << callInfo.argPointers[i] << L" changed:\n"
                << L"\tOld: {" << callInfo.args[i] << L"}\n"
                << L"\tNew: {" << paramToStr(callInfo.argPointers[i]) << L"}\n";
            callInfo.argChangeLogged[i] = true; // Mark as logged
        }
    }

    // Check return value changes : compare stored return pointer previous data to current
    if (!callInfo.returnChangeLogged && !callInfo.returnSnapshot.empty()) {
        const uint8_t* currentData = reinterpret_cast<const uint8_t*>(callInfo.returnPtr);
        if (memcmp(currentData, &callInfo.returnSnapshot[0], callInfo.returnSnapshot.size()) != 0) {
            ss << callInfo.functionName.c_str()
                << L", Return Pointer: 0x" << std::hex << callInfo.returnPtr << L" changed:\n"
                << L"\tOld: {" << callInfo.returnValue << L"}\n"
                << L"\tNew: {" << paramToStr(reinterpret_cast<void*>(callInfo.returnPtr)) << L"}\n";

            callInfo.returnChangeLogged = true; // Mark as logged
        }
    }

    if (!ss.str().empty()) {
        std::wstring wstr = ss.str();
        std::string s(wstr.begin(), wstr.end());
        traceLog.logLine(s); // Log the changes
    }
}

// Save args/return pointers and values of each call
// Log any change in logged args and return values
VOID LogCallDetails(const ADDRINT Address, CHAR* name, uint32_t argCount,
    VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
    VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
    VOID* arg9, VOID* arg10, VOID* arg11)
{
    THREADID tid = PIN_ThreadId();

    if (m_Settings.logReturn && m_Settings.followArgReturn) {
        // Check for changes in previous arg/returned pointers
        for (auto it = globalCallTracker.threadCalls.begin(); it != globalCallTracker.threadCalls.end(); ++it) {
            THREADID tid = it->first;
            auto& calls = it->second;
            for (auto callIt = calls.begin(); callIt != calls.end(); ++callIt) {
                CheckAndLogChanges(*callIt);
            }
        }
    }

    // Retrieve the thread-local call map
    auto* callMap = static_cast<std::map<ADDRINT, CallInfo>*>(PIN_GetThreadData(tlsKey, tid));

    // Initialize CallInfo
    CallInfo info;
    info.returnAddress = Address;
    info.functionName = name;
    info.argCount = argCount;

    // Prepare arguments to log their value (paramToStr result)
    VOID* args[] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11 };

    for (size_t i = 0; i < argCount; i++) {
        info.args.push_back(paramToStr(args[i]));   // Convert and store arguments

        // Take memory snapshot for pointers
        if (isValidReadPtr(args[i])) {
            info.argPointers.push_back(args[i]);    // Store the raw address

            size_t size = 16;                       // Change the size if needed
            std::vector<uint8_t> snapshot(size);
            memcpy(&snapshot[0], args[i], size);    // Copy memory contents into the snapshot
            info.argSnapshots.push_back(snapshot);  // Add the snapshot to the vector
        }
        else {
            info.argSnapshots.push_back(std::vector<uint8_t>()); // Push an empty vector for non-pointers
            info.argPointers.push_back(nullptr); // Push empty vector
        }
    }

    // Store function call info in the thread map
    (*callMap)[Address] = info;

    // Add the call to the global log
    PIN_GetLock(&globalLock, tid);
    globalCallTracker.addCall(tid, info); // Increment the call counter and add the call
    PIN_ReleaseLock(&globalLock);
}

VOID CheckIfFunctionReturned(const THREADID tid, const ADDRINT ip, const ADDRINT retVal)
{
    auto* callMap = static_cast<std::map<ADDRINT, CallInfo>*>(PIN_GetThreadData(tlsKey, tid));

    auto it = callMap->find(ip);
    if (it != callMap->end()) {
        std::wstringstream ss;

        CallInfo& info = it->second;

        ss << info.functionName.c_str() << L"\n";
        ss << L"\treturned: " << paramToStr(reinterpret_cast<VOID*>(retVal));
        ss << "\n";

        // Update the global call tracker
        PIN_GetLock(&globalLock, tid + 1); // Lock for thread safety
        auto& threadCalls = globalCallTracker.threadCalls[tid];
        for (auto& call : threadCalls) {
            if (call.returnAddress == info.returnAddress && call.functionName == info.functionName) {
                call.returnValue = paramToStr(reinterpret_cast<VOID*>(retVal)); // Update the return value
                info.returnValue = paramToStr(reinterpret_cast<VOID*>(retVal));

                // Snapshot the return value if the return is a ptr
                if (!call.returnValue.empty() && isValidReadPtr(reinterpret_cast<VOID*>(retVal))) {
                    size_t size = 16; // Change if needed
                    call.returnSnapshot.resize(size);
                    memcpy(&call.returnSnapshot[0], reinterpret_cast<VOID*>(retVal), size); // Copy memory content into the snapshot

                    // Also store the pointer itself
                    call.returnPtr = retVal;
                }
                break;
            }
        }

        PIN_ReleaseLock(&globalLock);

        callMap->erase(it);
        std::wstring wstr = ss.str();
        std::string s(wstr.begin(), wstr.end());
        traceLog.logLine(s);
    }
}

VOID LogAllTrackedCalls()
{
    PIN_GetLock(&globalLock, 0);          // Acquire lock for thread safety
    globalCallTracker.logAll();              // Log all calls through traceLog
    PIN_ReleaseLock(&globalLock);         // Release lock
}


VOID SaveReturnValue(const THREADID tid, const ADDRINT address, const ADDRINT returnValue)
{
    PIN_GetLock(&globalLock, tid); // Lock for thread safety
    auto& threadCalls = globalCallTracker.threadCalls[tid];

    // Retrieve the corresponding syscall from globalCallTracker
    for (auto& call : threadCalls) {
        if (call.returnAddress == address) {
            std::wstringstream ss;
            call.returnValue = paramToStr(reinterpret_cast<VOID*>(returnValue));; // Update the return value
            ss << call.functionName.c_str() << L"\n";
            ss << L"\treturned: " << paramToStr(reinterpret_cast<VOID*>(returnValue));
            ss << "\n";

            // Snapshot the return value if the return is a ptr
            if (!call.returnValue.empty() && isValidReadPtr(reinterpret_cast<VOID*>(returnValue))) {
                size_t size = 16; // Example size, adjust as needed
                call.returnSnapshot.resize(size); // Resize the vector to hold the snapshot
                memcpy(&call.returnSnapshot[0], reinterpret_cast<VOID*>(returnValue), size); // Copy memory content into the snapshot

                // Also store the pointer itself
                call.returnPtr = returnValue;
            }
            std::wstring wstr = ss.str();
            std::string s(wstr.begin(), wstr.end());
            traceLog.logLine(s);
            break;
        }
    }
    PIN_ReleaseLock(&globalLock);
}
