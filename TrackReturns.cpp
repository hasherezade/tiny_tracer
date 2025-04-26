#include "TrackReturns.h"

#include "TinyTracer.h"
#include "ModuleInfo.h"

#define MEM_SNAPSHOT_SIZE 8

struct CallInfo
{
    uint64_t callNumber = 0;                        // Unique (incremented) identifier for each call (per thread)
    ADDRINT returnAddress = UNKNOWN_ADDR;           // Return address of the call
    std::string functionName;                       // Name of the API
    size_t argCount = 0;                            // Number of arguments
    std::vector<std::wstring> args;                 // Stored arguments values (result of paramToStr)
    std::vector<VOID*> argPointers;                 // Stored args pointers (empty if args is not a pointer)
    std::vector<std::vector<uint8_t>> argSnapshots; // Memory snapshots for arguments
    std::wstring returnValue;                       // Stored return value (ret of paramToStr)
    ADDRINT returnPtr = UNKNOWN_ADDR;               // Stored return Ptr if return value is ptr
    std::vector<uint8_t> returnSnapshot;            // Exists if return is ptr. Memory snapshot for return value
    std::vector<bool> argChangeLogged;              // Track whether changes were logged for each argument (track only one change)
    bool returnChangeLogged = false;                // Track whether return value change was logged (track only one change)
};

//---

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
            const THREADID tid = thread.first;
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
            const std::wstring wstr = ss.str();
            const std::string s(wstr.begin(), wstr.end());
            traceLog.logLine(s);
        }
    }
}; //struct FunctionTracker

//---

namespace RetTracker {

    FunctionTracker globalCallTracker;
    PIN_LOCK globalLock;
    static TLS_KEY tlsKey;

    VOID InitTracker()
    {
        // Create the TLS key 
        RetTracker::tlsKey = PIN_CreateThreadDataKey(NULL);
    }

    // Init the thread-local call map
    VOID InitTrackerForThread(THREADID tid)
    {
        const std::map<ADDRINT, CallInfo>* newMap = new std::map<ADDRINT, CallInfo>();
        PIN_SetThreadData(RetTracker::tlsKey, newMap, tid);
    }

    // Retrieve the thread-local call map
    std::map<ADDRINT, CallInfo>* GetCallMapForThread(const THREADID tid)
    {
        return static_cast<std::map<ADDRINT, CallInfo>*>(PIN_GetThreadData(RetTracker::tlsKey, tid));
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

            if (callInfo.argChangeLogged[i] || callInfo.argSnapshots[i].empty()) continue;

            // Should be always true because previous condition checks if argSnapshots is not empty
            // .ie a corresponding valid pointer exists as it is used to do the snapshot
            if (callInfo.argPointers[i] == nullptr) continue;

            if (!IsMemorySame((ADDRINT)callInfo.argPointers[i], callInfo.argSnapshots[i])) {
                ss << callInfo.functionName.c_str()
                    << L", Arg[" << i << L"] = " << std::hex << callInfo.argPointers[i] << L" changed:\n"
                    << L"\tOld: " << callInfo.args[i] << L"\n"
                    << L"\tNew: " << paramToStr(callInfo.argPointers[i])
                    << L"\n";
                callInfo.argChangeLogged[i] = true; // Mark as logged
            }
        }

        // Check return value changes : compare stored return pointer previous data to current
        if (!callInfo.returnChangeLogged && !callInfo.returnSnapshot.empty()
            && callInfo.returnPtr && callInfo.returnPtr != UNKNOWN_ADDR)
        {
            if (!IsMemorySame(callInfo.returnPtr, callInfo.returnSnapshot)) {
                ss << callInfo.functionName.c_str()
                    << L", Return Pointer: 0x" << std::hex << callInfo.returnPtr << L" changed:\n"
                    << L"\tOld: " << callInfo.returnValue << L"\n"
                    << L"\tNew: " << paramToStr(reinterpret_cast<void*>(callInfo.returnPtr))
                    << L"\n";
                callInfo.returnChangeLogged = true; // Mark as logged
            }
        }

        if (!ss.str().empty()) {
            std::wstring wstr = ss.str();
            std::string s(wstr.begin(), wstr.end());
            traceLog.logLine(s); // Log the changes
        }
    }
}; // namespace RetTracker

// Save args/return pointers and values of each call
// Log any change in logged args and return values
VOID RetTracker::LogCallDetails(const ADDRINT Address, const CHAR* name, uint32_t argCount,
    VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4,
    VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8,
    VOID* arg9, VOID* arg10, VOID* arg11)
{
    const THREADID tid = PIN_ThreadId();

    if (m_Settings.logReturn && m_Settings.followArgReturn) {
        // Check for changes in previous arg/returned pointers
        for (auto it = RetTracker::globalCallTracker.threadCalls.begin(); it != RetTracker::globalCallTracker.threadCalls.end(); ++it) {
            auto& calls = it->second;
            for (auto callIt = calls.begin(); callIt != calls.end(); ++callIt) {
                CheckAndLogChanges(*callIt);
            }
        }
    }

    // Retrieve the thread-local call map
    auto* callMap = GetCallMapForThread(tid);
    if (!callMap) return;

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

    // Store function call info in the thread map
    (*callMap)[Address] = info;

    // Add the call to the global log
    PIN_GetLock(&RetTracker::globalLock, tid);
    RetTracker::globalCallTracker.addCall(tid, info); // Increment the call counter and add the call
    PIN_ReleaseLock(&RetTracker::globalLock);
}

VOID RetTracker::CheckIfFunctionReturned(const THREADID tid, const ADDRINT ip, const ADDRINT retVal)
{
    auto* callMap = GetCallMapForThread(tid);
    if (!callMap) return;

    const auto it = callMap->find(ip);
    if (it == callMap->end()) return;

    CallInfo& info = it->second;

    std::wstringstream ss;
    ss << info.functionName.c_str() << L"\n";
    ss << L"\treturned: " << paramToStr(reinterpret_cast<VOID*>(retVal));
    ss << "\n";

    // Update the global call tracker
    PIN_GetLock(&RetTracker::globalLock, tid + 1); // Lock for thread safety
    auto& threadCalls = RetTracker::globalCallTracker.threadCalls[tid];
    for (auto& call : threadCalls) {
        if (call.returnAddress == info.returnAddress && call.functionName == info.functionName) {
            call.returnValue = paramToStr(reinterpret_cast<VOID*>(retVal)); // Update the return value
            info.returnValue = call.returnValue;

            // Snapshot the return value if the return is a ptr
            if (!call.returnValue.empty() && isValidReadPtr(reinterpret_cast<VOID*>(retVal))) {
                MakeMemorySnapshot(retVal, call.returnSnapshot, MEM_SNAPSHOT_SIZE);
                // Also store the pointer itself
                call.returnPtr = retVal;
            }
            break;
        }
    }
    PIN_ReleaseLock(&RetTracker::globalLock);

    callMap->erase(it);

    const std::wstring wstr = ss.str();
    const std::string s(wstr.begin(), wstr.end());
    traceLog.logLine(s);
}

VOID RetTracker::LogAllTrackedCalls()
{
    PIN_GetLock(&RetTracker::globalLock, 0);          // Acquire lock for thread safety
    RetTracker::globalCallTracker.logAll();              // Log all calls through traceLog
    PIN_ReleaseLock(&RetTracker::globalLock);         // Release lock
}

VOID RetTracker::SaveReturnValue(const THREADID tid, const ADDRINT address, const ADDRINT returnValue)
{
    PIN_GetLock(&RetTracker::globalLock, tid); // Lock for thread safety
    auto& threadCalls = RetTracker::globalCallTracker.threadCalls[tid];

    // Retrieve the corresponding syscall from globalCallTracker
    for (auto& call : threadCalls) {
        if (returnValue && returnValue != UNKNOWN_ADDR
            && address && address != UNKNOWN_ADDR
            && (call.returnAddress == address)
            )
        {
            std::wstringstream ss;
            call.returnValue = paramToStr(reinterpret_cast<VOID*>(returnValue)); // Update the return value
            ss << call.functionName.c_str() << L"\n";
            ss << L"\treturned: " << paramToStr(reinterpret_cast<VOID*>(returnValue));
            ss << "\n";

            // Snapshot the return value if the return is a ptr
            if (!call.returnValue.empty() && isValidReadPtr(reinterpret_cast<VOID*>(returnValue))) {
                MakeMemorySnapshot(returnValue, call.returnSnapshot, MEM_SNAPSHOT_SIZE);

                // Also store the pointer itself
                call.returnPtr = returnValue;
            }
            const std::wstring wstr = ss.str();
            const std::string s(wstr.begin(), wstr.end());
            traceLog.logLine(s);
            break;
        }
    }
    PIN_ReleaseLock(&RetTracker::globalLock);
}
