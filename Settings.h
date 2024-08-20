#pragma once

#include <iostream>
#include <string>
#include <map>
#include <set>

#include "FuncWatch.h"
#include "EvasionWatch.h"

typedef enum {
    SHELLC_DO_NOT_FOLLOW = 0,    // trace only the main target module
    SHELLC_FOLLOW_FIRST = 1,     // follow only the first shellcode called from the main module
    SHELLC_FOLLOW_RECURSIVE = 2, // follow also the shellcodes called recursively from the the original shellcode
    SHELLC_FOLLOW_ANY = 3, // follow any shellcodes
    SHELLC_OPTIONS_COUNT
} t_shellc_options;

t_shellc_options ConvertShcOption(int value);

//---

class SyscallsTable {
public:
    
    static std::string convertNameToNt(std::string funcName)
    {
        std::string prefix1("Nt");
        std::string prefix2("Zw");
        if (!funcName.compare(0, prefix2.size(), prefix2)) {
            funcName.replace(0, 2, prefix1); // replace with Zw prefix
        }
        return funcName;
    }

    size_t load(const std::string& file);
    std::string getName(int syscallID);
    size_t count() { return syscallToFuncName.size(); }

protected:
    std::map<int, std::string> syscallToFuncName;
};

//---

struct StopOffset
{
    ADDRINT rva;
    size_t times;

    StopOffset(ADDRINT _rva = 0, size_t _times = 0)
        : rva(_rva), times(_times)
    {
    }

    StopOffset(const StopOffset& other)
    {
        this->rva = other.rva;
        this->times = other.times;
    }

    StopOffset& operator=(const StopOffset& other)
    {
        this->rva = other.rva;
        this->times = other.times;
    }

    bool load(const std::string& sline, char delimiter);

    bool operator<(const StopOffset& other) const
    {
        return (this->rva < other.rva);
    }
};
//---

class Settings {

public:
    static void stripComments(std::string& str);
    static size_t loadOffsetsList(const char* filename, std::set<StopOffset>& offsetsList);

    Settings() 
        : followShellcode(SHELLC_FOLLOW_FIRST),
        traceRDTSC(false),
        traceINT(false),
        traceSYSCALL(true),
        logSectTrans(true),
        logShelcTrans(true),
        shortLogging(true),
        logIndirect(false),
        hexdumpSize(8),
        antidebug(WATCH_DISABLED),
        antivm(WATCH_DISABLED),
        useDebugSym(false),
        isHyperVSet(false),
        stopOffsetTime(30)
    {
    }

    bool loadINI(const std::string &filename);
    bool saveINI(const std::string &filename);

    t_shellc_options followShellcode;

    bool traceRDTSC; // Trace RDTSC
    bool traceINT; // trace INT
    bool traceSYSCALL; // Trace syscall instructions (i.e., syscall, int 2Eh, sysenter)
    bool logSectTrans; // watch transitions between sections
    bool logShelcTrans; // watch transitions between shellcodes
    bool shortLogging; // Use short call logging (without a full DLL path)
    bool logIndirect;
    size_t hexdumpSize;
    bool hookSleep;
    size_t sleepTime; // Define the time that will be passed to the hooked sleep function (in miliseconds)
    size_t stopOffsetTime; // Sleep time at the stop offset (in seconds)
    t_watch_level antidebug;
    t_watch_level antivm; // Trace Anti-VM techniques (WMI queries)
    bool useDebugSym;
    bool isHyperVSet;

    SyscallsTable syscallsTable; //Syscalls table: mapping the syscall ID to the function name
    FuncWatchList funcWatch; //List of functions, arguments of which are going to be logged
    FuncList<WFuncInfo> excludedFuncs; //List of functions that will NOT be logged
    std::set<StopOffset> stopOffsets; //List of offsets at which the execution should pause
};
