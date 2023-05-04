#pragma once

#include <iostream>
#include <string>
#include <map>

#include "FuncWatch.h"

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

class Settings {

public:
    Settings() 
        : followShellcode(SHELLC_FOLLOW_FIRST),
        traceRDTSC(false),
        traceSYSCALL(true),
        logSectTrans(true),
        logShelcTrans(true),
        shortLogging(true),
        logIndirect(false),
        hexdumpSize(8)
    {
    }

    bool loadINI(const std::string &filename);
    bool saveINI(const std::string &filename);

    t_shellc_options followShellcode;

    bool traceRDTSC; // Trace RDTSC
    bool traceSYSCALL; // Trace syscall instructions (i.e., syscall, int 2Eh, sysenter)
    bool logSectTrans; // watch transitions between sections
    bool logShelcTrans; // watch transitions between shellcodes
    bool shortLogging; // Use short call logging (without a full DLL path)
    bool logIndirect;
    size_t hexdumpSize;
    bool hookSleep;
    size_t sleepTime;

    SyscallsTable syscallsTable; //Syscalls table: mapping the syscall ID to the function name
    FuncWatchList funcWatch; //List of functions, arguments of which are going to be logged
};
