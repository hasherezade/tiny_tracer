#pragma once

#include <iostream>

typedef enum {
    SHELLC_DO_NOT_FOLLOW = 0,    // trace only the main target module
    SHELLC_FOLLOW_FIRST = 1,     // follow only the first shellcode called from the main module
    SHELLC_FOLLOW_RECURSIVE = 2, // follow also the shellcodes called recursively from the the original shellcode
    SHELLC_FOLLOW_ANY = 3, // follow any shellcodes
    SHELLC_OPTIONS_COUNT
} t_shellc_options;

class Settings {

public:
    Settings() 
        : followShellcode(SHELLC_DO_NOT_FOLLOW),
        traceRDTSC(false),
        logSectTrans(true),
        logShelcTrans(true)
    {
    }

    t_shellc_options followShellcode;

    bool traceRDTSC;
    bool logSectTrans; // watch transitions between sections
    bool logShelcTrans; // watch transitions between shellcodes

};
