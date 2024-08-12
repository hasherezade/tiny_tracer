#pragma once

#include "pin.H"
#include "FuncWatch.h"
#include <map>

typedef enum {
    WATCH_DISABLED = 0,      // Evasion detection is disabled
    WATCH_STANDARD = 1,      // Track "standard" and easily identifiable techniques
    WATCH_DEEP = 2,          // Track more techniques, may lead to false positives
    WATCH_OPTIONS_COUNT
} t_watch_level;

inline t_watch_level ConvertWatchLevel(int value)
{
    if (value >= WATCH_OPTIONS_COUNT) {
        // choose the last option:
        return t_watch_level(WATCH_OPTIONS_COUNT - 1);
    }
    return (t_watch_level)value;
}

//---

struct FuncData
{
public:
    FuncData() : name(""), argsNum(0) { }

    FuncData(const std::string& _name, size_t _argsNum) : name(_name), argsNum(_argsNum)
    {
        ::memset(args, 0, sizeof(args));
    }

    FuncData(const FuncData& other)
    {
        name = other.name;
        argsNum = other.argsNum;
        ::memcpy(args, other.args, sizeof(args));
    }

    std::string name;
    size_t argsNum;
    VOID* args[5];
};

//---

typedef VOID EvasionWatchCallBack(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5);

struct EvasionFuncInfo : public WFuncInfo
{
    EvasionFuncInfo(const std::string& _dllName, const std::string& _funcName, const size_t _paramCount, EvasionWatchCallBack* _callbackB = nullptr, EvasionWatchCallBack* _callbackA = nullptr, t_watch_level _type = WATCH_STANDARD)
        : callbackBefore(_callbackB), callbackAfter(_callbackA), type(_type),
        WFuncInfo(_dllName, _funcName, _paramCount) 
    {
    }

    EvasionWatchCallBack* callbackBefore;
    EvasionWatchCallBack* callbackAfter;
    t_watch_level type;
};

//---

class EvasionWatch
{
public:
    static bool EvasionAddCallbackBefore(IMG Image, const char* fName, uint32_t argNum, EvasionWatchCallBack callback);

    EvasionWatch() : isInit(FALSE) { }

    virtual BOOL Init() = 0;
    EvasionFuncInfo* fetchFunctionInfo(const std::string& dllName, const std::string& funcName, t_watch_level maxLevel);
    EvasionFuncInfo* fetchSyscallFuncInfo(const std::string& funcName, t_watch_level maxLevel);

    size_t installCallbacksBefore(IMG Image, EvasionWatchCallBack defaultCallback, t_watch_level maxLevel);
    FuncList<EvasionFuncInfo> watchedFuncs;

protected:
    BOOL isInit;
};
