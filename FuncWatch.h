#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>

const size_t g_WatchedMax = 300;

class WFuncInfo 
{
public:
    WFuncInfo() : paramCount(0), watchBefore(false), watchAfter(false)
    {
    }

    WFuncInfo(const WFuncInfo& a)
    {
        this->dllName = a.dllName;
        this->funcName = a.funcName;
        this->paramCount = a.paramCount;
        this->watchAfter = a.watchAfter;
        this->watchBefore = a.watchBefore;
    }

    bool load(const std::string &line, char delimiter, bool watchBefore, bool watchAfter);

    bool update(const WFuncInfo &func_info);

    bool isValid() const
    {
        if (dllName.length() > 0 && funcName.length() > 0
            && (watchBefore || watchAfter))
        {
            return true;
        }
        return false;
    }

    std::string dllName;
    std::string funcName;
    size_t paramCount;
    bool watchBefore;
    bool watchAfter;
};

class FuncWatchList {
public:
    FuncWatchList()
        : funcs(0), funcsCount(NULL)
    {
        funcs = new WFuncInfo[g_WatchedMax];
    }

    ~FuncWatchList()
    {
        funcs = 0;
        delete []funcs;
    }

    size_t loadList(const char* filename, bool watchBefore, bool watchAfter);

    bool appendFunc(WFuncInfo &info);

    WFuncInfo* findFunc(const std::string& dllName, const std::string &funcName);

    WFuncInfo *funcs;
    size_t funcsCount;
};

