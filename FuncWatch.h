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

    bool isValid()
    {
        if (dllName.length() > 0 && funcName.length() > 0 && paramCount > 0
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

    bool appendFunc(std::string& dllname, std::string& fname, size_t count);
    bool appendFunc(WFuncInfo &info);

    WFuncInfo *funcs;
    size_t funcsCount;
};

