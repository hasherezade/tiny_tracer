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
    WFuncInfo() : paramCount(0)
    {
    }

    WFuncInfo(const WFuncInfo& a)
    {
        this->dllName = a.dllName;
        this->funcName = a.funcName;
        this->paramCount = a.paramCount;
    }

    bool load(const std::string &line, char demiliter);

    std::string dllName;
    std::string funcName;
    size_t paramCount;
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

    size_t loadList(const char* filename);

    bool appendFunc(std::string& dllname, std::string& fname, size_t count);

    WFuncInfo *funcs;
    size_t funcsCount;
};

