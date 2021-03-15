#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <vector>

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

    bool load(const std::string &line, char delimiter);

    bool update(const WFuncInfo &func_info);

    bool isValid() const
    {
        if (dllName.length() > 0 && funcName.length() > 0) {
            return true;
        }
        return false;
    }

    std::string dllName;
    std::string funcName;
    size_t paramCount;
};

class FuncWatchList {
public:
    FuncWatchList()
    {
    }

    ~FuncWatchList()
    {
    }

    size_t loadList(const char* filename);
    bool appendFunc(WFuncInfo &info);

    WFuncInfo* findFunc(const std::string& dllName, const std::string &funcName);

    std::vector<WFuncInfo> funcs;
};

