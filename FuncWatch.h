#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>

struct WFuncInfo 
{
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
        return dllName.length() > 0 && funcName.length() > 0;
    }

    std::string dllName;
    std::string funcName;
    size_t paramCount;
};

struct WSyscallInfo
{
    WSyscallInfo() : syscallId(0), paramCount(0)
    {
    }

    bool load(const std::string& line, char delimiter);

    bool update(const WSyscallInfo& syscall_info);

    uint32_t syscallId;
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

    std::vector<WFuncInfo> funcs;
    std::map<uint32_t, WSyscallInfo> syscalls;

private:
    bool appendFunc(WFuncInfo& info);
    void appendSyscall(WSyscallInfo& syscall_info);

    WFuncInfo* findFunc(const std::string& dllName, const std::string& funcName);
};

