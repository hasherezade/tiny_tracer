#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>

struct RoutineInfo
{
    RoutineInfo() : paramCount(0) {};

    virtual bool load(const std::string& line, char delimiter) = 0;
    virtual bool isValid() const = 0;

    size_t paramCount;
};

struct WFuncInfo : public RoutineInfo
{
    WFuncInfo() : RoutineInfo()
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
};

struct WSyscallInfo : public RoutineInfo
{
    static const uint32_t INVALID_SYSCALL = (-1);

    WSyscallInfo() :
        RoutineInfo(), 
        syscallId(INVALID_SYSCALL)
    {
    }

    bool load(const std::string& line, char delimiter);

    bool update(const WSyscallInfo& syscall_info);

    bool isValid() const
    {
        return (syscallId != INVALID_SYSCALL);
    }

    uint32_t syscallId;
};

//---

class FuncList {
public:
    static const char DELIM = ';';

    FuncList()
    {
    }

    ~FuncList()
    {
    }

    bool isEmpty() { return this->funcs.size() > 0 ? false : true; }

    bool contains(const std::string& dll_name, const std::string& func);

    size_t loadList(const char* filename);

    std::vector<WFuncInfo> funcs;

protected:
    bool appendFunc(WFuncInfo& info);

    WFuncInfo* findFunc(const std::string& dllName, const std::string& funcName);
};

//--

class FuncWatchList : public FuncList {
public:
    FuncWatchList()
        : FuncList()
    {
    }

    bool isEmpty() { return (this->funcs.size() + this->syscalls.size()) > 0 ? false : true; }

    size_t loadList(const char* filename, FuncList* exclusions);

    std::map<uint32_t, WSyscallInfo> syscalls;

private:
    void appendSyscall(WSyscallInfo& syscall_info);
};

