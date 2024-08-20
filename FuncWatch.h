#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>

#define LIST_DELIMITER ';'

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

    WFuncInfo(const std::string& _dllName, const std::string& _funcName, const size_t _paramCount)
    {
        this->dllName = _dllName;
        this->funcName = _funcName;
        this->paramCount = _paramCount;
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

    static std::string formatSyscallName(int syscallID);

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
template <class WFuncInfo_T>
class FuncList {
public:
    static const char DELIM = LIST_DELIMITER;

    FuncList()
    {
    }

    ~FuncList()
    {
    }

    bool isEmpty() { return this->funcs.size() > 0 ? false : true; }

    bool contains(const std::string& dll_name, const std::string& func)
    {
        if (!dll_name.length() || !func.length()) return false;
        if (this->isEmpty()) return false;

        const std::string shortDll = util::getDllName(dll_name);
        for (auto itr = funcs.begin(); itr != funcs.end(); ++itr) {
            WFuncInfo_T& fInfo = *itr;
            if (util::iequals(fInfo.dllName, shortDll)) {
                if (fInfo.funcName == func) {
                    //std::cout << "Excluded Func: " << shortDll << "." << func << "\n";
                    return true;
                }
            }
        }
        return false;
    }

    bool appendFunc(WFuncInfo_T& func_info)
    {
        if (!func_info.isValid()) {
            return false;
        }
        WFuncInfo_T* found = findFunc(func_info.dllName, func_info.funcName);
        if (!found) {
            funcs.push_back(func_info);
        }
        else {
            found->update(func_info);
        }
        return true;
    }


    size_t loadList(const char* filename)
    {
        std::ifstream myfile(filename);
        if (!myfile.is_open()) {
            std::cerr << "Coud not open file: " << filename << std::endl;
            return 0;
        }
        const size_t MAX_LINE = 300;
        char line[MAX_LINE] = { 0 };
        while (!myfile.eof()) {
            myfile.getline(line, MAX_LINE);

            // Try to parse as a function
            WFuncInfo_T func_info;

            if (func_info.load(line, FuncList::DELIM)) {
                appendFunc(func_info);
            }
        }
        return funcs.size();
    }

    std::vector<WFuncInfo_T> funcs;

protected:
    WFuncInfo_T* findFunc(const std::string& dllName, const std::string& funcName)
    {
        for (size_t i = 0; i < funcs.size(); i++)
        {
            WFuncInfo_T& info = funcs[i];
            if (util::iequals(info.dllName, dllName)
                && util::iequals(info.funcName, funcName))
            {
                return &info;
            }
        }
        return NULL;
    }
};

//--

class FuncWatchList : public FuncList<WFuncInfo>{
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
