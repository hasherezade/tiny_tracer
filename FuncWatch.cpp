#include "FuncWatch.h"

#include <vector>
#include <fstream>
#include <sstream>

#include "Util.h"

bool WFuncInfo::load(const std::string &sline, char delimiter)
{
    std::vector<std::string> args;
    util::splitList(sline, delimiter, args);
    if (args.size() < 3) return false;

    this->dllName = args[0];
    this->funcName = args[1];
    this->paramCount = util::loadInt(args[2]);

    return true;
}

bool WFuncInfo::update(const WFuncInfo &func_info)
{
    bool isUpdated = false;
    if (this->paramCount < func_info.paramCount) {
        this->paramCount = func_info.paramCount;
        isUpdated = true;
    }
    return isUpdated;
}

//---

bool WSyscallInfo::load(const std::string& sline, char delimiter)
{
    std::vector<std::string> args;
    util::splitList(sline, delimiter, args);
    if (args.size() < 3) return false;
    // Note: '<' and '>' are used to ensure this cannot overlap with a valid
    // file or library name.
    if (args[0] != "<SYSCALL>") return false;

    // Parse syscall ID as a hexadecimal number
    const int syscallId = util::loadInt(args[1], true);
    if (syscallId < 0) return false;

    this->syscallId = static_cast<uint32_t>(syscallId);
    this->paramCount = util::loadInt(args[2]);

    return true;
}

bool WSyscallInfo::update(const WSyscallInfo& syscall_info)
{
    bool isUpdated = false;
    if (this->paramCount < syscall_info.paramCount) {
        this->paramCount = syscall_info.paramCount;
        isUpdated = true;
    }
    return isUpdated;
}

//---

WFuncInfo* FuncWatchList::findFunc(const std::string& dllName, const std::string &funcName)
{
    for (size_t i = 0; i < funcs.size(); i++)
    {
        WFuncInfo& info = funcs[i];
        if (util::iequals(info.dllName, dllName)
            && util::iequals(info.funcName, funcName))
        {
            return &info;
        }
    }
    return NULL;
}

bool FuncWatchList::appendFunc(WFuncInfo &func_info)
{
    if (!func_info.isValid()) {
        return false;
    }
    WFuncInfo* found = findFunc(func_info.dllName, func_info.funcName);
    if (!found) {
        funcs.push_back(func_info);
    }
    else {
        found->update(func_info);
    }
    return true;
}

void FuncWatchList::appendSyscall(WSyscallInfo& syscall_info)
{
    std::map<uint32_t, WSyscallInfo>::iterator it = syscalls.find(syscall_info.syscallId);
    if (it == syscalls.end()) {
        syscalls[syscall_info.syscallId] = syscall_info;
    }
    else {
        it->second.update(syscall_info);
    }
}

size_t FuncWatchList::loadList(const char* filename)
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

        // Try to parse as a syscall
        WSyscallInfo syscall_info;
        if (syscall_info.load(line, ';')) {
            appendSyscall(syscall_info);
            continue;
        }

        // Try to parse as a function
        WFuncInfo func_info;
        if (func_info.load(line, ';')) {
            appendFunc(func_info);
        }
    }
    return funcs.size();
}
