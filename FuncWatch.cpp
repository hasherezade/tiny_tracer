#include "FuncWatch.h"

#include <vector>
#include <fstream>
#include <sstream>

#include "Util.h"

size_t split_list(const std::string &sline, const char delimiter, std::vector<std::string> &args)
{
    std::istringstream f(sline);
    std::string s;
    while (getline(f, s, delimiter)) {
        args.push_back(s);
    }
    return args.size();
}

bool WFuncInfo::load(const std::string &sline, char delimiter, bool _watchBefore, bool _watchAfter)
{
    std::vector<std::string> args;
    split_list(sline, delimiter, args);
    if (args.size() < 2) return false;

    this->dllName = args[0];
    this->funcName = args[1];
    this->paramCount = 0;
    if (args.size() >= 3)
    {
        std::stringstream ss;
        ss << std::dec << args[2];
        ss >> this->paramCount;
    }
    this->watchBefore = _watchBefore;
    this->watchAfter = _watchAfter;
    return true;
}

bool WFuncInfo::update(const WFuncInfo &func_info)
{
    bool isUpdated = false;
    if (this->paramCount < func_info.paramCount) {
        this->paramCount = func_info.paramCount;
        isUpdated = true;
    }
    if (!this->watchAfter && func_info.watchAfter) {
        this->watchAfter = func_info.watchAfter;
        isUpdated = true;
    }
    if (!this->watchBefore && func_info.watchBefore) {
        this->watchBefore = func_info.watchBefore;
        isUpdated = true;
    }
    return isUpdated;
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

size_t FuncWatchList::loadList(const char* filename, bool watchBefore, bool watchAfter)
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

        WFuncInfo func_info;
        if (func_info.load(line, ';', watchBefore, watchAfter)) {
            appendFunc(func_info);
        }
    }
    return funcs.size();
}
