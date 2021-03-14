#include "FuncWatch.h"

#include <vector>
#include <fstream>
#include <sstream>

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
    if (args.size() < 3) return false;

    this->dllName = args[0];
    this->funcName = args[1];
    {
        std::stringstream ss;
        ss << std::dec << args[2];
        ss >> this->paramCount;
    }
    this->watchBefore = _watchBefore;
    this->watchAfter = _watchAfter;
    return true;
}

bool FuncWatchList::appendFunc(std::string& dllname, std::string& fname, size_t count)
{
    if (funcsCount == (g_WatchedMax - 1)) {
        return false;
    }
    if (dllname.length() == 0 || fname.length() == 0) {
        return false;
    }
    funcs[funcsCount].dllName = dllname;
    funcs[funcsCount].funcName = fname;
    funcs[funcsCount].paramCount = count;
    funcsCount++;
    return true;
}

bool FuncWatchList::appendFunc(WFuncInfo &func_info)
{
    if (funcsCount == (g_WatchedMax - 1)) {
        return false;
    }
    if (!func_info.isValid()) {
        return false;
    }
    funcs[funcsCount] = func_info;
    funcsCount++;
    return true;
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
    return funcsCount;
}
