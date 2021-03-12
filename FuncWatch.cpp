#include "FuncWatch.h"

#include <vector>
#include <fstream>
#include <sstream>

bool WFuncInfo::load(const std::string &sline, char demiliter)
{
    std::vector<std::string> args;
    std::istringstream f(sline);
    std::string s;
    while (getline(f, s, demiliter)) {
        args.push_back(s);
    }
    if (args.size() < 3) return false;

    this->dllName = args[0];
    this->funcName = args[1];
    {
        std::stringstream ss;
        ss << std::dec << args[2];
        ss >> this->paramCount;
    }
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

        WFuncInfo func_info;
        if (func_info.load(line, ';')) {
            funcs[funcsCount] = func_info;
            funcsCount++;
        }
    }
    return funcsCount;
}
