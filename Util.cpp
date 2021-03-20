#include "Util.h"

#include <algorithm>
#include <sstream>

size_t util::getAsciiLen(const char *inp, size_t maxInp)
{
    size_t i = 0;
    for (; i < maxInp; i++) {
        const char c = inp[i];
        if (c == '\0') return i; //end of string
        if (!IS_PRINTABLE(c) && !IS_ENDLINE(c)) return 0;
    }
    return 0;
}

size_t util::getAsciiLenW(const wchar_t *inp, size_t maxInp)
{
    size_t i = 0;
    for (; i < maxInp; i++) {
        const wchar_t w = inp[i];
        if (w == 0) return i; //end of string
        if (!IS_PRINTABLE(w) && !IS_ENDLINE(w)) return 0;
    }
    return 0;
}

std::string util::getDllName(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(found + 1, ext - (found + 1));
    std::transform(name.begin(), name.end(), name.begin(), std::tolower);
    return name;
}

bool util::iequals(const std::string& a, const std::string& b)
{
    size_t aLen = a.size();
    if (b.size() != aLen) return false;

    for (size_t i = 0; i < aLen; ++i) {
        if (tolower(a[i]) != tolower(b[i])) return false;
    }
    return true;
}

size_t util::splitList(const std::string &sline, const char delimiter, std::vector<std::string> &args)
{
    std::istringstream f(sline);
    std::string s;
    while (getline(f, s, delimiter)) {
        args.push_back(s);
    }
    return args.size();
}
