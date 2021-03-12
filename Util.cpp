#include "Util.h"

#include <algorithm>

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
