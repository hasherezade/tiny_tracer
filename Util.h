#pragma once

#include <cctype>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#define IS_PRINTABLE(c) (c >= 0x20 && c < 0x7f)
#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)

#define MAX_DWORD 0xffffffff
#define MAX_WORD 0xffff

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

namespace util {
    std::wstring hexdump(const uint8_t* in_buf, const size_t max_size);

    size_t getAsciiLen(const char *inp, size_t maxInp);
    size_t getAsciiLenW(const wchar_t *inp, size_t maxInp);

    std::string getDllName(const std::string& str);

    bool iequals(const std::string& a, const std::string& b);
    size_t splitList(const std::string &sline, const char delimiter, std::vector<std::string> &args);

    // trim from both ends (in place)
    void trim(std::string &s);

    int loadInt(const std::string &str, bool as_hex = false);

    std::string stripQuotes(const std::string& str);

    // compare strings, ignore case
    bool isStrEqualI(const std::string& str1, const std::string& str2);

    inline void wstr_to_str(const wchar_t* c, char* buf, const size_t bufSize)
    {
        size_t i;
        for (i = 0; i < bufSize; i++) {
            buf[i] = c[i];
            if (c[i] == '\0') break;
        }
    }

};
