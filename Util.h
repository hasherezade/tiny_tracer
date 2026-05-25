#pragma once

#include <cctype>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <string>       // std::string
#include <sstream>      // std::stringstream
#include <vector>

#define IS_PRINTABLE(c) (c >= 0x20 && c < 0x7f)
#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)

#define MAX_DWORD 0xffffffff
#define MAX_WORD 0xffff

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#if defined(WIN32) || defined(_WIN32) 
#define PATH_SEPARATOR "\\" 
#else 
#define PATH_SEPARATOR "/" 
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

    template <typename T_INT>
    T_INT loadInt(std::string str, bool as_hex = false)
    {
        // Allow values like "(-1)"
        if (str.size() >= 2 &&
            str.front() == '(' &&
            str.back() == ')')
        {
            str = str.substr(1, str.size() - 2);
        }

        T_INT intVal = 0;
	std::stringstream ss;
	if (as_hex) {
            ss.setf(std::ios::hex, std::ios::basefield);
	}   
	else {
            ss.setf(std::ios::dec, std::ios::basefield);
	}
	ss << str;
	ss >> intVal;
        return intVal;
    }

    std::string stripQuotes(const std::string& str);

    // compare strings, ignore case
    bool isStrEqualI(const std::string& str1, const std::string& str2);

    inline void wstr_to_str(const wchar_t* c, char* buf, const size_t bufSize)
    {
        size_t i;
        for (i = 0; i < bufSize; i++) {
            buf[i] = c[i];
            if (c[i] == 0) break;
        }
    }

    std::string getDirectory(const std::string& filepath);
    std::string getFilename(const std::string& filepath);
    std::string makePath(const std::string& outDir, const std::string& module_name, const std::string& ext);
};
