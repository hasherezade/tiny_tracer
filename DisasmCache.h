#pragma once

#include <iostream>
#include <string>
#include <map>

#include "Crc.h"

//----

struct DisasmCache
{
    static uint64_t calcChecks(const std::string& _disasm)
    {
        uint64_t init = 0;
        return crc64(init, (unsigned char*)_disasm.c_str(), _disasm.length());
    }

    DisasmCache() {}

    ~DisasmCache() {
        for (auto itr = disasmLines.begin(); itr != disasmLines.end(); ++itr) {
            char* buf = itr->second;
            if (buf) free(buf);
        }
    }

    const char* get(uint32_t crc32)
    {
        auto itr = disasmLines.find(crc32);
        if (itr == disasmLines.end()) {
            return nullptr;
        }
        return disasmLines[crc32];
    }

    const char* put(const std::string& _disasm)
    {
        auto checks = calcChecks(_disasm);
        auto infoPtr = get(checks);
        if (infoPtr) {
            return infoPtr;
        }
        const size_t len = _disasm.length();
        char *buf = (char*)::malloc(len + 1);
        ::memcpy(buf, _disasm.c_str(), len);
        buf[len] = 0;
        disasmLines[checks] = buf;
        return disasmLines[checks];
    }

    //---
    std::map<uint64_t, char*> disasmLines;
};
