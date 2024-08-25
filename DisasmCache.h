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
		for (auto itr = disasmLines.begin(); itr != disasmLines.end(); ++itr)
		{
			delete itr->second;
		}
	}

    std::string* get(uint32_t crc32)
    {
        auto itr = disasmLines.find(crc32);
        if (itr == disasmLines.end()) {
            return nullptr;
        }
        return disasmLines[crc32];
    }

    std::string* put(const std::string& _disasm)
    {
        auto checks = calcChecks(_disasm);
        auto infoPtr = get(checks);
        if (infoPtr) {
            return infoPtr;
        }
        disasmLines[checks] = new std::string(_disasm);
        return disasmLines[checks];
    }

	//---
	std::map<uint64_t, std::string*> disasmLines;
};
