#pragma once

#include <iostream>
#include <string>
#include <map>

#include "crc.h"

//----

struct InstrInfo
{
    static uint64_t calcChecks(const std::string& _disasm)
    {
        uint64_t init = 0;
        return crc64(init, (unsigned char*)_disasm.c_str(), _disasm.length());
    }

    //---

    InstrInfo() : disasm(nullptr), checks(0) { }

    InstrInfo(const InstrInfo& other) {
        this->disasm = new std::string(other.disasm->c_str());
        this->checks = other.checks;
    }

    InstrInfo(const std::string& _disasm)
        : disasm(nullptr), checks(0)
    {
        this->disasm = new std::string(_disasm.c_str());
        this->checks = calcChecks(_disasm);
    }

	~InstrInfo() { delete disasm; }

	//---
	std::string* disasm;
	uint64_t checks;
};

struct DisasmCache
{
	DisasmCache() {}

	~DisasmCache() {
		for (auto itr = disasmLines.begin(); itr != disasmLines.end(); ++itr)
		{
			delete itr->second;
		}
	}

    InstrInfo* get(uint32_t crc32)
    {
        auto itr = disasmLines.find(crc32);
        if (itr == disasmLines.end()) {
            return nullptr;
        }
        return disasmLines[crc32];
    }

    InstrInfo* put(const std::string& _disasm)
    {
        auto checks = InstrInfo::calcChecks(_disasm);
        auto itr = disasmLines.find(checks);
        if (itr != disasmLines.end()) {
            return itr->second;
        }
        InstrInfo* info = new InstrInfo(_disasm);
        disasmLines[checks] = info;
        return info;
    }

	//---
	std::map<uint64_t, InstrInfo*> disasmLines;
};
