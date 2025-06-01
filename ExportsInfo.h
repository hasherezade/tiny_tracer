#pragma once

#include "pin.H"
#include <fstream>
#include <string>
#include <map>

class ExportsLookup
{
public:
	size_t addFromFile(const IMG& img);
	
	std::string fetchExport(const ADDRINT& addr)
	{
		auto itr = namesLookup.find(addr);
		if (itr != namesLookup.end()) {
			return itr->second;
		}
		return "";
	}

protected:
	void appendExport(const ADDRINT addr, const std::string name)
	{
		namesLookup[addr] = name;
	}

	size_t fillExports(const ADDRINT base, const void* mod);

	std::map<ADDRINT, std::string> namesLookup;
	std::map<ADDRINT, INT> ordinalsLookup;
};

size_t dumpFileExports(std::ofstream& fileStream, const IMG& img);
size_t dumpModuleExports(std::ofstream& fileStream, IMG& img);
size_t dumpModuleSymbols(std::ofstream& fileStream, IMG& img);
