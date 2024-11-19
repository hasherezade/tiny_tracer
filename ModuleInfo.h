#pragma once

#include "pin.H"

#include <map>

#define UNKNOWN_ADDR ~ADDRINT(0)

struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
    bool is_valid;
};

bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec);

const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules);

std::string get_func_at(ADDRINT callAddr, ADDRINT&diff);

ADDRINT get_mod_base(ADDRINT Address);

ADDRINT get_base(ADDRINT Address);

ADDRINT addr_to_rva(ADDRINT Address);

ADDRINT query_region_base(ADDRINT memoryAddr);

std::string get_unmangled_name(RTN rtn);

RTN find_by_unmangled_name(IMG img, const CHAR* fName);

