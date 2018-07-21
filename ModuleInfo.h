#pragma once

#include "pin.H"

#include <map>

#define UNKNOWN_ADDR (-1)

struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
    bool is_valid;
};

bool init_module(s_module &mod, const ADDRINT &Address);
bool init_module(s_module &mod, const IMG &Image);

bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec);

const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules);

std::string get_func_at(ADDRINT callAddr);
