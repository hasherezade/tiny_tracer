#include "ModuleInfo.h"
#include <string>
#include <iostream>
#include <sstream>

bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec)
{
    if (SEC_Address(sec) < ImageBase) {
        return false;
    }
    section.name = SEC_Name(sec);
    section.start = SEC_Address(sec) - ImageBase;
    section.end = section.start + SEC_Size(sec);
    return true;
}

const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules)
{
    std::map<ADDRINT, s_module>::iterator bound = modules.upper_bound(Address);
    std::map<ADDRINT, s_module>::iterator itr = modules.begin();

    for (; itr != bound; ++itr) {
        s_module &mod = itr->second;
        if (Address >= mod.start && Address < mod.end) {
            return &mod;
        }
    }
    return nullptr;
}

std::string get_func_at(ADDRINT callAddr, ADDRINT& diff)
{
    IMG pImg = IMG_FindByAddress(callAddr);
    if (!IMG_Valid(pImg)) {
        std::ostringstream sstr;
        sstr << "[ " << callAddr << "]*";
        return sstr.str();
    }
    const ADDRINT base = IMG_LoadOffset(pImg);
    RTN rtn = RTN_FindByAddress(callAddr);
    if (!RTN_Valid(rtn)) {
        std::ostringstream sstr;
        sstr << "[ + " << (callAddr - base) << "]*";
        return sstr.str();
    }

    std::string name = get_unmangled_name(rtn);
    ADDRINT rtnAddr = RTN_Address(rtn);
    diff = callAddr - rtnAddr;
    return name;
}

ADDRINT get_mod_base(ADDRINT Address)
{
    if (Address == UNKNOWN_ADDR) {
        return UNKNOWN_ADDR;
    }
    IMG img = IMG_FindByAddress(Address);
    if (IMG_Valid(img)) {
        ADDRINT base = IMG_LoadOffset(img);
        if (base == 0) {
            base = IMG_LowAddress(img);
        }
        return base;
    }
    return UNKNOWN_ADDR;
}

ADDRINT get_base(ADDRINT Address)
{
    ADDRINT base = get_mod_base(Address);
    if (base != UNKNOWN_ADDR) {
        return base;
    }
    return query_region_base(Address);
}

ADDRINT addr_to_rva(ADDRINT Address)
{
    ADDRINT base = get_base(Address);
    if (base == UNKNOWN_ADDR) {
        return Address;
    }
    return Address - base;
}

ADDRINT query_region_base(ADDRINT memoryAddr)
{
    if (memoryAddr == UNKNOWN_ADDR) {
        return UNKNOWN_ADDR;
    }
    return GetPageOfAddr((ADDRINT)memoryAddr);
}

std::string get_unmangled_name(RTN rtn)
{
    return PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
}

RTN find_by_unmangled_name(IMG img, const CHAR* fName)
{
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        const std::string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
        if (undFuncName == fName) {
            const ADDRINT offset = SYM_Value(sym);
            if (offset == UNKNOWN_ADDR) break;
            return RTN_FindByAddress(IMG_LowAddress(img) + offset);
        }
    }
    return RTN_Invalid();
}
