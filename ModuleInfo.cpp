#include "ModuleInfo.h"
#include <string>
#include <iostream>

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

    for (; itr != bound; itr++) {
        s_module &mod = itr->second;
        if (Address >= mod.start && Address < mod.end) {
            return &mod;
        }
    }
    return nullptr;
}

std::string get_func_at(ADDRINT callAddr)
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
    std::string name = RTN_Name(rtn);
    ADDRINT rtnAddr = RTN_Address(rtn);
    if (rtnAddr == callAddr) {
        return name;
    }
    // it doesn't start at the beginning of the routine
    const ADDRINT diff = callAddr - rtnAddr;
    std::ostringstream sstr;
    sstr << "[" << name << "+" << std::hex << diff << "]*";
    return sstr.str();
}

ADDRINT get_mod_base(ADDRINT Address)
{
    IMG img = IMG_FindByAddress(Address);
    if (IMG_Valid(img)) {
        const ADDRINT base = IMG_LoadOffset(img);
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
    NATIVE_PID processId = (NATIVE_PID)PIN_GetPid();
    OS_MEMORY_AT_ADDR_INFORMATION  info = { 0 };
    OS_RETURN_CODE ret = OS_QueryMemory(processId,
        (VOID*)memoryAddr,
        &info
    );
    const ADDRINT pageFrom = GetPageOfAddr((ADDRINT)memoryAddr);
    const ADDRINT baseAddr = (ADDRINT)info.BaseAddress;

    if (pageFrom != baseAddr) {
        std::cout << std::hex << "baseAddr: " << baseAddr << " pageFrom: " << pageFrom << std::endl;
    }
    if (ret.generic_err != OS_RETURN_CODE_NO_ERROR) {
        return pageFrom;
    }
    return baseAddr;
}
