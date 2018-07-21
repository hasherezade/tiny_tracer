#include "ModuleInfo.h"

std::string get_dll_name(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(found + 1, ext - (found + 1));
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    return name;
}

bool init_module(s_module &mod, const ADDRINT &Address)
{
    IMG Image = IMG_FindByAddress(Address);
    if (!IMG_Valid(Image)) {
        mod.is_valid = false;
        return false;
    }
    return init_module(mod, Image);
}

bool init_module(s_module &mod, const IMG &Image)
{
    if (!IMG_Valid(Image)) {
        mod.is_valid = false;
        return false;
    }
    mod.name = std::string(IMG_Name(Image));
    mod.short_name = get_dll_name(mod.name);
    mod.start = IMG_LoadOffset(Image);
    mod.end = mod.start + IMG_SizeMapped(Image);
    mod.is_valid = true;
    return true;
}

bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec)
{
    if (SEC_Address(sec) < ImageBase) {
        return false;
    }
    section.name = SEC_Name(sec);
    section.short_name = section.name;
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
    RTN rtn = RTN_FindByAddress(callAddr);

    if (IMG_Valid(pImg) && RTN_Valid(rtn)) {
        return RTN_Name(rtn);
    }
    return "";
}
