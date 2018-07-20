#include "ProcessInfo.h"

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

//----

bool ProcessInfo::isMyModule(const s_module* mod, std::string name)
{
    if (!mod) {
        return false;
    }
    std::size_t found = mod->name.find(name);
    if (found != std::string::npos) {
        return true;
    }
    return false;
}

void ProcessInfo::addModuleSections(IMG Image, ADDRINT ImageBase)
{
    // enumerate sections within the analysed module
    for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {
        s_module section;
        init_section(section, ImageBase, sec);
        m_Sections[section.start] = section;
    }
}

bool ProcessInfo::addModule(IMG Image)
{
    // Add module into a global map
    s_module mod;
    init_module(mod, Image);
    m_Modules[mod.start] = mod;

    // if this module is an object of observation, add its sections also
    if (m_myPid == 0 && isMyModule(&mod, m_AnalysedApp)) {
        m_myPid = PIN_GetPid();
        addModuleSections(Image, mod.start);
    }
    return true;
}

const bool ProcessInfo::isSectionChanged(ADDRINT Address /* without imagebase */)
{
    static s_module* prevModule = nullptr;
    const s_module* currModule = getSecByAddr(Address);

    if (prevModule != currModule) {
        prevModule = (s_module*)currModule;
        return true;
    }
    return false;
}

