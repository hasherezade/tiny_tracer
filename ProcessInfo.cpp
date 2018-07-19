#include "ProcessInfo.h"

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
        section.name = SEC_Name(sec);
        section.start = SEC_Address(sec) - ImageBase;
        section.end = section.start + SEC_Size(sec);

        m_Sections[section.start] = section;
    }
}

bool ProcessInfo::addModule(IMG Image)
{
    // Add module into a global map
    s_module mod;
    mod.name = std::string(IMG_Name(Image));
    mod.start = IMG_LowAddress(Image);
    mod.end = IMG_HighAddress(Image);

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

