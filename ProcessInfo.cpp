#include "ProcessInfo.h"

//----

bool is_my_name(const s_module* mod, std::string name)
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

bool ProcessInfo::isMyModule(const s_module* mod)
{
    if (!mod || !myModule) return false;
    if (this->myModule->start == mod->start) {
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
    if (m_myPid == 0 && is_my_name(&mod, m_AnalysedApp)) {
        m_myPid = PIN_GetPid();
        myModule = &m_Modules[mod.start];
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

