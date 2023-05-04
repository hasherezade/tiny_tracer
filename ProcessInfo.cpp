#include "ProcessInfo.h"
#include <algorithm>
#include <cstring>

std::string to_lowercase(const std::string &_str)
{
    std::string str = _str;
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}


bool is_my_name(const std::string &module_name, const std::string &my_name)
{
    std::string mod1 = to_lowercase(module_name);
    std::string mod2 = to_lowercase(my_name);
    if (mod1 == mod2) {
        return true;
    }
    std::size_t found1 = mod1.find_last_of("/\\");
    if (found1 != std::string::npos) {
            mod1 = mod1.substr(found1+1);
    }
    std::size_t found2 = mod2.find_last_of("/\\");
    if (found2 != std::string::npos) {
            mod2 = mod2.substr(found2+1);
    }    

    if (mod1 == mod2) {
        return true;
    }
    return false;
}

//----
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
    // if this module is an object of observation, add its sections also
    if (m_myPid == 0 && is_my_name(IMG_Name(Image), m_AnalysedApp)) {
        m_myPid = PIN_GetPid();
        myModuleBase = IMG_LoadOffset(Image);
        if (myModuleBase == 0) {
            myModuleBase = IMG_LowAddress(Image);
        }
        addModuleSections(Image, myModuleBase);
    }
    return true;
}

const bool ProcessInfo::updateTracedModuleSection(ADDRINT Rva)
{
    // saved section (of the target module)
    static s_module* prevSec = nullptr;

    // current section of the target module (by RVA)
    const s_module* currSec = getSecByAddr(Rva);

    if (prevSec != currSec) {
        // update the stored section
        prevSec = (s_module*)currSec;
        return true;
    }
    return false;
}

