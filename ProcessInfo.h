#pragma once

#include "pin.H"

#include <map>
#include "ModuleInfo.h"

class ProcessInfo
{
public:
    ProcessInfo()
        : m_myPid(0), isInit(false)
    {
    }

    bool init(std::string app)
    {
        if (isInit) {
            return false; // already initialized
        }
        m_AnalysedApp = app;
        m_myPid = 0; //UNKNOWN
        isInit = true;
        myModule = nullptr;
        return true;
    }

    bool addModule(IMG Image);

    const s_module* getModByAddr(ADDRINT Address)
    {
        return get_by_addr(Address, m_Modules);
    }

    const s_module* getSecByAddr(ADDRINT Address)
    {
        return get_by_addr(Address, m_Sections);
    }

    bool isMyAddress(ADDRINT Address)
    {
        const s_module *mod_ptr = getModByAddr(Address);
        if (!mod_ptr) {
            return false;
        }
        return isMyModule(mod_ptr);
    }

    const bool isSectionChanged(ADDRINT Address);
    
    bool isMyModule(const s_module* mod);

protected:
    
    void addModuleSections(IMG Image, ADDRINT ImageBase);

    std::map<ADDRINT, s_module> m_Modules;
    std::map<ADDRINT, s_module> m_Sections;
    const s_module *myModule;

    std::string m_AnalysedApp;
    INT m_myPid;
    bool isInit;
};

