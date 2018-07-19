#pragma once

#include "pin.H"

#include <map>

#define UNKNOWN_ADDR (-1)

struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
};

const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules);

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
        return isMyModule(mod_ptr, m_AnalysedApp);
    }

    const bool isSectionChanged(ADDRINT Address);

protected:
    bool isMyModule(const s_module* mod, std::string name);
    void addModuleSections(IMG Image, ADDRINT ImageBase);

    std::map<ADDRINT, s_module> m_Modules;
    std::map<ADDRINT, s_module> m_Sections;

    std::string m_AnalysedApp;
    INT m_myPid;
    bool isInit;
};
