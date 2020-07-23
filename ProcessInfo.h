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
        myModuleBase = UNKNOWN_ADDR;
        return true;
    }

    bool addModule(IMG Image);

    const s_module* getSecByAddr(ADDRINT Address)
    {
        return get_by_addr(Address, m_Sections);
    }

    bool isMyAddress(ADDRINT Address)
    {
        if (Address == UNKNOWN_ADDR) {
            return false;
        }
        IMG myImg = IMG_FindByAddress(myModuleBase);
        IMG otherImg = IMG_FindByAddress(Address);
        if (!IMG_Valid(myImg) || !IMG_Valid(otherImg)) {
            return false;
        }
        if (IMG_LoadOffset(myImg) == IMG_LoadOffset(otherImg)) {
            return true;
        }
        return false;
    }

    /** 
        Saves the transition between sections witing the target module.
        \param Rva : current RVA witin the target module
        \return : true if the section changed, false otherwise
    */
    const bool updateTracedModuleSection(ADDRINT Rva);
    
protected:
    
    void addModuleSections(IMG Image, ADDRINT ImageBase);

    std::map<ADDRINT, s_module> m_Sections;
    ADDRINT myModuleBase;

    std::string m_AnalysedApp;
    INT m_myPid;
    bool isInit;
};

