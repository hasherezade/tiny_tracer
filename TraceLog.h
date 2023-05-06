#pragma once
#include "pin.H"

#include <iostream>
#include <fstream>

class TraceLog 
{
public:
    TraceLog()
    {
    }

    ~TraceLog()
    {
        if (m_traceFile.is_open()) {
            m_traceFile.close();
        }
    }

    void init(std::string fileName, bool is_short)
    {
        if (fileName.empty()) fileName = "output.txt";
        m_logFileName = fileName;
        m_shortLog = is_short;
        createFile();
    }

    void logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string &module, const std::string &func = "");
    void logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr);
    void logCallRet(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT retPageBase, const ADDRINT retAddr, const std::string &module, const std::string &func);
    void logSectionChange(const ADDRINT addr, std::string &sectionName);
    void logNewSectionCalled(const ADDRINT addFrom, const std::string &prevSection, const std::string &currSection);
    void logIndirectCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const ADDRINT calledBase, const ADDRINT callRVA);
    void logRdtsc(const ADDRINT base, const ADDRINT rva);
    void logCpuid(const ADDRINT base, const ADDRINT rva, const ADDRINT param);
    void logSyscall(const ADDRINT base, const ADDRINT rva, const ADDRINT param, const std::string &funcName);

    void logLine(std::string &str);

protected:

    bool createFile()
    {
        if (m_traceFile.is_open()) {
            return true;
        }
        m_traceFile.open(m_logFileName.c_str());
        if (m_traceFile.is_open()) {
            return true;
        }
        return false;
    }

    std::string m_logFileName;
    std::ofstream m_traceFile;
    bool m_shortLog;
};
