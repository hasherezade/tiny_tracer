#pragma once
#include "pin.H"

#include <iostream>
#include <fstream>


class TraceLog 
{
public:
    static const char DELIMITER = ';';

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
        _createFile(m_traceFile, m_logFileName);
        _createFile(m_ListingFile, m_logFileName + ".listing.txt");
    }

    void logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string &module, const std::string &func = "");
    void logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr);
    void logCallRet(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT retPageBase, const ADDRINT retAddr, const std::string &module, const std::string &func);
    void logSectionChange(const ADDRINT addr, std::string &sectionName);
    void logNewSectionCalled(const ADDRINT addFrom, const std::string &prevSection, const std::string &currSection);
    void logIndirectCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const ADDRINT calledBase, const ADDRINT callRVA);
    void logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem, const ADDRINT param);
    void logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem);
    void logSyscall(const ADDRINT base, const ADDRINT rva, const ADDRINT param, const std::string &funcName);

    void logLine(const std::string &str);
    void logListingLine(const std::string& str);
protected:

    bool createFile()
    {
        return _createFile(m_traceFile, m_logFileName);
    }

    bool _createFile(std::ofstream &file, const std::string &fileName)
    {
        if (file.is_open()) {
            return true;
        }
        file.open(fileName.c_str());
        if (file.is_open()) {
            return true;
        }
        return false;
    }

    std::string m_logFileName;
    std::ofstream m_traceFile;
    std::ofstream m_ListingFile;
    bool m_shortLog;
};
