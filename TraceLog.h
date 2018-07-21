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

    void init(std::string fileName)
    {
        if (fileName.empty()) fileName = "output.txt";
        m_logFileName = fileName;
        createFile();
    }

    void logCall(const ADDRINT prevAddr, const string module, const string func = "");
    void logCall(const ADDRINT prevAddr, const ADDRINT callAddr);
    void logSectionChange(const ADDRINT addr, std::string sectionName);
    void logNewSectionCalled(const ADDRINT addFrom, std::string prevSection, std::string currSection);

protected:
    void createFile()
    {
        if (m_traceFile.is_open()) return;
        m_traceFile.open(m_logFileName.c_str());
    }

    std::string m_logFileName;
    std::ofstream m_traceFile;
};
