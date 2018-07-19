#pragma once
#include "pin.H"

#include <iostream>

class TraceLog 
{
public:
    TraceLog()
    {
        m_BlocksFile = nullptr;
    }

    ~TraceLog()
    {
        if (m_BlocksFile) {
            fclose(m_BlocksFile);
            m_BlocksFile = nullptr;
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

protected:
    void createFile()
    {
        if (m_BlocksFile) return;
        m_BlocksFile = fopen(m_logFileName.c_str(), "w");
    }

    FILE *m_BlocksFile;
    std::string m_logFileName;
};
