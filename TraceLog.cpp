#include "TraceLog.h"

#define DELIMITER ';'

void TraceLog::logCall(const ADDRINT prevAddr, const string module, const string func)
{
    createFile();
    m_traceFile << 
        std::hex << prevAddr 
        << DELIMITER 
        << "called: " << module;
    if (func.length() > 0) {
        m_traceFile << "." << func;
    }
    m_traceFile << std::endl;
    m_traceFile.flush();
}

void TraceLog::logCall(const ADDRINT prevAddr, const ADDRINT callAddr)
{
    createFile();
    m_traceFile << 
        std::hex << prevAddr 
        << DELIMITER 
        << "called: ?? [" << callAddr << "]" 
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logSectionChange(const ADDRINT prevAddr, std::string name)
{
    createFile();
    m_traceFile 
        << std::hex << prevAddr 
        << DELIMITER 
        << "section: " << name 
        << std::endl;
    m_traceFile.flush();
}
