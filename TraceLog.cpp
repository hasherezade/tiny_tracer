#include "TraceLog.h"

#define DELIMITER ';'

std::string get_dll_name(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(found + 1, ext - (found + 1));
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    return name;
}

void TraceLog::logCall(const ADDRINT prevAddr, bool isRVA, const std::string module, const std::string func)
{
    createFile();
    if (!isRVA) {
        m_traceFile << ">>";
    }
    m_traceFile <<
        std::hex << prevAddr
        << DELIMITER;

    if (!m_shortLog) {
        m_traceFile << "called: "
            << module;
    }
    else {
        m_traceFile << get_dll_name(module);
    }
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

void TraceLog::logNewSectionCalled(const ADDRINT prevAddr, std::string prevSection, std::string currSection)
{
    createFile();
    m_traceFile
        << std::hex << prevAddr
        << DELIMITER
        << prevSection << "->" << currSection
        << std::endl;
    m_traceFile.flush();
}
