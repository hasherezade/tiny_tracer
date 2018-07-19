#include "TraceLog.h"

void TraceLog::logCall(const ADDRINT prevAddr, const string module, const string func)
{
    createFile();
    fprintf(m_BlocksFile, "%p;called: %s:", prevAddr, module.c_str());
    if (func.length() > 0) {
        fprintf(m_BlocksFile, "%s", func.c_str());
    }
    fprintf(m_BlocksFile, "\n");
    fflush(m_BlocksFile);
}

void TraceLog::logCall(const ADDRINT prevAddr, const ADDRINT callAddr)
{
    createFile();
    fprintf(m_BlocksFile, "%p;called: ?? [%p];\n", prevAddr, callAddr);
    fprintf(m_BlocksFile, "\n");
    fflush(m_BlocksFile);
}

void TraceLog::logSectionChange(const ADDRINT addr, std::string name)
{
    createFile();
    fprintf(m_BlocksFile, "%p;sec: %s\n", addr, name.c_str());
    fflush(m_BlocksFile);
}
