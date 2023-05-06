#include "TraceLog.h"

#define DELIMITER ';'

#include "Util.h"

void TraceLog::logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string &module, const std::string &func)
{
    if (!createFile()) return;
    ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
    if (!isRVA) {
        m_traceFile << "> " << prevModuleBase << "+";
    }
    m_traceFile <<
        std::hex << rva
        << DELIMITER;

    if (!m_shortLog) {
        m_traceFile << "called: "
            << module;
    }
    else {
        m_traceFile << util::getDllName(module);
    }
    if (func.length() > 0) {
        m_traceFile << "." << func;
    }
    m_traceFile << std::endl;
    m_traceFile.flush();
}

void TraceLog::logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr)
{
    if (!createFile()) return;
    if (prevBase) {
        m_traceFile << "> " << prevBase << "+";
    }
    const ADDRINT rva = callAddr - calledPageBase;
    m_traceFile << 
        std::hex << prevAddr 
        << DELIMITER 
        << "called: ?? [" << calledPageBase << "+" << rva << "]"
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logCallRet(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT retPageBase, const ADDRINT retAddr, const std::string &module, const std::string &func)
{
    if (!createFile()) return;

    ADDRINT retRva = retAddr;
    if (retPageBase) {
        retRva -= retPageBase;
        m_traceFile << "> " << retPageBase << "+";
    }
    m_traceFile
        << std::hex << retRva
        << DELIMITER
        << "RET from: "
        << "[" << prevBase << "+" << prevAddr << "] -> "
        << util::getDllName(module);

    if (func.length() > 0) {
        m_traceFile << "." << func;
    }
    m_traceFile << std::endl;
    m_traceFile.flush();
}


void TraceLog::logSectionChange(const ADDRINT prevAddr, std::string &name)
{
    if (!createFile()) return;
    m_traceFile 
        << std::hex << prevAddr 
        << DELIMITER 
        << "section: [" << name << "]"
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logIndirectCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const ADDRINT calledBase, const ADDRINT calledRVA)
{
    if (!createFile()) return;
    ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
    if (!isRVA) {
        m_traceFile << "> " << prevModuleBase << "+";
    }
    m_traceFile <<
        std::hex << rva
        << DELIMITER;

    m_traceFile
        << "to: " << (calledBase + calledRVA) << " [" << calledBase << " + " << calledRVA << "]"
        << std::endl;
}

void TraceLog::logRdtsc(const ADDRINT base, const ADDRINT rva)
{
    if (!createFile()) return;
    if (base) {
        m_traceFile << "> " << std::hex << base << "+";
    }
    m_traceFile
        << std::hex << rva
        << DELIMITER
        << "RDTSC"
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logCpuid(const ADDRINT base, const ADDRINT rva, const ADDRINT param)
{
    if (!createFile()) return;
    if (base) {
        m_traceFile << "> " << std::hex << base << "+";
    }
    m_traceFile
        << std::hex << rva
        << DELIMITER
        << "CPUID:"
        << std::hex << param
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logSyscall(const ADDRINT base, const ADDRINT rva, const ADDRINT param, const std::string& funcName)
{
    if (!createFile()) return;
    if (base) {
        m_traceFile << "> " << std::hex << base << "+";
    }
    m_traceFile
        << std::hex << rva
        << DELIMITER
        << "SYSCALL:0x"
        << std::hex << param;
    if (!funcName.empty()) {
        m_traceFile << "(" << funcName << ")";
    }
    m_traceFile << std::endl;
    m_traceFile.flush();
}

void TraceLog::logLine(std::string &str)
{
    if (!createFile()) return;

    m_traceFile
        << str
        << std::endl;
    m_traceFile.flush();
}

void TraceLog::logNewSectionCalled(const ADDRINT prevAddr, const std::string &prevSection, const std::string &currSection)
{
    createFile();
    m_traceFile
        << std::hex << prevAddr
        << DELIMITER
        << "[" << prevSection << "] -> [" << currSection << "]"
        << std::endl;
    m_traceFile.flush();
}
