#include "TraceLog.h"

#include "Util.h"
#include <sstream>

void TraceLog::logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string &module, const std::string &func)
{
    std::stringstream ss;
    ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
    if (!isRVA) {
        ss << "> " << prevModuleBase << "+";
    }
    ss <<
        std::hex << rva
        << DELIMITER;

    if (!m_shortLog) {
        ss << "called: "
            << module;
    }
    else {
        ss << util::getDllName(module);
    }
    if (func.length() > 0) {
        ss << "." << func;
    }
    logLine(ss.str());
}

void TraceLog::logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr)
{
    std::stringstream ss;
    if (prevBase) {
        ss << "> " << prevBase << "+";
    }
    const ADDRINT rva = callAddr - calledPageBase;
    ss <<
        std::hex << prevAddr
        << DELIMITER
        << "called: ?? [" << calledPageBase << "+" << rva << "]";
    logLine(ss.str());
}

void TraceLog::logCallRet(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT retPageBase, const ADDRINT retAddr, const std::string &module, const std::string &func)
{
    std::stringstream ss;
    ADDRINT retRva = retAddr;
    if (retPageBase) {
        retRva -= retPageBase;
        ss << "> " << retPageBase << "+";
    }
    ss
        << std::hex << retRva
        << DELIMITER
        << "RET from: "
        << "[" << prevBase << "+" << prevAddr << "] -> "
        << util::getDllName(module);

    if (func.length() > 0) {
        ss << "." << func;
    }
    logLine(ss.str());
}


void TraceLog::logSectionChange(const ADDRINT prevAddr, std::string &name)
{
    std::stringstream ss;
    ss
        << std::hex << prevAddr 
        << DELIMITER 
        << "section: [" << name << "]";
    logLine(ss.str());
}

void TraceLog::logIndirectCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const ADDRINT calledBase, const ADDRINT calledRVA, const char* disasm)
{
    std::stringstream ss;
    ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
    if (!isRVA) {
        ss << "> " << prevModuleBase << "+";
    }
    ss
        << std::hex << rva
        << DELIMITER;
    if (disasm) {
        ss << "[" << disasm << "] ";
    }
    ss << "to: " << (calledBase + calledRVA) << " [" << calledBase << " + " << calledRVA << "]";
    logLine(ss.str());
}

void TraceLog::logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem, const ADDRINT param)
{
    std::stringstream ss;
    if (base) {
        ss << "> " << std::hex << base << "+";
    }
    ss
        << std::hex << rva
        << DELIMITER
        << mnem << ":"
        << std::hex << param;
    logLine(ss.str());
}

void TraceLog::logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem)
{
    std::stringstream ss;
    if (base) {
        ss << "> " << std::hex << base << "+";
    }
    ss
        << std::hex << rva
        << DELIMITER
        << mnem;
    logLine(ss.str());
}

void TraceLog::logSyscall(const ADDRINT base, const ADDRINT rva, const ADDRINT param, const std::string& funcName)
{
    std::stringstream ss;
    if (base) {
        ss << "> " << std::hex << base << "+";
    }
    ss
        << std::hex << rva
        << DELIMITER
        << "SYSCALL:0x"
        << std::hex << param;
    if (!funcName.empty()) {
        ss << "(" << funcName << ")";
    }
    logLine(ss.str());
}

void TraceLog::logLine(const std::string& str)
{
    if (!createFile()) return;

    m_traceFile << str << std::endl;
    autoFlush();
}

void TraceLog::logNewSectionCalled(const ADDRINT prevAddr, const std::string &prevSection, const std::string &currSection)
{
    std::stringstream ss;
    ss
        << std::hex << prevAddr
        << DELIMITER
        << "[" << prevSection << "] -> [" << currSection << "]";
    logLine(ss.str());
}
