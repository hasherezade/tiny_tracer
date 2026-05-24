#pragma once
#include "pin.H"

#include <iostream>
#include <fstream>
#include <chrono>

class TraceLog 
{
public:
    static const char DELIMITER = ';';

    TraceLog()
        : m_firstFlush(true)
    {
    }

    ~TraceLog()
    {
        if (m_traceFile.is_open()) {
            m_traceFile.close();
        }
    }

    void init(const std::string &fileName, bool is_short)
    {
        m_logFileName = (fileName.empty()) ? "output.txt" : fileName;
        m_shortLog = is_short;
        createFile(true);
    }

    void logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string &module, const std::string &func = "");
    void logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr);
    void logCallRet(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT retPageBase, const ADDRINT retAddr, const std::string &module, const std::string &func);
    void logSectionChange(const ADDRINT addr, std::string &sectionName);
    void logNewSectionCalled(const ADDRINT addFrom, const std::string &prevSection, const std::string &currSection);
    void logIndirectCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const ADDRINT calledBase, const ADDRINT callRVA, const char* disasm);
    void logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem, const ADDRINT param);
    void logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem);
    void logSyscall(const ADDRINT base, const ADDRINT rva, const ADDRINT param, const std::string &funcName);

    void logLine(const std::string &str);

protected:

    bool createFile(bool reset = false)
    {
        if (m_traceFile.is_open()) {
            return true;
        }
        auto mode = std::ios::out;
        if (!reset) {
            mode |= std::ios::app;
        }
        m_traceFile.open(m_logFileName.c_str(), mode);
        if (m_traceFile.is_open()) {
            return true;
        }
        return false;
    }

    bool maybeFlush()
    {
        auto now = std::chrono::steady_clock::now();

        if (m_firstFlush ||
            std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastFlushTime) >= m_flushInterval)
        {
            m_traceFile.flush();
            m_lastFlushTime = now;
            m_firstFlush = false;
            return true;
        }
        return false;
    }

    void autoFlush(bool close = true)
    {
        if (!m_traceFile.is_open()) {
            return;
        }
        const bool isFlushed = maybeFlush();
        if (isFlushed && close) {
            m_traceFile.close();
        }
    }

    std::chrono::steady_clock::time_point m_lastFlushTime;
    std::chrono::milliseconds m_flushInterval{ 200 };
    bool m_firstFlush;

    std::string m_logFileName;
    std::ofstream m_traceFile;
    bool m_shortLog;
};
