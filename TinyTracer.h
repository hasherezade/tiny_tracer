#pragma once

#include "pin.H"

#include "TraceLog.h"
#include "Settings.h"
#include <string>

extern Settings m_Settings;
extern TraceLog traceLog;

enum class WatchedType {
    NOT_WATCHED = 0,
    WATCHED_MY_MODULE,
    WATCHED_SHELLCODE
};

WatchedType isWatchedAddress(const ADDRINT Address);
std::wstring paramToStr(VOID* arg1);
size_t getReadableMemSize(VOID* ptr);
BOOL isValidReadPtr(VOID* arg1);
BOOL fetchInterruptID(const ADDRINT Address, int& intID);

VOID LogMsgAtAddress(const WatchedType wType, const ADDRINT Address, const char* label, const char* msg, const char* link=nullptr);
