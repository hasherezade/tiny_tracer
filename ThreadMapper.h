#pragma once

#include "pin.H"

#include "PinLocker.h"
#include "Settings.h"

#include <map>
#include <iostream>

class ThreadMapper
{
public:
    ThreadMapper()
        : m_LastTid(INVALID_THREADID)
    {
        PIN_InitLock(&m_Lock);
    }

    void setLastSpawningTid(const THREADID parentTid)
    {
        PinDataLock dLocker(&m_Lock);
        m_LastTid = parentTid;
    }

    void resetLastSpawningTid(const THREADID tid)
    {
        PinDataLock dLocker(&m_Lock);
        if (m_LastTid == tid) {
            m_LastTid = INVALID_THREADID;
        }
    }

    THREADID getLastSpawningTid()
    {
        PinDataLock dLocker(&m_Lock);
        return m_LastTid;
    }

    void eraseTid(const THREADID tid)
    {
        PinDataLock dLocker(&m_Lock);
        m_threadToParent.erase(tid);

        //erase thread from the mapping to OS thread:
        auto itr = m_PinTid_to_OsTid.find(tid);
        if (itr != m_PinTid_to_OsTid.end()) {
            m_OsTid_to_PinTid.erase(itr->second);
            m_PinTid_to_OsTid.erase(itr);
        }
    }

    void mapToOSTid(const THREADID tid, const OS_THREAD_ID os_tid)
    {
        PinDataLock dLocker(&m_Lock);
        m_PinTid_to_OsTid[tid] = os_tid;
        m_OsTid_to_PinTid[os_tid] = tid;
    }

    bool mapToParent(const THREADID tid)
    {
        PinDataLock dLocker(&m_Lock);
        if (m_LastTid == INVALID_THREADID) {
            return false;
        }
#ifdef _DEBUG
        std::cout << std::dec << "[M] ParentThread: " << m_LastTid << " created: " << tid << std::endl;
#endif //_DEBUG
        m_threadToParent[tid] = m_LastTid;
        m_LastTid = INVALID_THREADID;
        return true;
    }

    THREADID getParentTID(const THREADID tid)
    {
        PinDataLock dLocker(&m_Lock);
        THREADID parentTID = INVALID_THREADID;
#ifdef _WIN32
        const auto parentItr = m_threadToParent.find(tid);
        if (parentItr != m_threadToParent.end()) {
            parentTID = parentItr->second;
        }
#else
        const OS_THREAD_ID _parentTid = PIN_GetParentTid();
        if (m_OsTid_to_PinTid.find(_parentTid) != m_OsTid_to_PinTid.end()) {
            parentTID = m_OsTid_to_PinTid[_parentTid];
        }
#endif
        return parentTID;
    }

protected:
    PIN_LOCK m_Lock;
    THREADID m_LastTid;
    std::map<THREADID, THREADID> m_threadToParent;
    std::map<OS_THREAD_ID, THREADID> m_OsTid_to_PinTid;
    std::map<THREADID, OS_THREAD_ID> m_PinTid_to_OsTid;
};

/* ===================================================================== */

namespace TrackThreads
{
    ThreadMapper g_ThreadMapper;

    VOID OnThreadStarted(const THREADID tid)
    {
        //map OS TID to the internal one
        TrackThreads::g_ThreadMapper.mapToOSTid(tid, PIN_GetTid());
#ifdef _WIN32
        g_ThreadMapper.mapToParent(tid);
#endif //_WIN32
    }

    VOID OnThreadFinished(const THREADID tid)
    {
        g_ThreadMapper.eraseTid(tid);
    }

    THREADID GetParentTID(const THREADID tid)
    {
        return g_ThreadMapper.getParentTID(tid);
    }

#ifdef _WIN32
    VOID Watch_NtCreateThread_before(const ADDRINT Address, const THREADID tid)
    {
        PinLocker locker;
        g_ThreadMapper.setLastSpawningTid(tid);
#ifdef _DEBUG
        std::cout << "[!!!] Setting Parent Thread ID: " << std::dec << tid << std::endl;
#endif //_DEBUG
    }

    VOID Watch_NtCreateThread_after(const ADDRINT Address, const THREADID tid, ADDRINT status)
    {
        PinLocker locker;
#ifdef _DEBUG
        std::cout << "[!!!] Thread created by: TID: " << tid << " status: " << status << std::endl;
#endif //_DEBUG
        if (status != 0) {
            g_ThreadMapper.resetLastSpawningTid(tid);
        }
    }

    VOID InstrumentCreateThreadRoutines(IMG Image)
    {
        if (!IMG_Valid(Image)) return;

        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (!util::iequals(dllName, "ntdll")) {
            return;
        }
        const size_t functionsCount = 3;
        static const char* functions[functionsCount] = {
            "NtCreateThread",
            "NtCreateThreadEx",
            "RtlCreateUserThread"
        };
        for (size_t i = 0; i < functionsCount; i++)
        {
            const char* fName = functions[i];
            const RTN funcRtn = find_by_unmangled_name(Image, fName);
            if (RTN_Valid(funcRtn)) {
                RTN_Open(funcRtn);

                RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(Watch_NtCreateThread_before),
                    IARG_RETURN_IP,
                    IARG_THREAD_ID,

                    IARG_END
                );

                RTN_InsertCall(funcRtn, IPOINT_AFTER, AFUNPTR(Watch_NtCreateThread_after),
                    IARG_RETURN_IP,
                    IARG_THREAD_ID,
                    IARG_FUNCRET_EXITPOINT_VALUE, //NTSTATUS
                    IARG_END);
                RTN_Close(funcRtn);
            }
        }
    }

    //--

    inline bool isCreateThreadSyscall(ADDRINT syscallNum)
    {
        static const size_t functionsCount = 2;
        static const char* functions[functionsCount] = {
            "NtCreateThread",
            "NtCreateThreadEx"
        };

        if (syscallNum == UNKNOWN_ADDR) return false; //invalid
        syscallNum &= MAX_WORD;

        const std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
        if (!syscallFuncName.length()) return false;

        for (size_t i = 0; i < functionsCount; i++) {
            if (syscallFuncName.compare(functions[i]) == 0) {
                return true;
            }
        }
        return false;
    }

    VOID Watch_ThreadCreateSyscallBefore(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
    {
        PinLocker locker;

        const ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
        if (!isCreateThreadSyscall(syscallNum)) return;
        g_ThreadMapper.setLastSpawningTid(tid);
#ifdef _DEBUG
        std::cout << "S [!!!] Setting Parent Thread ID: " << std::dec << tid << std::endl;
#endif //_DEBUG
    }

    VOID Watch_ThreadCreateSyscallAfter(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
    {
        PinLocker locker;

        const ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
        if (!isCreateThreadSyscall(syscallNum)) return;

        const ADDRINT status = PIN_GetSyscallReturn(ctxt, std);
#ifdef _DEBUG
        std::cout << "S [!!!] Thread created by: TID: " << tid << " status: " << status << std::endl;
#endif //_DEBUG
        if (status != 0) {
            g_ThreadMapper.resetLastSpawningTid(tid);
        }
    }

    VOID InstrumentCreateThreadSyscalls()
    {
        PIN_AddSyscallEntryFunction(Watch_ThreadCreateSyscallBefore, NULL);
        PIN_AddSyscallExitFunction(Watch_ThreadCreateSyscallAfter, NULL);
    }
#endif //_WIN32
};
