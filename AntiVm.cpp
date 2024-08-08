#include "AntiVm.h"

#include <iostream>
#include <sstream>
#include <string>
#include <map>

#include "ProcessInfo.h"
#include "Util.h"
#include "TraceLog.h"
#include "Settings.h"
#include "PinLocker.h"
#include "TinyTracer.h"

#define ANTIVM_LABEL "[ANTIVM] --> "

using namespace LEVEL_PINCLIENT;

/* ================================================================== */
// Global variables used by AntiVm
/* ================================================================== */
#define PATH_BUFSIZE	 512
#define WMI_NUMBER_CORES "NUMBEROFCORES"
#define WMI_PROCESSOR    "PROCESSORID"
#define WMI_SIZE         "SIZE"
#define WMI_DEVICE_ID    "DEVICEID"
#define WMI_MAC_ADDRESS  "MACADDRESS"
#define WMI_TEMPERATURE  "CURRENTTEMPERATURE"
#define WMI_SERIAL       "SERIALNUMBER"
#define WMI_MODEL        "MODEL"
#define WMI_MANUFACTURER "MANUFACTURER"
#define WMI_GPU_ADAPTER  "ADAPTERCOMPATIBILITY"	
#define WMI_PRODUCT      "PRODUCT"
#define WMI_NAME         "NAME"

typedef VOID AntiVmCallBack(const ADDRINT addr, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6);

/* ==================================================================== */
// Log info with AntiVm label
/* ==================================================================== */

VOID LogAntiVm(const WatchedType wType, const ADDRINT Address, const char* msg, const char* link = nullptr)
{
    LogMsgAtAddress(wType, Address, ANTIVM_LABEL, msg, link);
}

/* ==================================================================== */
// Process API calls (related to AntiVm techniques)
/* ==================================================================== */

VOID AntiVm_WmiQueries(const ADDRINT addr, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6)
{   
    if (!argCount) return;

    PinLocker locker;
    const WatchedType wType = isWatchedAddress(addr);
    if (wType == WatchedType::NOT_WATCHED) return;

    const wchar_t* wmi_query = reinterpret_cast<const wchar_t*>(arg2);
    if (wmi_query == NULL) return;

    char wmi_query_field[PATH_BUFSIZE];
    GET_STR_TO_UPPER(wmi_query, wmi_query_field, PATH_BUFSIZE);

    if (util::iequals(wmi_query_field, WMI_NUMBER_CORES) || util::iequals(wmi_query_field, WMI_PROCESSOR)) {
        return LogAntiVm(wType, addr, "^ WMI query - number of CPU cores",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_SIZE)) {
        return LogAntiVm(wType, addr, "^ WMI query - hard disk size",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_DEVICE_ID)) {
        return LogAntiVm(wType, addr, "^ WMI query - device ID",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_MAC_ADDRESS)) {
        return LogAntiVm(wType, addr, "^ WMI query - MAC address",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_TEMPERATURE)) {
        return LogAntiVm(wType, addr, "^ WMI query - system temperatures",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_SERIAL)) {
        return LogAntiVm(wType, addr, "^ WMI query - BIOS serial number",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_MODEL) || util::iequals(wmi_query_field, WMI_MANUFACTURER)) {
        return LogAntiVm(wType, addr, "^ WMI query - system model and/or manufacturer",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_GPU_ADAPTER)) {
        return LogAntiVm(wType, addr, "^ WMI query - video controller adapter",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
    else if (util::iequals(wmi_query_field, WMI_PRODUCT) || util::iequals(wmi_query_field, WMI_NAME)) {
        return LogAntiVm(wType, addr, "^ WMI query - system device names",
            "https://evasions.checkpoint.com/techniques/wmi.html#generic-wmi-queries");
    }
}

/* ==================================================================== */
// Add single hooking function
/* ==================================================================== */

bool AntiVmAddCallbackBefore(IMG Image, char* fName, uint32_t argNum, AntiVmCallBack callback)
{
    const size_t argMax = 6;
    if (argNum > argMax) argNum = argMax;

    RTN funcRtn = RTN_FindByName(Image, fName);
    if (RTN_Valid(funcRtn)) {
        RTN_Open(funcRtn);

        RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(callback),
            IARG_RETURN_IP,
            IARG_ADDRINT, fName,
            IARG_UINT32, argNum,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
            IARG_END
        );

        RTN_Close(funcRtn);
        return true;
    }

    return false;
}

/* ==================================================================== */
// Add to monitored functions all the API calls or WMI queries needed for AntiVM.
// Called by ImageLoad
/* ==================================================================== */

VOID AntiVm::MonitorAntiVmFunctions(IMG Image)
{
    // API needed to trace WMI queries
    const std::string dllName = util::getDllName(IMG_Name(Image));
    if (util::iequals(dllName, "fastprox")) {
#ifdef _WIN64
        AntiVmAddCallbackBefore(Image, "?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z", 6, AntiVm_WmiQueries);
#else
        AntiVmAddCallbackBefore(Image, "?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z", 6, AntiVm_WmiQueries);
#endif
    }
}

std::map<THREADID, ADDRINT> cpuidThreads;
#define CLEAR_CPUID_HYPERVISOR
VOID AntiVm::CpuidCheck(CONTEXT* ctxt, THREADID tid)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    ADDRINT opId = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
#ifdef CLEAR_CPUID_HYPERVISOR
    cpuidThreads[tid] = opId;
#endif
    if (opId == 0x0) {
        return LogAntiVm(wType, Address, "CPUID - vendor check",
            "https://unprotect.it/technique/cpuid/");
    }
    if (opId == 0x1) {
        return LogAntiVm(wType, Address, "CPUID - HyperVisor bit check",
            "https://unprotect.it/technique/cpuid/");
    }
    if (opId == 0x80000002 || opId == 0x80000003 || opId == 0x80000004) {
        return LogAntiVm(wType, Address, "CPUID - brand check",
            "https://unprotect.it/technique/cpuid/");
    }
    if (opId == 0x40000000) {
        return LogAntiVm(wType, Address, "CPUID - HyperVisor vendor check",
            "https://unprotect.it/technique/cpuid/");
    }
    if (opId == 0x40000002) {
        return LogAntiVm(wType, Address, "CPUID - HyperVisor system identity");
    }
    if (opId == 0x40000003) {
        return LogAntiVm(wType, Address, "CPUID - HyperVisor feature identification");
    }
}

namespace AntiVm
{

    BOOL _AlterCpuidValue(CONTEXT* ctxt, THREADID tid, const REG reg, ADDRINT& regVal)
    {
        BOOL isSet = FALSE;
        const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

        const WatchedType wType = isWatchedAddress(Address);
        if (wType == WatchedType::NOT_WATCHED) return FALSE;

        auto itr = cpuidThreads.find(tid);
        if (itr == cpuidThreads.end()) return FALSE;

        const ADDRINT opId = itr->second;
        std::stringstream ss;
        ss << "CPUID - HyperVisor res:" << std::hex;
        if (opId == 0x1) {
            if (reg == REG_GCX) {
                ss << " ECX: " << regVal;
                ADDRINT hv_bit = (ADDRINT)0x1 << 31;
                regVal &= ~hv_bit;
            }
            isSet = TRUE;
        }
        if (opId == 0x40000000) {
            //GenuineIntel
            // 47 65 6E 75 | 69 6E 65 49 | 6E 74 65 6C
            if (reg == REG_GAX) {
                ss << " EAX: " << regVal;
            } else if (reg == REG_GBX) {
                ss << " EBX: " << regVal;
                regVal = 0x7263694d;
            } else if (reg == REG_GCX) {
                ss << " ECX: " << regVal;
                regVal = 0x666f736f;
            } else if (reg == REG_GDX) {
                ss << " EDX: " << regVal;
                regVal = 0x76482074;
            }
            isSet = TRUE;
        }
        else if (opId == 0x40000003) {
            if (reg == REG_GAX) {
                ss << " EAX: " << regVal;
                regVal = 0x3fff;
            } else if (reg == REG_GBX) {
                ss << " EBX: " << regVal;
                regVal = 0x2bb9ff;
            } else if (reg == REG_GCX) {
                ss << " ECX: " << regVal;
                regVal = 0;
            } else if (reg == REG_GDX) {
                ss << " EDX: " << regVal;
                regVal = 0;
            }
            isSet = TRUE;
        }
        if (isSet && ss.str().length()) {
            LogAntiVm(wType, Address, ss.str().c_str());
        }
        return isSet;
    }

    ADDRINT AlterCpuidValue(CONTEXT* ctxt, THREADID tid, const REG reg)
    {
        PinLocker locker;
        ADDRINT regVal = PIN_GetContextReg(ctxt, reg);
        _AlterCpuidValue(ctxt, tid, reg, regVal);
        return regVal;
    }

}; //namespace AntiVm


ADDRINT AntiVm::AlterCpuidValueEax(CONTEXT* ctxt, THREADID tid)
{
    return AlterCpuidValue(ctxt, tid, REG_GAX);
}

ADDRINT AntiVm::AlterCpuidValueEbx(CONTEXT* ctxt, THREADID tid)
{
    return AlterCpuidValue(ctxt, tid, REG_GBX);
}

ADDRINT AntiVm::AlterCpuidValueEcx(CONTEXT* ctxt, THREADID tid)
{
    return AlterCpuidValue(ctxt, tid, REG_GCX);
}

ADDRINT AntiVm::AlterCpuidValueEdx(CONTEXT* ctxt, THREADID tid)\
{
    return AlterCpuidValue(ctxt, tid, REG_GDX);
}
