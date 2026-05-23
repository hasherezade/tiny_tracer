#include "SysUtil.h"

#ifdef _WIN32

#pragma comment(lib, "kernel32.lib")

// Minimal Win32 declarations to avoid pulling in Windows.h under PinCRT
extern "C" {

    typedef struct _MEMORY_BASIC_INFORMATION {
        void* BaseAddress;
        void* AllocationBase;
        unsigned long AllocationProtect;
        size_t        RegionSize;
        unsigned long State;
        unsigned long Protect;
        unsigned long Type;
    } MEMORY_BASIC_INFORMATION;

#define MEM_COMMIT                  0x1000
#define PAGE_NOACCESS               0x01
#define PAGE_READONLY               0x02
#define PAGE_READWRITE              0x04
#define PAGE_EXECUTE_READ           0x20
#define PAGE_EXECUTE_READWRITE      0x40
#define PAGE_WRITECOPY              0x08
#define PAGE_EXECUTE_WRITECOPY      0x80

    __declspec(dllimport) size_t __stdcall VirtualQuery(
        const void* lpAddress,
        MEMORY_BASIC_INFORMATION* lpBuffer,
        size_t dwLength
    );

} // extern "C"

#else
#include <cstdio>
#endif

#include "ModuleInfo.h"
#include "Util.h"

size_t getReadableMemSize(VOID* addr)
{
    const ADDRINT start = query_region_base((ADDRINT)addr);
    if (start == UNKNOWN_ADDR || start == 0) {
        return 0;
    }
#ifdef _WIN32
    // On Windows, use VirtualQuery
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(addr, &mbi, sizeof(mbi))) {
        return 0;
    }
    if (mbi.State != MEM_COMMIT) {
        return 0;
    }
    if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == 0) {
        return 0;
    }
    size_t memSize = mbi.RegionSize;
    const VOID* base = mbi.BaseAddress;
    if ((ADDRINT)addr < (ADDRINT)base || (ADDRINT)addr >= ((ADDRINT)base + memSize)) {
        return 0;
    }
    if (base != 0 && base < addr) {
        size_t pos = (ADDRINT)addr - (ADDRINT)base;
        memSize -= pos;
    }
    bool isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | 
                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                       PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
    return isReadable ? memSize : 0;
#else
    // On Linux, parse /proc/self/maps
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) {
        return 0;
    }

    const ADDRINT target_addr = (ADDRINT)addr;
    const long unsigned int target = static_cast<long unsigned int>(target_addr);
    size_t result = 0;
    char line[512] = { 0 };

    while (fgets(line, sizeof(line), f)) {
        long unsigned int regionStart = 0, regionEnd = 0;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &regionStart, &regionEnd, perms) != 3) {
            continue;
        }
        if (target >= regionStart && target < regionEnd) {
            if (perms[0] != 'r') {
                // not readable
                break;
            }
            result = (size_t)(regionEnd - target);
            break;
        }
    }
    fclose(f);
    return result;
#endif
}
