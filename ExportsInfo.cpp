#include "ExportsInfo.h"

#include "mini_pe.h"
#include "ModuleInfo.h"

#include <iostream>
#include <vector>
#include <fstream>

namespace ExportsInfo {

    inline bool validate_ptr(const void* buffer_bgn, size_t buffer_size, const void* field_bgn, size_t field_size)
    {
        if (buffer_bgn == nullptr || field_bgn == nullptr) {
            return false;
        }
        BYTE* _start = (BYTE*)buffer_bgn;
        BYTE* _field_start = (BYTE*)field_bgn;
        if (_field_start < _start) {
            return false;
        }
        size_t start_delta = (BYTE*)_field_start - (BYTE*)_start;
        size_t area_size = start_delta + field_size;
        if (area_size > buffer_size) {
            return false;
        }
        if (area_size < field_size || area_size < start_delta) {
            return false;
        }
        return true;
    }

    inline bool manual_map(BYTE* image, size_t imgSize, BYTE* rawPE, size_t rawSize, PIMAGE_NT_HEADERS nt)
    {
        if (imgSize < nt->OptionalHeader.SizeOfHeaders || rawSize < nt->OptionalHeader.SizeOfHeaders) {
            return false;
        }
        ::memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);
        // map sections
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!validate_ptr(rawPE, rawSize, &section[i], sizeof(IMAGE_SECTION_HEADER))) {
                return false;
            }
            BYTE* vPtr = (BYTE*)(image)+section[i].VirtualAddress;
            BYTE* rPtr = (BYTE*)(rawPE)+section[i].PointerToRawData;
            const size_t secSize = section[i].SizeOfRawData;
            if (!validate_ptr(image, imgSize, vPtr, secSize) ||
                !validate_ptr(rawPE, rawSize, rPtr, secSize))
            {
                return false;
            }
            ::memcpy(vPtr, rPtr, secSize);
        }
        return true;
    }

    size_t loadPE(std::vector<char>& buffer, std::vector<char>& mapped)
    {
        BYTE* raw = (BYTE*)&buffer[0];
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(raw + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        size_t imgSize = nt->OptionalHeader.SizeOfImage;
        mapped.resize(imgSize);
        BYTE* image = (BYTE*)&mapped[0];
        if (!manual_map(image, mapped.size(), raw, buffer.size(), nt)) {
            return 0;
        }
        return imgSize;
    }


    size_t fillExports(IMG& img, const ADDRINT base, BYTE* mem, size_t mem_size)
    {
        size_t count = 0;
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mem);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(mem + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        IMAGE_DATA_DIRECTORY exportDirEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirEntry.VirtualAddress == 0) return 0;

        IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(mem + exportDirEntry.VirtualAddress);
        DWORD funcsListRVA = exportDir->AddressOfFunctions;
        DWORD funcNamesListRVA = exportDir->AddressOfNames;
        DWORD namesOrdsListRVA = exportDir->AddressOfNameOrdinals;
        DWORD namesCount = exportDir->NumberOfNames;

        for (DWORD i = 0; i < namesCount; i++) {
            DWORD* nameRVA = (DWORD*)((ADDRINT)mem + funcNamesListRVA + i * sizeof(DWORD));
            WORD* nameIndex = (WORD*)((ADDRINT)mem + namesOrdsListRVA + i * sizeof(WORD));
            DWORD* funcRVA = (DWORD*)((ADDRINT)mem + funcsListRVA + (*nameIndex) * sizeof(DWORD));

            if (!validate_ptr(mem, mem_size, nameRVA, sizeof(DWORD)) || 
                !validate_ptr(mem, mem_size, nameIndex, sizeof(WORD)) || 
                !validate_ptr(mem, mem_size, funcRVA, sizeof(DWORD)))
            {
                break;
            }
            ADDRINT funcVA = base + (*funcRVA);
            const char* name = reinterpret_cast<const char*>(mem + (*nameRVA));
            if (!name || !validate_ptr(mem, mem_size, name, sizeof(char))) {
                continue;
            }
            RTN rtn = RTN_FindByAddress(funcVA);
            if (RTN_Address(rtn) != funcVA) {
                RTN_CreateAt(funcVA, name);
            }
            count++;
        }
        return count;
    }

}; //ExportsInfo

size_t ExportsInfo::addFromFile(IMG& img)
{
    if (!IMG_Valid(img)) {
        return 0;
    }
    ADDRINT base = IMG_LoadOffset(img);
    if (base == 0) {
        base = IMG_LowAddress(img);
    }
    const std::string imagePath = IMG_Name(img);
    std::ifstream file(imagePath, std::ios::binary | std::ios::in);
    if (!file.is_open()) return 0;

    file.seekg(0, std::ios::end);

    const std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(fileSize);
    bool isOk = file.read(&buffer[0], fileSize);
    file.close();
    if (!isOk) return 0;

    std::vector<char> mapped;
    if (!loadPE(buffer, mapped)) return 0;

    BYTE* mem = (BYTE*)&mapped[0];
    return fillExports(img, base, mem, mapped.size());
}
