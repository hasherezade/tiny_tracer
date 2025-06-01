#include "ExportsInfo.h"

#include "mini_pe.h"
#include "ModuleInfo.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>

size_t walkExports(std::ofstream& fileStream, ADDRINT base, BYTE* mem)
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

        ADDRINT funcVA = base + (*funcRVA);
        const char* name = reinterpret_cast<const char*>(mem + (*nameRVA));
        fileStream << "\t" << std::hex << funcVA << " : " << (*funcRVA) << " : " << std::string(name) << "\n";
        count++;
    }
    return count;
}

inline void manual_map(BYTE* image, BYTE* rawPE, PIMAGE_NT_HEADERS nt)
{
    ::memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);

    // map sections
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        ::memcpy((BYTE*)(image)+section[i].VirtualAddress, (BYTE*)(rawPE)+section[i].PointerToRawData, section[i].SizeOfRawData);
    }
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
    manual_map(image, raw, nt);
    return imgSize;
}

size_t dumpFileExports(std::ofstream& fileStream, const IMG& img)
{
    if (!IMG_Valid(img)) {
        return 0;
    }
    ADDRINT base = IMG_LoadOffset(img);
    if (base == 0) {
        base = IMG_LowAddress(img);
    }
    const std::string imagePath = IMG_Name(img);
    fileStream << "Trying to open file: " << imagePath << std::endl;
    std::ifstream file(imagePath, std::ios::binary | std::ios::in);
    if (!file.is_open()) return 0;

    fileStream << "Opened file: " << imagePath << std::endl;

    file.seekg(0, std::ios::end);

    std::streamsize fileSize = file.tellg();
    fileStream << "File size: " << fileSize << std::endl;
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(fileSize);
    bool isOk = file.read(&buffer[0], fileSize);
    file.close();
    if (!isOk) return 0;

    fileStream << "Read file: " << imagePath << "\n";
    std::vector<char> mapped;
    if (!loadPE(buffer, mapped)) return 0;
    fileStream << "\n" << "---From-file EXPORTS---\n";
    BYTE* mem = (BYTE*)&mapped[0];
    size_t count = walkExports(fileStream, base, mem);
    fileStream << "\n" << "---END From-file EXPORTS---\n";
    return count;
}

size_t dumpModuleExports(std::ofstream& fileStream, IMG& img)
{
    ADDRINT base = IMG_LoadOffset(img);
    if (base == 0) {
        base = IMG_LowAddress(img);
    }
    size_t count = 0;
    BYTE* mem = reinterpret_cast<BYTE*>(base);
    std::stringstream ss;
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
    fileStream << "\n" << "---In-memory IMPORTS---\n";
    count = walkExports(fileStream, base, mem);
    fileStream << "\n" << "---END In-memory IMPORTS---\n";
    return count;
}

size_t dumpModuleSymbols(std::ofstream& fileStream, IMG& img)
{
    ADDRINT base = IMG_LoadOffset(img);
    if (base == 0) {
        base = IMG_LowAddress(img);
    }
    size_t count;
    fileStream << "\n" << "---SYMBOLS---\n";
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        const std::string name = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
        const ADDRINT offset = SYM_Value(sym);
        if (offset == UNKNOWN_ADDR) continue;
        RTN rtn = RTN_FindByAddress(base + offset);
        if (!RTN_Valid(rtn)) continue;
        fileStream << "\t" << std::hex << (base + offset) << " : " << offset << " : " << std::string(name) << "\n";
        count++;
    }
    fileStream << "\n" << "---END SYMBOLS---\n";
    return count;
}

///---


size_t ExportsLookup::fillExports(IMG& img, const ADDRINT base, const void* mod)
{
    BYTE* mem = (BYTE*)mod;
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

        ADDRINT funcVA = base + (*funcRVA);
        const char* name = reinterpret_cast<const char*>(mem + (*nameRVA));
        this->appendExport(funcVA, name);

        RTN rtn = RTN_FindByAddress(funcVA);
        if (RTN_Address(rtn) != funcVA) {
            RTN_CreateAt(funcVA, name);
        }
        count++;
    }
    return count;
}

size_t ExportsLookup::addFromFile(IMG& img)
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
    return fillExports(img, base, mem);
}
