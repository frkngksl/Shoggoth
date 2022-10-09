#include "APISolver.h"

unsigned long UnicodeDjb2(const wchar_t* str);
unsigned long XorHash(unsigned long hash);
unsigned long djb2(unsigned char* str);

// custom strcmp function since this function will be called by GetSymbolAddress
// which means we have to call strcmp before loading msvcrt.dll
// so we are writing our own my_strcmp so that we don't have to play with egg or chicken dilemma
int MyStrCmp(const char* p1, const char* p2) {
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
            return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

UINT64 FollowExport(char* ptr_forward, LPCSTR lpProcName) {
    UINT64 kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32);
    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    LOADLIBRARYA loadLibraryAFunc = (LOADLIBRARYA)GetSymbolAddress(kernel32DLL, loadLibraryAString);
    UINT64 shlwapiDLL = GetLoadedLibrary(CRYPTED_HASH_SHLWAPIDLL);
    if (shlwapiDLL == 0) {
        CHAR shlwapiDLLString[] = { 's','h','l','w','a','p','i','.','d','l','l',0x00 };
        loadLibraryAFunc(shlwapiDLLString);
        shlwapiDLL = GetLoadedLibrary(CRYPTED_HASH_SHLWAPIDLL);
    }
    CHAR strStrAString[] = { 'S', 't', 'r', 'S', 't', 'r', 'A', 0 };
    STRSTRA _StrStrA = (STRSTRA)GetSymbolAddress(shlwapiDLL, strStrAString);

    char del[] = { '.', 0x00 };
    char* pos_del = 0x00;
    char forward_dll[MAX_PATH] = { 0 };
    char forward_export[MAX_PATH] = { 0 };
    uint8_t i = 0;
    uint64_t fwd_dll_base = 0x00, forwarded_export = 0x00;

    while (*ptr_forward)
        forward_dll[i++] = *ptr_forward++;

    pos_del = (char*)_StrStrA(forward_dll, del);
    if (pos_del == 0)
        return 0;

    *(char*)(pos_del++) = 0x00;
    i = 0;
    while (*pos_del)
        forward_export[i++] = *pos_del++;


    fwd_dll_base = GetLoadedLibrary(XorHash(djb2((unsigned char*)forward_dll)));
    if (fwd_dll_base == 0x00) {
        fwd_dll_base = (uint64_t) loadLibraryAFunc(forward_dll);
        if (fwd_dll_base == 0x00)
            return 0;
    }

    forwarded_export = GetSymbolAddress(fwd_dll_base, forward_export);

    return forwarded_export;

}


UINT64 GetSymbolAddress(UINT64 dllAddress, LPCSTR lpProcName) {
    UINT64 symbolAddress = 0;
    PDWORD exportedAddressTable = 0;
    PDWORD namePointerTable = 0;
    PWORD ordinalTable = 0;
    UINT64 exportDirectoryRVA = 0;
    DWORD exportTableSize = 0;

    if (dllAddress == 0) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
    char* functionName;
    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dllAddress)->e_lfanew);
    exportDirectoryRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exportTableSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + exportDirectoryRVA);

    exportedAddressTable = (PDWORD)(dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (PDWORD)(dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (PWORD)(dllAddress + exportDirectory->AddressOfNameOrdinals);

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {

        functionName = (char*)dllAddress + (namePointerTable[i]);
        if (MyStrCmp(functionName, lpProcName) == 0) {

            WORD nameord = ordinalTable[i];
            DWORD rva = exportedAddressTable[nameord];

            //Still points to export table
            if (dllAddress + rva >= dllAddress + exportDirectoryRVA && dllAddress + rva <= dllAddress + exportDirectoryRVA + exportTableSize) {
                // This is a forwarded export

                // Normally it should be address, but it points to a name
                char* ptr_forward = (char*)(dllAddress + rva);
                return FollowExport(ptr_forward, lpProcName);

            }


            return dllAddress + rva;
        }
    }
    return symbolAddress;
}


unsigned long XorHash(unsigned long hash) {
    return hash ^ CRYPT_KEY;
}


static WCHAR* ToLower(WCHAR* str){
    WCHAR* start = str;

    while (*str) {
        if (*str <= L'Z' && *str >= 'A') {
            *str += 32;
        }
        str += 1;
    }
    return start;
}

unsigned long UnicodeDjb2(const wchar_t* str){

    unsigned long hash = 5381;
    DWORD val;

    while (*str != 0) {
        val = (DWORD)*str++;
        hash = ((hash << 5) + hash) + val;
    }

    return hash;

}

unsigned long djb2(unsigned char* str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

// function to fetch the base address of kernel32.dll from the Process Environment Block
UINT64 GetLoadedLibrary(unsigned long hash) {
    PLDR_DATA_TABLE_ENTRY cursorLoadedModules,startEntry;
    PUNICODE_STR dllName = NULL;
    // Get PEB ptr
    _PPEB PEBPtr = (_PPEB) __readgsqword(0x60);
    // Circular linked list
    cursorLoadedModules = startEntry = (PLDR_DATA_TABLE_ENTRY)(PEBPtr->pLdr->InMemoryOrderModuleList.Flink);
    do {
        dllName = &(cursorLoadedModules->BaseDllName);

        if (UnicodeDjb2(ToLower(dllName->pBuffer)) == XorHash(hash)) {
            return (uint64_t)cursorLoadedModules->DllBase;
        }
        cursorLoadedModules = (PLDR_DATA_TABLE_ENTRY)cursorLoadedModules->InMemoryOrderModuleList.Flink;
    } while (cursorLoadedModules && startEntry != cursorLoadedModules);
    return 0;
}
