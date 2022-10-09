/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <windows.h>
#include "APISolver.h"
#include "BeaconFunctions.h"


void SetFileSharingAddress(LPVOID beacon_compatibility_output,int beacon_compatibility_size,int beacon_compatibility_offset,int flagFirstTime){
    HANDLE hMapFile;
    LPCTSTR pBuf;
    CHAR sharedMemoryName[] = { 'S','h','a','r','e','d','S','h','o','g','g','o','t','h',0x00 };
    UINT64 kernel32DLL;
    UINT64 createFileMappingAFunc, mapViewOfFileFunc, openFileMappingAFunc, closeHandleFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR createFileMappingAString[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'M', 'a', 'p','p','i','n','g', 'A', 0 };
    createFileMappingAFunc = GetSymbolAddress(kernel32DLL, createFileMappingAString);

    CHAR mapViewOfFileString[] = { 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', 0 };
    mapViewOfFileFunc = GetSymbolAddress(kernel32DLL, mapViewOfFileString);

    CHAR openFileMappingAString[] = { 'O', 'p', 'e', 'n', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'A' , 0 };
    openFileMappingAFunc = GetSymbolAddress(kernel32DLL, openFileMappingAString);

    CHAR closeHandleString[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    closeHandleFunc = GetSymbolAddress(kernel32DLL, closeHandleString);


    if (flagFirstTime) {
        hMapFile = ((CREATEFILEMAPPINGA)createFileMappingAFunc)(
            INVALID_HANDLE_VALUE,    // use paging file
            NULL,                    // default security
            PAGE_READWRITE,          // read/write access
            0,                       // maximum object size (high-order DWORD)
            256,                // maximum object size (low-order DWORD)
            sharedMemoryName);                 // name of mapping object
    }
    else {
        hMapFile = ((OPENFILEMAPPINGA) openFileMappingAFunc)(
            FILE_MAP_ALL_ACCESS,   // read/write access
            FALSE,                 // do not inherit the name
            sharedMemoryName);
    }

    if (hMapFile == NULL)
    {
        return;
    }
    pBuf = (LPTSTR)((MAPVIEWOFFILE) mapViewOfFileFunc)(hMapFile,   // handle to map object
        FILE_MAP_ALL_ACCESS, // read/write permission
        0,
        0,
        256);

    if (pBuf == NULL)
    {

        ((CLOSEHANDLE) closeHandleFunc)(hMapFile);

        return;
    }


    MyMemCpy((PBYTE) pBuf,(PBYTE) &beacon_compatibility_output, sizeof(LPVOID));
    MyMemCpy((PBYTE) pBuf+sizeof(LPVOID), (PBYTE) &beacon_compatibility_size, sizeof(int));
    MyMemCpy((PBYTE) pBuf+sizeof(LPVOID)+sizeof(int), (PBYTE) &beacon_compatibility_offset, sizeof(int));
    if (!flagFirstTime) {
        ((CLOSEHANDLE)closeHandleFunc)(hMapFile);
    }
}


void GetFileSharingAddress(LPVOID *beacon_compatibility_output, int *beacon_compatibility_size, int *beacon_compatibility_offset) {
    CHAR sharedMemoryName[] = { 'S','h','a','r','e','d','S','h','o','g','g','o','t','h',0x00 };
    HANDLE hMapFile;
    PBYTE pBuf;
    UINT64 kernel32DLL;
    UINT64 mapViewOfFileFunc, openFileMappingAFunc, closeHandleFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR openFileMappingAString[] = { 'O', 'p', 'e', 'n', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'A' , 0 };
    openFileMappingAFunc = GetSymbolAddress(kernel32DLL, openFileMappingAString);

    CHAR mapViewOfFileString[] = { 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', 0 };
    mapViewOfFileFunc = GetSymbolAddress(kernel32DLL, mapViewOfFileString);

    CHAR closeHandleString[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    closeHandleFunc = GetSymbolAddress(kernel32DLL, closeHandleString);


    hMapFile = ((OPENFILEMAPPINGA)openFileMappingAFunc)(
        FILE_MAP_ALL_ACCESS,   // read/write access
        FALSE,                 // do not inherit the name
        sharedMemoryName);               // name of mapping object

    if (hMapFile == NULL)
    {
        return;
    }

    pBuf = (PBYTE)((MAPVIEWOFFILE)mapViewOfFileFunc)(hMapFile, // handle to map object
        FILE_MAP_READ,  // read/write permission
        0,
        0,
        256);

    if (pBuf == NULL)
    {
        ((CLOSEHANDLE)closeHandleFunc)(hMapFile);
        return;
    }

    MyMemCpy((PBYTE)beacon_compatibility_output, pBuf, sizeof(LPVOID));
    MyMemCpy((PBYTE)beacon_compatibility_size, pBuf + sizeof(LPVOID), sizeof(int));
    MyMemCpy((PBYTE)beacon_compatibility_offset, pBuf + sizeof(LPVOID) + sizeof(int), sizeof(int));
    ((CLOSEHANDLE)closeHandleFunc)(hMapFile);

}


uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}


void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    MyMemCpy((PBYTE) &fourbyteint, (PBYTE) parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    MyMemCpy((PBYTE) &retvalue,(PBYTE) parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    MyMemCpy((PBYTE) &length, (PBYTE) parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc,callocFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);


    CHAR callocString[] = { 'c', 'a', 'l', 'l', 'o', 'c', 0 };
    callocFunc = GetSymbolAddress(msvcrtDLL, callocString);

    format->original = ((CALLOC) callocFunc)(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    PBYTE cursor = (PBYTE) format->original;
    for (int i = 0; i < format->size; i++) {
        cursor[i] = 0;
    }
    format->buffer = format->original;
    format->length = format->size;
    return;
}

void BeaconFormatFree(formatp* format) {
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, freeFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);


    CHAR freeString[] = { 'f', 'r', 'e', 'e', 0 };
    freeFunc = GetSymbolAddress(msvcrtDLL, freeString);
    if (format == NULL) {
        return;
    }
    if (format->original) {
        ((FREE)freeFunc)(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    MyMemCpy((PBYTE) format->buffer,(PBYTE) text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    /*Take format string, and sprintf it into here*/
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, vsnprintfFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    //CHAR va_startString[] = { 'v', 'a', '_', 's', 't','a','r','t',0};
    //va_startFunc = GetSymbolAddress(msvcrtDLL, va_startString);

    //CHAR va_endString[] = { 'v', 'a', '_','e','n','d',0 };
    //va_endFunc = GetSymbolAddress(msvcrtDLL, va_endString);

    CHAR vsnprintfString[] = { 'v', 's','n', 'p','r','i','n','t','f',0};
    vsnprintfFunc = GetSymbolAddress(msvcrtDLL, vsnprintfString);

    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = ((VSNPRINTF) vsnprintfFunc)(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)((VSNPRINTF)vsnprintfFunc)(format->buffer, length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    MyMemCpy((PBYTE) format->buffer,(PBYTE) &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    /* Change to maintain internal buffer, and return after done running. */
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, vsnprintfFunc, vprintfFunc, reallocFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    //CHAR va_startString[] = { 'v', 'a', '_', 's', 't','a','r','t',0};
    //va_startFunc = GetSymbolAddress(msvcrtDLL, va_startString);

    //CHAR va_endString[] = { 'v', 'a', '_','e','n','d',0 };
    //va_endFunc = GetSymbolAddress(msvcrtDLL, va_endString);

    CHAR vsnprintfString[] = { 'v', 's','n', 'p','r','i','n','t','f',0 };
    vsnprintfFunc = GetSymbolAddress(msvcrtDLL, vsnprintfString);

    CHAR vprintfString[] = { 'v', 'p','r','i','n','t','f',0 };
    vprintfFunc = GetSymbolAddress(msvcrtDLL, vprintfString);

    CHAR reallocString[] = { 'r', 'e','a','l','l','o','c',0 };
    reallocFunc = GetSymbolAddress(msvcrtDLL, reallocString);

    char* beacon_compatibility_output = NULL;
    int beacon_compatibility_size = 0;
    int beacon_compatibility_offset = 0;
    int length = 0;
    char* tempptr = NULL;
    va_list args;
    va_start(args, fmt);
    ((VPRINTF) vprintfFunc)(fmt, args);
    va_end(args);

    va_start(args, fmt);
    length = ((VSNPRINTF) vsnprintfFunc)(NULL, 0, fmt, args);
    va_end(args);
    GetFileSharingAddress((LPVOID *)&beacon_compatibility_output, &beacon_compatibility_size, &beacon_compatibility_offset);
    tempptr = ((REALLOC) reallocFunc)(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    PBYTE cursor = (PBYTE) (beacon_compatibility_output + beacon_compatibility_offset);
    for (int i = 0; i < length + 1; i++) {
        cursor[i] = 0;
    }
    va_start(args, fmt);
    length = ((VSNPRINTF) vsnprintfFunc)(beacon_compatibility_output + beacon_compatibility_offset, length, fmt, args);
    beacon_compatibility_size += length;
    beacon_compatibility_offset += length;
    va_end(args);
    SetFileSharingAddress(beacon_compatibility_output, beacon_compatibility_size, beacon_compatibility_offset,0);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, reallocFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    //CHAR va_startString[] = { 'v', 'a', '_', 's', 't','a','r','t',0};
    //va_startFunc = GetSymbolAddress(msvcrtDLL, va_startString);

    //CHAR va_endString[] = { 'v', 'a', '_','e','n','d',0 };
    //va_endFunc = GetSymbolAddress(msvcrtDLL, va_endString);

    CHAR reallocString[] = { 'r', 'e','a','l','l','o','c',0 };
    reallocFunc = GetSymbolAddress(msvcrtDLL, reallocString);

    char* tempptr = NULL;
    char* beacon_compatibility_output = NULL;
    int beacon_compatibility_size = 0;
    int beacon_compatibility_offset = 0;
    GetFileSharingAddress((LPVOID *)&beacon_compatibility_output, &beacon_compatibility_size, &beacon_compatibility_offset);

    tempptr = ((REALLOC) reallocFunc)(beacon_compatibility_output, beacon_compatibility_size + len + 1);
    beacon_compatibility_output = tempptr;
    if (tempptr == NULL) {
        return;
    }
    PBYTE cursor = (PBYTE) (beacon_compatibility_output + beacon_compatibility_offset);
    for (int i = 0; i < len + 1; i++) {
        cursor[i] = 0;
    }
    MyMemCpy((PBYTE) (beacon_compatibility_output + beacon_compatibility_offset), (PBYTE) data, len);
    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;
    SetFileSharingAddress(beacon_compatibility_output, beacon_compatibility_size, beacon_compatibility_offset,0);
    return;
}

/* Token Functions */

BOOL BeaconUseToken(HANDLE token) {
    UINT64 kernel32DLL,advapi32DLL;
    UINT64 setThreadTokenFunc, loadLibraryAFunc;
    /* Probably needs to handle DuplicateTokenEx too */
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return FALSE;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR advapi32DllString[] = { 'A', 'd', 'v', 'a', 'p', 'i','3','2', '.', 'd', 'l', 'l', 0};
    advapi32DLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(advapi32DllString);

    CHAR setThreadTokenString[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'k','e','n', 0};
    setThreadTokenFunc = GetSymbolAddress(advapi32DLL, setThreadTokenString);
    ((SETTHREADTOKEN)setThreadTokenFunc)(NULL, token);
    return TRUE;
}

void BeaconRevertToken(void) {
    UINT64 kernel32DLL, advapi32DLL;
    UINT64 revertToSelfFunc, loadLibraryAFunc;
    /* Probably needs to handle DuplicateTokenEx too */
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR advapi32DllString[] = { 'A', 'd', 'v', 'a', 'p', 'i','3','2', '.', 'd', 'l', 'l', 0 };
    advapi32DLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(advapi32DllString);

    CHAR revertToSelfFuncString[] = { 'R', 'e', 'v', 'e', 'r', 't', 'T', 'o', 'S', 'e', 'l', 'f', 0 };
    revertToSelfFunc = GetSymbolAddress(advapi32DLL, revertToSelfFuncString);

    if (!((REVERTTOSELF)revertToSelfFunc)()) {
    }
    return;
}

BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    char tempBufferPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','r','u','n','d','l','l','3','2','.','d','l','l',0x00 };
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 closeHandleFunc, strlenFunc, loadLibraryAFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }
    CHAR closeHandleString[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    closeHandleFunc = GetSymbolAddress(kernel32DLL, closeHandleString);

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    CHAR strlenString[] = { 's', 't', 'r', 'l', 'e', 'n', 0 };
    strlenFunc = GetSymbolAddress(msvcrtDLL, strlenString);

    if (buffer == NULL) {
        return;
    }
    else {
        if (((CLOSEHANDLE)closeHandleFunc)(tempBufferPath) > length) {
            return;
        }
        MyMemCpy((PBYTE) buffer, (PBYTE) tempBufferPath, ((STRLEN) strlenFunc)(tempBufferPath));

    }
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo) {
    char tempBufferPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','r','u','n','d','l','l','3','2','.','d','l','l',0x00 };
    UINT64 kernel32DLL;
    UINT64 createProcessAFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return 0;
    }
    CHAR createProcessAString[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e','s','s','A', 0};
    createProcessAFunc = GetSymbolAddress(kernel32DLL, createProcessAString);
    BOOL bSuccess = ((CREATEPROCESSA)createProcessAFunc)(NULL, tempBufferPath, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    UINT64 kernel32DLL;
    UINT64 closeHandleFunc;
    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }
    CHAR closeHandleString[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    closeHandleFunc = GetSymbolAddress(kernel32DLL, closeHandleString);
    (void)((CLOSEHANDLE) closeHandleFunc)(pInfo->hThread);
    (void)((CLOSEHANDLE)closeHandleFunc)(pInfo->hProcess);
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

char* BeaconGetOutputData(int* outsize) {
    char* beacon_compatibility_output = NULL;
    int beacon_compatibility_size = 0;
    int beacon_compatibility_offset = 0;
    GetFileSharingAddress((LPVOID *)&beacon_compatibility_output, &beacon_compatibility_size, &beacon_compatibility_offset);
    char* outdata = beacon_compatibility_output;
    if (outsize)
        *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    SetFileSharingAddress(beacon_compatibility_output, beacon_compatibility_size, beacon_compatibility_offset,0);
    return outdata;
}

void SetInternalFunctions(char **internalAddressArray){

  internalAddressArray[0] = (char*)BeaconDataParse;
  internalAddressArray[1] = (char*)BeaconDataInt;
  internalAddressArray[2] = (char*)BeaconDataShort;
  internalAddressArray[3] = (char*)BeaconDataLength;
  internalAddressArray[4] = (char*)BeaconDataExtract;
  internalAddressArray[5] = (char*)BeaconFormatAlloc;
  internalAddressArray[6] = (char*)BeaconFormatReset;
  internalAddressArray[7] = (char*)BeaconFormatFree;
  internalAddressArray[8] = (char*)BeaconFormatAppend;
  internalAddressArray[9] = (char*)BeaconFormatPrintf;
  internalAddressArray[10] = (char*)BeaconFormatToString;
  internalAddressArray[11] = (char*)BeaconFormatInt;
  internalAddressArray[12] = (char*)BeaconPrintf;
  internalAddressArray[13] = (char*)BeaconOutput;
  internalAddressArray[14] = (char*)BeaconUseToken;
  internalAddressArray[15] = (char*)BeaconRevertToken;
  internalAddressArray[16] = (char*)BeaconIsAdmin;
  internalAddressArray[17] = (char*)BeaconGetSpawnTo;
  internalAddressArray[18] = (char*)BeaconSpawnTemporaryProcess;
  internalAddressArray[19] = (char*)BeaconInjectProcess;
  internalAddressArray[20] = (char*)BeaconInjectTemporaryProcess;
  internalAddressArray[21] = (char*)BeaconCleanupProcess;
  internalAddressArray[22] = (char*)toWideChar;
}
