
#include "APISolver.h"
#include "BeaconFunctions.h"
#include "Structs.h"
#include <stdio.h>



typedef void(* COFFSIGNATURE)(PCHAR, UINT32);

UINT32 Read32le(const PUINT8 p)
{
    /* The one true way, see
     * https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html */
    return ((UINT32)p[0] << 0) |
        ((UINT32)p[1] << 8) |
        ((UINT32)p[2] << 16) |
        ((UINT32)p[3] << 24);
}
VOID Write32le(PUINT8 dst, UINT32 x)
{
    dst[0] = (UINT8)(x >> 0);
    dst[1] = (UINT8)(x >> 8);
    dst[2] = (UINT8)(x >> 16);
    dst[3] = (UINT8)(x >> 24);
}

VOID Add32(PUINT8 P, UINT32 V) {
    Write32le(P, Read32le(P) + V);
}


void ApplyGeneralRelocations(PUINT32 patchAddress, PBYTE sectionStartAddress, UINT16 givenType, UINT32 symbolOffset) {
    switch (givenType) {
        case IMAGE_REL_AMD64_REL32:
            Add32((PUINT8)patchAddress, sectionStartAddress - (PBYTE)patchAddress + symbolOffset  - 4);
            break;
        case IMAGE_REL_AMD64_ADDR32NB:
            Add32((PUINT8)patchAddress, (PUINT32) sectionStartAddress - patchAddress - 4);
            break;
        case IMAGE_REL_AMD64_ADDR64:
            *patchAddress = (UINT32)(*patchAddress + (UINT64) sectionStartAddress);
            break;
    }
}

PBYTE GetExternalFunctionAddress(LPCSTR symbolName, char** internalFunctionAddresses,  char** internalFunctionStrings) {
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, strncmpFunc, strcpy_sFunc, strtok_sFunc, strlenFunc;
    CHAR localSymbolNameCopy[512];
    PCHAR localLib = NULL;
    PCHAR localFunc = NULL;
    CHAR tokenString[] = {'$','@',0x00};
    for(int i=0;i<512;i++){
      localSymbolNameCopy[i] = '\0';
    }
    CHAR prefixSymbolString[] = { '_','_','i','m','p','_',0x00 };
    CHAR prefixBeaconString[] = { '_','_','i','m','p','_','B','e','a','c','o','n',0x00 };
    CHAR prefixToWideCharString[] = { '_','_','i','m','p','_','t','o','W','i','d','e','C','h','a','r',0x00 };
    PCHAR therest = NULL;
    PBYTE returnAddress = NULL;
    LPCSTR symbolWithoutPrefix = (LPCSTR)(((PBYTE)symbolName) + 6);

    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return returnAddress;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    CHAR strncmpString[] = { 's', 't', 'r', 'n', 'c', 'm', 'p', 0 };
    strncmpFunc = GetSymbolAddress(msvcrtDLL, strncmpString);

    CHAR strcpy_sString[] = { 's', 't', 'r', 'c', 'p', 'y', '_','s', 0};
    strcpy_sFunc = GetSymbolAddress(msvcrtDLL, strcpy_sString);

    CHAR strtok_sString[] = { 's', 't', 'r', 't', 'o', 'k', '_' ,'s', 0};
    strtok_sFunc = GetSymbolAddress(msvcrtDLL, strtok_sString);

    CHAR strlenString[] = { 's', 't', 'r', 'l', 'e', 'n', 0 };
    strlenFunc = GetSymbolAddress(msvcrtDLL, strlenString);

    if (((STRNCMP)strncmpFunc)(prefixSymbolString, symbolName, 6)) {
        return returnAddress;
    }
    // Check is it our cs function implmenetation
    if (((STRNCMP)strncmpFunc)(prefixBeaconString, symbolName, 12) == 0 || ((STRNCMP)strncmpFunc)(prefixToWideCharString, symbolName, 16) == 0) {
        for (int i = 0; i < 23; i++) {
            if (((STRNCMP)strncmpFunc)(symbolWithoutPrefix, (LPCSTR) internalFunctionStrings[i],((STRLEN)strlenFunc)(symbolWithoutPrefix)) == 0) {
                return (PBYTE) internalFunctionAddresses[i];
            }

        }
    }
    else {
        ((STRCPY_S) strcpy_sFunc)(localSymbolNameCopy, _countof(localSymbolNameCopy), symbolName);
        localLib = ((STRTOK_S) strtok_sFunc)(localSymbolNameCopy + 6, tokenString, &therest);
        localFunc = ((STRTOK_S) strtok_sFunc)(therest, tokenString, &therest);
        HANDLE libraryHandle = ((LOADLIBRARYA)loadLibraryAFunc)(localLib);
        if (libraryHandle != 0) {
            returnAddress = (PBYTE) GetSymbolAddress((UINT64)libraryHandle, localFunc);
        }
    }
    return returnAddress;

}

// By traversing the relocations of text section, we can count the external functions
uint64_t GetNumberOfExternalFunctions(PBYTE fileBuffer, PSECTION_HEADER textSectionHeader) {
    uint64_t returnValue = 0;
    PFILE_HEADER imageFileHeader = (PFILE_HEADER)fileBuffer;
    PSYMBOL_TABLE_ENTRY symbolTableCursor = NULL;
    PSYMBOL_TABLE_ENTRY symbolTable = (PSYMBOL_TABLE_ENTRY)(fileBuffer + imageFileHeader->PointerToSymbolTable);
    PRELOCATION_TABLE_ENTRY relocationTableCursor = (PRELOCATION_TABLE_ENTRY)(fileBuffer + textSectionHeader->PointerToRelocations);
    for (int i = 0; i < textSectionHeader->NumberOfRelocations; i++) {
        symbolTableCursor = (PSYMBOL_TABLE_ENTRY)((PBYTE) symbolTable + relocationTableCursor->SymbolTableIndex*sizeof(SYMBOL_TABLE_ENTRY));
        // Condition for an external symbol
        if (symbolTableCursor->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbolTableCursor->SectionNumber == 0) {
            returnValue++;
        }
        relocationTableCursor++;
    }
    return returnValue * sizeof(PBYTE);
}

void RunCOFF(PBYTE fileBuffer, PCHAR argumentBuffer, UINT32 argumentLength) {
    UINT64 kernel32DLL, msvcrtDLL;
    UINT64 loadLibraryAFunc, virtualAllocFunc, strncmpFunc, strlenFunc, printfFunc;
    PBYTE allocatedMemory = NULL;
	  PFILE_HEADER imageFileHeader = (PFILE_HEADER)fileBuffer;
	  int totalSize = 0;
	  PSECTION_HEADER sectionHeaderArray = (PSECTION_HEADER)(fileBuffer + sizeof(IMAGE_FILE_HEADER) + imageFileHeader->SizeOfOptionalHeader);
    PSECTION_HEADER sectionHeaderCursor = sectionHeaderArray;
    PSECTION_HEADER textSectionHeader = NULL;
    PSECTION_INFO sectionInfoList = NULL;
    int sectionInfoListLength = 0;
    SECTION_INFO tempSectionInfo;
    uint64_t memoryCursor = 0;
    PSYMBOL_TABLE_ENTRY symbolTable = (PSYMBOL_TABLE_ENTRY)(fileBuffer + imageFileHeader->PointerToSymbolTable);
    PSYMBOL_TABLE_ENTRY symbolTableCursor = NULL;
    PRELOCATION_TABLE_ENTRY relocationTableCursor = NULL;
    int sectionIndex = 0;
    int isExternal = 0;
    int isInternal = 0;
    PBYTE patchAddress = NULL;
    int stringTableOffset = 0;
    LPCSTR symbolName = NULL;
    int externalFunctionCount = 0;
    PBYTE* externalFunctionStoreAddress = NULL;
    PBYTE tempFunctionAddress = NULL;
    uint64_t deltaOffset = 0;
    uint32_t* tempPointer = NULL;
    PBYTE entryAddress = NULL;
    PBYTE sectionStartAddress = NULL;
    CHAR functionName[] = { 'g','o',0x00 };
    CHAR textSectionAsString[] = { '.', 't', 'e', 'x', 't', 0};
    CHAR beaconDataParseAsString[] = { 'B','e','a','c','o','n','D','a','t','a','P','a','r','s','e',0x00 };
    CHAR beaconDataIntAsString[] = { 'B','e','a','c','o','n','D','a','t','a','I','n','t',0x00};
    CHAR beaconDataShortAsString[] = { 'B','e','a','c','o','n','D','a','t','a','S','h','o','r','t',0x00 };
    CHAR beaconDataLengthAsString[] = { 'B','e','a','c','o','n','D','a','t','a','L','e','n','g','t','h',0x00};
    CHAR beaconDataExtractAsString[] = { 'B','e','a','c','o','n','D','a','t','a','E','x','t','r','a','c','t',0x00 };
    CHAR beaconFormatAllocAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','A','l','l','o','c',0x00};
    CHAR beaconFormatResetAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','R','e','s','e','t',0x00 };
    CHAR beaconFormatFreeAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','F','r','e','e',0x00 };
    CHAR beaconFormatAppendAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','A','p','p','e','n','d',0x00};
    CHAR beaconFormatPrintfAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','P','r','i','n','t','f',0x00};
    CHAR beaconFormatToStringAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','T','o','S','t','r','i','n','g',0x00};
    CHAR beaconFormatIntAsString[] = { 'B','e','a','c','o','n','F','o','r','m','a','t','I','n','t',0x00};
    CHAR beaconPrintfAsString[] = { 'B','e','a','c','o','n','P','r','i','n','t','f',0x00};
    CHAR beaconOutputAsString[] = { 'B','e','a','c','o','n','O','u','t','p','u','t',0x00 };
    CHAR beaconUseTokenAsString[] = { 'B','e','a','c','o','n','U','s','e','T','o','k','e','n',0x00};
    CHAR beaconRevertTokenAsString[] = { 'B','e','a','c','o','n','R','e','v','e','r','t','T','o','k','e','n',0x00};
    CHAR beaconIsAdminAsString[] = { 'B','e','a','c','o','n','I','s','A','d','m','i','n', 0x00 };
    CHAR beaconGetSpawnToAsString[] = { 'B','e','a','c','o','n','G','e','t','S','p','a','w','n','T','o', 0x00};
    CHAR beaconSpawnTemporaryProcessAsString[] = { 'B','e','a','a','c','o','n','S','p','a','w','n','T','e','m','p','o','r','a','r','y','P','r','o','c','e','s','s',0x00};
    CHAR beaconInjectProcessAsString[] = { 'B','e','a','c','o','n','I','n','j','e','c','t','P','r','o','c','e','s','s',0x00 };
    CHAR beaconInjectTemporaryProcessAsString[] = { 'B','e','a','a','c','o','n','I','n','j','e','c','t','T','e','m','p','o','r','a','r','y','P','r','o','c','e','s','s',0x00};
    CHAR beaconCleanupProcessAsString[] = { 'B','e','a','c','o','n','C','l','e','a','n','u','p','P','r','o','c','e','s','s',0x00 };
    CHAR toWideCharAsString[] = { 't','o','W','i','d','e','C','h','a','r',0x00 };

    /* Data Parsing */
    char* InternalFunctionStrings[] = {
        beaconDataParseAsString,
        beaconDataIntAsString,
        beaconDataShortAsString,
        beaconDataLengthAsString,
        beaconDataExtractAsString,
        beaconFormatAllocAsString,
        beaconFormatResetAsString,
        beaconFormatFreeAsString,
        beaconFormatAppendAsString,
        beaconFormatPrintfAsString,
        beaconFormatToStringAsString,
        beaconFormatIntAsString,
        beaconPrintfAsString,
        beaconOutputAsString,
        beaconUseTokenAsString,
        beaconRevertTokenAsString,
        beaconIsAdminAsString,
        beaconGetSpawnToAsString,
        beaconSpawnTemporaryProcessAsString,
        beaconInjectProcessAsString,
        beaconInjectTemporaryProcessAsString,
        beaconCleanupProcessAsString,
        toWideCharAsString,
    };

    char* InternalFunctionAddresses[23] = { 0x00};

    SetInternalFunctions(InternalFunctionAddresses);

    if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
        return;
    }

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
    msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    CHAR virtualAllocString[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    virtualAllocFunc = GetSymbolAddress(kernel32DLL, virtualAllocString);

    CHAR strncmpString[] = { 's', 't', 'r', 'n', 'c', 'm', 'p', 0};
    strncmpFunc = GetSymbolAddress(msvcrtDLL, strncmpString);

    CHAR strlenString[] = { 's', 't', 'r', 'l', 'e', 'n', 0 };
    strlenFunc = GetSymbolAddress(msvcrtDLL, strlenString);

    CHAR printfString[] = { 'p','r','i','n','t','f', 0};
    printfFunc = GetSymbolAddress(msvcrtDLL, printfString);

    // Calculate total size for allocation
    //sectionInfoList = (PSECTION_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_INFO) * imageFileHeader->NumberOfSections);
    sectionInfoList = (PSECTION_INFO)((VIRTUALALLOC) virtualAllocFunc)(NULL, sizeof(SECTION_INFO) * imageFileHeader->NumberOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    sectionInfoListLength = imageFileHeader->NumberOfSections;
    for (int i = 0; i < imageFileHeader->NumberOfSections;i++) {
        if (((STRNCMP) strncmpFunc)(sectionHeaderCursor->Name, textSectionAsString, 5) == 0) {
            // Seperate saving for text section header
            textSectionHeader = sectionHeaderCursor;
        }
        //tempSectionInfo.name = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlen(sectionHeaderCursor->Name)+1);
        tempSectionInfo.name = ((VIRTUALALLOC)virtualAllocFunc)(NULL, sizeof(SECTION_INFO) * imageFileHeader->NumberOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        MyMemCpy((PBYTE) tempSectionInfo.name, (PBYTE) sectionHeaderCursor->Name, ((STRLEN) strlenFunc)(sectionHeaderCursor->Name) + 1);
        tempSectionInfo.sectionOffset = totalSize;
        tempSectionInfo.sectionHeaderPtr = sectionHeaderCursor;
        MyMemCpy((PBYTE) &sectionInfoList[i], (PBYTE) &tempSectionInfo, sizeof(SECTION_INFO));
        // Add the size
        totalSize += sectionHeaderCursor->SizeOfRawData;
        sectionHeaderCursor += 1;
    }
    if (textSectionHeader == NULL) {
        return;
    }
    // We need to store external function addresses too
    allocatedMemory = ((VIRTUALALLOC)virtualAllocFunc)(NULL, totalSize + GetNumberOfExternalFunctions(fileBuffer, textSectionHeader), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        return;
    }

    // Now copy the sections
    sectionHeaderCursor = sectionHeaderArray;
    externalFunctionStoreAddress = (PBYTE *)(totalSize + allocatedMemory);
    for (int i = 0; i < imageFileHeader->NumberOfSections; i++) {
        MyMemCpy(allocatedMemory + memoryCursor, fileBuffer + sectionHeaderCursor->PointerToRawData, sectionHeaderCursor->SizeOfRawData);
        memoryCursor += sectionHeaderCursor->SizeOfRawData;
        sectionHeaderCursor += 1;
    }
    // Sections are copied
    for (int i = 0; i < imageFileHeader->NumberOfSections; i++) {
        // Traverse each section for its relocations
        relocationTableCursor = (PRELOCATION_TABLE_ENTRY) (fileBuffer + sectionInfoList[i].sectionHeaderPtr->PointerToRelocations);
        for (int relocationCount = 0; relocationCount < sectionInfoList[i].sectionHeaderPtr->NumberOfRelocations; relocationCount++) {
            symbolTableCursor = symbolTable + relocationTableCursor->SymbolTableIndex;
            sectionIndex = symbolTableCursor->SectionNumber - 1;
            // The symbol record is not yet assigned a section. A value of zero indicates that a reference to an external symbol is defined elsewhere.
            // A value of non-zero is a common symbol with a size that is specified by the value.
            isExternal = (symbolTableCursor->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbolTableCursor->SectionNumber == 0);
            isInternal = (symbolTableCursor->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbolTableCursor->SectionNumber != 0);
            patchAddress = allocatedMemory + sectionInfoList[i].sectionOffset + (relocationTableCursor->VirtualAddress - sectionInfoList[i].sectionHeaderPtr->VirtualAddress);
            if (isExternal) {
                // If it is a function
                stringTableOffset = symbolTableCursor->first.value[1];
                symbolName = (LPCSTR)(((PBYTE)(symbolTable + imageFileHeader->NumberOfSymbols)) + stringTableOffset);
                tempFunctionAddress = GetExternalFunctionAddress(symbolName, InternalFunctionAddresses,InternalFunctionStrings);
                if (tempFunctionAddress == (PBYTE)-1) {
                    return;
                }
                if (tempFunctionAddress != NULL) {
                    *(externalFunctionStoreAddress + externalFunctionCount) = tempFunctionAddress;
                    deltaOffset = (uint64_t)((externalFunctionStoreAddress + externalFunctionCount)) - (uint64_t)(patchAddress) - 4;
                    tempPointer = (uint32_t*)patchAddress;
                    *tempPointer = ((uint32_t)deltaOffset);
                    externalFunctionCount++;
                }
                else {
                    return;
                }
            }
            else {
                if (sectionIndex >= sectionInfoListLength || sectionIndex < 0) {
                    return;
                }
                sectionStartAddress = allocatedMemory + sectionInfoList[sectionIndex].sectionOffset;
                if (isInternal) {
                    for (int internalCount = 0; i < sectionInfoListLength; i++) {
                        if (((STRNCMP) strncmpFunc)(sectionInfoList[internalCount].name, textSectionAsString, 5) == 0) {
                            sectionStartAddress = allocatedMemory + sectionInfoList[internalCount].sectionOffset;
                        }
                    }
                }
                ApplyGeneralRelocations((PUINT32) patchAddress, sectionStartAddress, relocationTableCursor->Type, symbolTableCursor->Value);
            }
            relocationTableCursor++;
        }
    }

    for (int i = 0; i < imageFileHeader->NumberOfSymbols; i++) {
        symbolTableCursor = symbolTable + i;
        if (((STRNCMP)strncmpFunc)(functionName, symbolTableCursor->first.Name,2) == 0 && ((STRLEN)strlenFunc)(symbolTableCursor->first.Name) == 2) {
            entryAddress = allocatedMemory + sectionInfoList[symbolTableCursor->SectionNumber - 1].sectionOffset + symbolTableCursor->Value;
            break;
        }
    }
    if (entryAddress == 0) {
        return;
    }
    COFFSIGNATURE func = (COFFSIGNATURE)entryAddress;
    SetFileSharingAddress(NULL, 0, 0,1);
    func(argumentBuffer, argumentLength);
    LPCSTR coffOutput = BeaconGetOutputData(NULL);
    if (coffOutput != NULL) {
        CHAR formatSpecifier[] = {'%','s', 0x00};
        ((PRINTF) printfFunc)(formatSpecifier, coffOutput);
    }
}
