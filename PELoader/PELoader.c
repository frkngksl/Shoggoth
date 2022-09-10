#include "APISolver.h"

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;


void fixRelocTable(BYTE* loadedAddr, BYTE* preferableAddr, IMAGE_DATA_DIRECTORY* relocDir) {
	size_t maxSizeOfDir = relocDir->Size;
	size_t relocBlocks = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* relocBlockMetadata = NULL;

	size_t relocBlockOffset = 0;
	for (; relocBlockOffset < maxSizeOfDir; relocBlockOffset += relocBlockMetadata->SizeOfBlock) {
		relocBlockMetadata = (IMAGE_BASE_RELOCATION*)(relocBlocks + relocBlockOffset + loadedAddr);
		if (relocBlockMetadata->VirtualAddress == 0 || relocBlockMetadata->SizeOfBlock == 0) {
			//No more block
			break;
		}
		size_t entriesNum = (relocBlockMetadata->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t pageStart = relocBlockMetadata->VirtualAddress;
		//printf("Entries Num: %d %d\n", entriesNum, pageStart);
		BASE_RELOCATION_ENTRY* relocEntryCursor = (BASE_RELOCATION_ENTRY*)((BYTE*)relocBlockMetadata + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; i < entriesNum; i++) {
			if (relocEntryCursor->Type == 0) {
				continue;
			}
			DWORD* relocationAddr = (DWORD*)(pageStart + loadedAddr + relocEntryCursor->Offset);
			*relocationAddr = *relocationAddr + loadedAddr - preferableAddr;
			relocEntryCursor = (BASE_RELOCATION_ENTRY*)((BYTE*)relocEntryCursor + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	if (relocBlockOffset == 0) {
		//Nothing happened
	}
}


void loadPE(BYTE *baseAddr){
    UINT64 kernel32DLL, msvcrtDLL, ntdllDLL;
    //symbols to dynamically resolve from dll during runtime
    UINT64 loadLibraryAFunc, virtualAllocFunc, memcpyFunc, ntUnmapViewOfSectionFunc, getProcAddressFunc;
    // kernel32.dll exports
	// C:\Windows\System32\Kernel32.dll
	if ((kernel32DLL = GetLoadedLibrary(CRYPTED_HASH_KERNEL32)) == 0) {
		return;
	}
	if ((ntdllDLL = GetLoadedLibrary(CRYPTED_HASH_NTDLL)) == 0) {
		return;
	}

    CHAR loadLibraryAString[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    loadLibraryAFunc = GetSymbolAddress(kernel32DLL, loadLibraryAString);

	CHAR getProcAddressString[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's' , 's', 0 };
	getProcAddressFunc = GetSymbolAddress(kernel32DLL, getProcAddressString);

	CHAR virtualAllocString[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
	virtualAllocFunc = GetSymbolAddress(kernel32DLL, virtualAllocString);

	// ntdll.dll exports
	CHAR ntUnmapViewString[] = { 'N','t','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };
	ntUnmapViewOfSectionFunc = GetSymbolAddress(ntdllDLL, ntUnmapViewString);

    // msvcrt.dll exports
    CHAR msvcrtString[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
	msvcrtDLL = (UINT64)((LOADLIBRARYA)loadLibraryAFunc)(msvcrtString);

    // CHAR wprintfString[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0 };
    // wprintfFunc = GetSymbolAddress((HANDLE)msvcrtDLL, wprintfString);
	// CHAR printfString[] = { 'p', 'r', 'i', 'n', 't', 'f', 0 };
	// printfFunc = GetSymbolAddress((HANDLE)msvcrtDLL, printfString);
	CHAR memcpyString[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	memcpyFunc = GetSymbolAddress(msvcrtDLL, memcpyString);

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((size_t)baseAddr + ((IMAGE_DOS_HEADER*)baseAddr)->e_lfanew);
	IMAGE_DATA_DIRECTORY* relocTable = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_DATA_DIRECTORY* iatDirectory = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ULONGLONG preferableAddress = ntHeader->OptionalHeader.ImageBase;
	//Unmap the preferable address
	((NTUNMAPVIEWOFSECTION)ntUnmapViewOfSectionFunc)((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	BYTE* imageBaseForPE = (BYTE*)((VIRTUALALLOC)virtualAllocFunc)((LPVOID)preferableAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!imageBaseForPE && !relocTable) {
		//((PRINTF)printfFunc)("[!] No Relocation Table and Cannot load to the preferable address\n");
		return;
	}
	if (!imageBaseForPE && relocTable) {
		//((PRINTF)printfFunc)("[+] Cannot load to the preferable address\n");
		imageBaseForPE = (BYTE*)((VIRTUALALLOC)virtualAllocFunc)(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!imageBaseForPE) {
			//((PRINTF)printfFunc)("[!] Cannot allocate the memory\n");
			return;
		}
	}
	ntHeader->OptionalHeader.ImageBase = (ULONGLONG)imageBaseForPE;
	// SizeOfHeaders indicates how much space in the file is used for representing all the file headers, including the MS - DOS header, PE file header, PE optional header, and PE section headers.The section bodies begin at this location in the file.
	((MEMCPY) memcpyFunc)(imageBaseForPE, baseAddr, ntHeader->OptionalHeader.SizeOfHeaders);
	//((PRINTF)printfFunc)("[+] All headers are copied\n");
	IMAGE_SECTION_HEADER* sectionHeaderCursor = (IMAGE_SECTION_HEADER*)(((size_t)ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		((MEMCPY)memcpyFunc)(imageBaseForPE + sectionHeaderCursor[i].VirtualAddress, baseAddr + sectionHeaderCursor[i].PointerToRawData, sectionHeaderCursor[i].SizeOfRawData);
	}
	//((PRINTF)printfFunc)("[+] All sections are copied\n");

	// IAT FIX
	//((PRINTF)printfFunc)("[+] IAT Fix starts...\n");

	if (iatDirectory->VirtualAddress == 0) {
		//((PRINTF)printfFunc)("[!] Import Table not found\n");
	}
	else {
		UINT64 iatSize = iatDirectory->Size;
		UINT64 iatRVA = iatDirectory->VirtualAddress;
		IMAGE_IMPORT_DESCRIPTOR* ITEntryCursor = NULL;
		size_t parsedSize = 0;
		for (; parsedSize < iatSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			ITEntryCursor = (IMAGE_IMPORT_DESCRIPTOR*)(iatRVA + (ULONG_PTR)imageBaseForPE + parsedSize);
			if (ITEntryCursor->OriginalFirstThunk == 0 && ITEntryCursor->FirstThunk == 0) {
				break;
			}
			LPSTR dllName = (LPSTR)((ULONGLONG)imageBaseForPE + ITEntryCursor->Name);
			//((PRINTF)printfFunc)("[+] Imported DLL Name: \n");
			//Address
			size_t firstThunkRVA = ITEntryCursor->FirstThunk;
			//Name
			size_t originalFirstThunkRVA = ITEntryCursor->OriginalFirstThunk;
			if (originalFirstThunkRVA == 0) {
				originalFirstThunkRVA = ITEntryCursor->FirstThunk;
			}
			size_t cursorFirstThunk = 0;
			size_t cursorOriginalFirstThunk = 0;
			while (1) {
				IMAGE_THUNK_DATA* firstThunkData = (IMAGE_THUNK_DATA*)(imageBaseForPE + cursorFirstThunk + firstThunkRVA);
				IMAGE_THUNK_DATA* originalFirstThunkData = (IMAGE_THUNK_DATA*)(imageBaseForPE + cursorOriginalFirstThunk + originalFirstThunkRVA);
				if (firstThunkData->u1.Function == 0) {
					//end of the list
					break;
				}
				else if (IMAGE_SNAP_BY_ORDINAL64(originalFirstThunkData->u1.Ordinal)) {
					//Get_Sym((LOADLIBRARYA)LoadLibraryAFunc)(dllName);
					size_t functionAddr = (size_t)((GETPROCADDRESS)getProcAddressFunc)(((LOADLIBRARYA)loadLibraryAFunc)(dllName), (char*)(originalFirstThunkData->u1.Ordinal & 0xFFFF)); // Ordinal should be in low word for getProcA
					//((PRINTF)printfFunc)("[+] Import by ordinal : \n");
					firstThunkData->u1.Function = (ULONGLONG)functionAddr;
				}
				else {
					PIMAGE_IMPORT_BY_NAME nameOfFunc = (PIMAGE_IMPORT_BY_NAME)(((size_t)imageBaseForPE) + originalFirstThunkData->u1.AddressOfData);
					size_t functionAddr = (size_t)((GETPROCADDRESS)getProcAddressFunc)(((LOADLIBRARYA)loadLibraryAFunc)(dllName), nameOfFunc->Name);
					firstThunkData->u1.Function = (ULONGLONG)functionAddr;
				}
				cursorFirstThunk += sizeof(IMAGE_THUNK_DATA);
				cursorOriginalFirstThunk += sizeof(IMAGE_THUNK_DATA);
			}
		}
	}

	//RELOC FIX


	if (((ULONGLONG)imageBaseForPE) != preferableAddress) {
		if (relocTable) {
			fixRelocTable(imageBaseForPE, (BYTE*)preferableAddress, relocTable);
		}
		else {
			// ((PRINTF)printfFunc)("[!] No Reloc Table Found\n");
		}

	}
	size_t startAddress = (size_t)(imageBaseForPE)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	// ((PRINTF)printfFunc)("[+] Binary is running\n");

	((void(*)())startAddress)();
}
