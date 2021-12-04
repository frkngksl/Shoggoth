#include "Packer.h"

DWORD fileSizeWithoutOverlay(PBYTE baseAddr) { // Tested 
	DWORD returnValue = 0;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaderArray = (IMAGE_SECTION_HEADER *) (((PBYTE)ntHeaders) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (sectionHeaderArray[i].PointerToRawData + sectionHeaderArray[i].SizeOfRawData > returnValue) {
			returnValue = sectionHeaderArray[i].PointerToRawData + sectionHeaderArray[i].SizeOfRawData;
		}
	}
	return returnValue;
}

void createSections(PBYTE baseAddr) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
#ifdef DEBUG
		std::cout << "DOS Signature is not valid!" << std::endl;
#endif // DEBUG
		return;
	}
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
#ifdef DEBUG
		std::cout << "NT Signature is not valid!" << std::endl;
#endif // DEBUG
		return;
	}
}


BOOL preparePackedFile(PBYTE newFileBuffer, PBYTE unpackedFile) {
	IMAGE_DOS_HEADER* dosHeaderForOld = (IMAGE_DOS_HEADER *) unpackedFile;
	IMAGE_NT_HEADERS* ntHeadersForOld = (IMAGE_NT_HEADERS*)(unpackedFile + dosHeaderForOld->e_lfanew);
	CopyMemory(newFileBuffer, unpackedFile, ((PBYTE) ntHeadersForOld)+sizeof(IMAGE_NT_HEADERS)-unpackedFile);
	return true;
}