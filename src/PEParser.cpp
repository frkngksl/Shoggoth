#include "PEParser.h"


void ParseInput(PBYTE baseAddr) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *) baseAddr;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
#ifdef DEBUG
		std::cout << "DOS Signature is not valid!" << std::endl;
#endif // DEBUG
		return;
	}
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS *) (baseAddr + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
#ifdef DEBUG
		std::cout << "NT Signature is not valid!" << std::endl;
#endif // DEBUG
		return;
	}
	int numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*) ((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < numberOfSections; i++) {
		std::cout << (char *) sectionHeaders[i].Name << std::endl;
	}
}