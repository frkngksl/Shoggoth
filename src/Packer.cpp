#include "Packer.h"
#include "AuxFunctions.h"

DWORD FileSizeWithoutOverlay(PBYTE baseAddr) { // Tested 
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

void CreateSections(PBYTE baseAddr) {
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

PBYTE GenerateImportTable(PBYTE startAddressRVA, DWORD& outSize, DWORD& iatSize, DWORD& importSize) {
	importStruct DLLNAMES[] = {
	{ "KERNEL32.dll", 0 },
	{ "USER32.dll", 0 },
	{ "GDI32.dll", 0 },
	{ "OLE32.dll", 0 },
	{ "COMDLG32.dll", 0 },
	{ "OLEAUT32.dll", 0 },
	{ "SHELL32.dll", 0 },
	{ "ADVAPI32.dll", 0},
	{ "SHLWAPI.dll", 0},
	{ "WININET.dll", 0}
	};
	return NULL;
}


BOOL PreparePackedFile(PBYTE newFileBuffer, PBYTE unpackedFile) {
	IMAGE_DOS_HEADER* dosHeaderForOld = (IMAGE_DOS_HEADER *) unpackedFile;
	IMAGE_NT_HEADERS* ntHeadersForOld = (IMAGE_NT_HEADERS*)(unpackedFile + dosHeaderForOld->e_lfanew);
	IMAGE_DOS_HEADER* dosHeaderForNew = (IMAGE_DOS_HEADER*)newFileBuffer;
	IMAGE_NT_HEADERS* ntHeadersForNew = (IMAGE_NT_HEADERS*)(newFileBuffer + dosHeaderForNew->e_lfanew);
	IMAGE_FILE_HEADER* fileHeaderForNew = (IMAGE_FILE_HEADER*) &(ntHeadersForNew->FileHeader);
	IMAGE_OPTIONAL_HEADER* optionalHeaderForNew = (IMAGE_OPTIONAL_HEADER*)&(ntHeadersForNew->OptionalHeader);
	IMAGE_SECTION_HEADER* imageSectionHeaders;
	memcpy(newFileBuffer, unpackedFile, ((PBYTE) ntHeadersForOld)+sizeof(IMAGE_NT_HEADERS)-unpackedFile); // All nt headers, section headers are not included
	memset(&(ntHeadersForNew->OptionalHeader.DataDirectory), 0, ntHeadersForNew->OptionalHeader.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));

	//prepare stubNT data.
	fileHeaderForNew->NumberOfSections = 3;

	fileHeaderForNew->TimeDateStamp = 0;// w\e do that shit later.

	optionalHeaderForNew->CheckSum = 0; //CheckSumMappedFile, later.

	optionalHeaderForNew->SectionAlignment = 0x1000;

	while (optionalHeaderForNew->SectionAlignment > 0x200 && rand() % 3) //set new alignment
		optionalHeaderForNew->SectionAlignment /= 2;
	optionalHeaderForNew->FileAlignment = optionalHeaderForNew->SectionAlignment;

	//new header size
	optionalHeaderForNew->SizeOfHeaders = AlignBytes(dosHeaderForNew->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * fileHeaderForNew->NumberOfSections), optionalHeaderForNew->FileAlignment);
	optionalHeaderForNew->SizeOfUninitializedData = 0;

	//create section headers
	imageSectionHeaders = (IMAGE_SECTION_HEADER *) VirtualAlloc(NULL, sizeof(IMAGE_SECTION_HEADER) *3, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// ****
	//.text (code)
	//.rdata (imports) contains IAT
	//.data (data)

	memcpy(imageSectionHeaders[0].Name, ".text", 5);
	memcpy(imageSectionHeaders[1].Name, ".rdata", 6);
	memcpy(imageSectionHeaders[2].Name, ".data", 5);
	/*
	Stub Sections Size
	//returns size of code, data or all stub sections depending on bType.
	//bType can be:
	//0 = total size of code sections
	//1 = total size of data sections

	*/
	//.text
	//	pstubSections[0].Misc.VirtualSize = Align(StubSectionsSize(0), stubNT.OptionalHeader.SectionAlignment);
	imageSectionHeaders[0].Misc.VirtualSize = 1; //StubSectionsSize(0);
	imageSectionHeaders[0].Characteristics = 0x60000020;
	imageSectionHeaders[0].PointerToRawData = AlignBytes(optionalHeaderForNew->SizeOfHeaders, optionalHeaderForNew->FileAlignment);
	imageSectionHeaders[0].SizeOfRawData = AlignBytes(1, optionalHeaderForNew->FileAlignment);
	imageSectionHeaders[0].VirtualAddress = AlignBytes(optionalHeaderForNew->SizeOfHeaders, optionalHeaderForNew->SectionAlignment); // Size of headers, directory headerlari sanirsam ondan hemen sonra


	imageSectionHeaders[1].VirtualAddress = AlignBytes(imageSectionHeaders[0].VirtualAddress + imageSectionHeaders[0].Misc.VirtualSize, optionalHeaderForNew->SectionAlignment);

	//dwImportRawSize = 10240;
	//pImportData = FakeImports(pstubSections[1].VirtualAddress, &dwImportRawSize, &dwIATSize, &dwImportsSize);

	
	// .rdata
	//	pstubSections[1].Misc.VirtualSize = Align(dwImportRawSize, stubNT.OptionalHeader.SectionAlignment);
	imageSectionHeaders[1].Misc.VirtualSize = 1;
	imageSectionHeaders[1].Characteristics = 0x40000040;
	imageSectionHeaders[1].PointerToRawData = AlignBytes(imageSectionHeaders[0].PointerToRawData + imageSectionHeaders[0].SizeOfRawData, optionalHeaderForNew->FileAlignment);
	imageSectionHeaders[1].SizeOfRawData = AlignBytes(1, optionalHeaderForNew->FileAlignment);
	//imageSectionHeaders[1].VirtualAddress = 1;

	// File Header is Coff header

	// .data
	//	pstubSections[2].Misc.VirtualSize = Align(StubSectionsSize(1), stubNT.OptionalHeader.SectionAlignment);
	imageSectionHeaders[2].Misc.VirtualSize = 1; //StubSectionsSize(1);
	imageSectionHeaders[2].Characteristics = 0xC0000040;
	imageSectionHeaders[2].PointerToRawData = AlignBytes(imageSectionHeaders[1].PointerToRawData + imageSectionHeaders[1].SizeOfRawData, optionalHeaderForNew->FileAlignment);
	imageSectionHeaders[2].SizeOfRawData = AlignBytes(1, optionalHeaderForNew->FileAlignment);
	imageSectionHeaders[2].VirtualAddress = AlignBytes(imageSectionHeaders[1].VirtualAddress + imageSectionHeaders[1].Misc.VirtualSize, optionalHeaderForNew->SectionAlignment);

	//TODO what is this --> sectionlari gommmek icin
	//MapStubSections(pstubSections[0].VirtualAddress, pstubSections[2].VirtualAddress, CryptedData);

	optionalHeaderForNew->BaseOfCode = imageSectionHeaders[0].VirtualAddress;
	// In x64 there is no information about baseofdata
	//stubNT.OptionalHeader.BaseOfData = pstubSections[2].VirtualAddress;
	// Checked from cff explorer
	optionalHeaderForNew->SizeOfCode = imageSectionHeaders[0].SizeOfRawData;

	optionalHeaderForNew->SizeOfInitializedData = imageSectionHeaders[1].Misc.VirtualSize + imageSectionHeaders[2].Misc.VirtualSize;
	/*
	// https://reverseengineering.stackexchange.com/questions/16870/import-table-vs-import-address-table
	//#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
	optionalHeaderForNew->DataDirectory[1].Size = dwImportsSize;
	optionalHeaderForNew->DataDirectory[1].VirtualAddress = pstubSections[1].VirtualAddress + dwIATSize;
	//IMAGE_DIRECTORY_ENTRY_IAT            12
	optionalHeaderForNew->DataDirectory[12].Size = dwIATSize;
	optionalHeaderForNew->DataDirectory[12].VirtualAddress = pstubSections[1].VirtualAddress;
	//header done, make sure stub variables are set and then write.

	for (i = 0; i < NUM_STUB_SECTIONS; i++)
	{
		if (stubsections[i].Offsets.dwOldVA == (DWORD)pFileArray)
		{
			pFileArray = (FileInfo*)stubsections[i].Offsets.dwNewVA;
			break;
		}
	}

	FixVAs((DWORD)pMe, stubNT.OptionalHeader.SizeOfImage, stubNT.OptionalHeader.ImageBase);

	for (i = 0; i < NUM_STUB_SECTIONS; i++)
	{
		if (stubsections[i].IsCodeOrData == 0 && stubsections[i].FixVAs == 1) //permutate stub code.
		{
			smi2le engine(GetTickCount());

			engine.Disasm((BYTE*)stubsections[i].Offsets.dwOldVA, stubsections[i].dwOldSize, 0);

			for (k = 0; k < 4; k++)
			{
				engine.AddTrash(1, 50, 500, true);
			}

			if (!(rand() % 3))
				engine.AddTrash(1, 20, 200, false);

			for (k = 0; k < 4; k++)
				engine.Mutate(5);

			for (k = 0; k < 2; k++)
				engine.Permutate(15);

			DWORD dwret;

			(*(etg_engine*)&etg_bin)
				(0,
					ETG_ALL,
					REG_ALL,
					REG_ALL,
					&dwret,
					stubsections[i].dwNewSize,
					stubsections[i].dwNewSize,
					(unsigned char*)stubsections[i].pCodeData,
					smi2le::my_rand);

			for (dwret = 0; dwret < 100; dwret++)
			{
				if (engine.Asm((BYTE*)stubsections[i].pCodeData, stubsections[i].dwNewSize, &dwEP) == ERR_SUCCESS)
					break;
			}

			if (dwret >= 100)
			{
				MessageBox(0, "Oops, try again", "Error", MB_ICONERROR);
				goto whataloser;
			}


			//no mutation (for testing/debugging)
//			memcpy((void*)stubsections[i].pCodeData, (void*)stubsections[i].Offsets.dwOldVA, stubsections[i].dwOldSize);
//			dwEP = 0;
		}
	// Number of sections
	// fileHeaderForNew
	*/
	return true;
}