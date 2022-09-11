#include "AuxFunctions.h"

BOOL WriteBinary(char* outputFileName, PBYTE fileBuffer, int fileSize) {
	HANDLE fileHandle = CreateFileA(outputFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		std::cout << "CreateFileA Error: " << GetLastError() << std::endl;
#endif 
		return FALSE;
	}
	BOOL writeResult = WriteFile(fileHandle, fileBuffer, fileSize, NULL, NULL);
	if (writeResult == FALSE) {
#ifdef DEBUG
		std::cout << "WriteFile Error: " << GetLastError() << std::endl;
#endif 
		return FALSE;
	}
	CloseHandle(fileHandle);
	return TRUE;
}

PBYTE ReadBinary(char* fileName, int& fileSize) {
	PBYTE fileBuffer;
	HANDLE fileHandle = CreateFileA(fileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		std::cout << "CreateFileA Error: " << GetLastError() << std::endl;
#endif 
		return NULL;
	}
	fileSize = GetFileSize(fileHandle, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
#ifdef DEBUG
		std::cout << "GetFileSize Error: " << GetLastError() << std::endl;
#endif 
		return NULL;
	}
	fileBuffer = (PBYTE)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (fileBuffer == NULL) {
#ifdef DEBUG
		std::cout << "VirtualAlloc Error: " << GetLastError() << std::endl;
#endif 
		return NULL;
	}
	if (ReadFile(fileHandle, fileBuffer, fileSize, NULL, NULL) == FALSE) {
#ifdef DEBUG
		std::cout << "ReadFile Error: " << GetLastError() << std::endl;
#endif 
		return NULL;
	}
	CloseHandle(fileHandle);
	return fileBuffer;
}

PBYTE GetRandomBytes(size_t numberOfBytes) {
	PBYTE returnValue = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBytes);
	for (int i = 0; i < numberOfBytes; i++) {
		returnValue[i] = rand() % 256;
	}
	return returnValue;
}

BYTE GetRandomByte() {
	return rand() % 256;
}

bool RandomizeBool() {
    int randVal = rand() % 2;
    return randVal == 1;
}

unsigned long long RandomizeQWORD() {
    BYTE b0, b1, b2, b3, b4, b5, b6, b7;
    b0 = rand() % 256;
    b1 = rand() % 256;
    b2 = rand() % 256;
    b3 = rand() % 256;
    b4 = rand() % 256;
    b5 = rand() % 256;
    b6 = rand() % 256;
    b7 = rand() % 256;
    uint64_t dw = (uint64_t)b7 << 56 | (uint64_t)b6 << 48 | (uint64_t)b5 << 40 | (uint64_t) b4 << 32 | b3 << 24 | b2 << 16 | b1 << 8 | b0;
	return dw;
}


unsigned long RandomizeDWORD() {
    BYTE b0, b1, b2, b3;
    b0 = rand() % 256;
    b1 = rand() % 256;
    b2 = rand() % 256;
    b3 = rand() % 256;
    unsigned long dw =  b3 << 24 | b2 << 16 | b1 << 8 | b0;
    return dw;
}

int AlignBytes(int currentSize, int alignment) {
    return (int)(ceil(((float)currentSize) / alignment)) * alignment;
}

int RandomizeInRange(int min, int max) {
	return min + (rand() % (max - min + 1));
}

char *GenerateRandomString(){
	char * stringBuffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 17);
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for (int i = 0; i < 16; ++i) {
		stringBuffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	stringBuffer[17] = 0;
	return stringBuffer;
}

PBYTE MergeChunks(PBYTE firstChunk, int firstChunkSize, PBYTE secondChunk, int secondChunkSize) {
	PBYTE returnValue = (PBYTE) VirtualAlloc(NULL,firstChunkSize + secondChunkSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(returnValue, firstChunk, firstChunkSize);
	memcpy(returnValue + firstChunkSize, secondChunk, secondChunkSize);
	return returnValue;
}

bool CheckValidPE(PBYTE fileBuffer) {
	PIMAGE_DOS_HEADER testFileDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS testFileNtHeader = (PIMAGE_NT_HEADERS)(testFileDosHeader->e_lfanew + fileBuffer);
	if (testFileDosHeader->e_magic == IMAGE_DOS_SIGNATURE && testFileNtHeader->Signature == IMAGE_NT_SIGNATURE && testFileNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return true;
	}
	return false;
}