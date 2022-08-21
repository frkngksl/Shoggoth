#include "AuxFunctions.h"

BOOL WriteBinary(char* outputFileName, PBYTE fileBuffer, DWORD fileSize) {
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

PBYTE ReadBinary(char* fileName, DWORD& fileSize) {
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


bool RandomizeBool() {
    int randVal = rand() % 2;
    return randVal == 1;
}

long RandomizeBinary() {
    return rand()%2;
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
    unsigned long long dw = b7 << 56 | b6 << 48 | b5 << 40 | b4 << 32 | b3 << 24 | b2 << 16 | b1 << 8 | b0;
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

DWORD AlignBytes(DWORD currentSize, DWORD alignment) {
    return (DWORD)(ceil(((float)currentSize) / alignment)) * alignment;
}