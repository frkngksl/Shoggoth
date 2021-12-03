#include<Windows.h>
#include<iostream>
#include<vector>
#define DEBUG 1

void printHeader() {
	const char* shoggothHeader = R"(
  ______ _                                  _     
 / _____) |                             _  | |    
( (____ | |__   ___   ____  ____  ___ _| |_| |__  
 \____ \|  _ \ / _ \ / _  |/ _  |/ _ (_   _)  _ \ 
 _____) ) | | | |_| ( (_| ( (_| | |_| || |_| | | |
(______/|_| |_|\___/ \___ |\___ |\___/  \__)_| |_|
                    (_____(_____|                                                                          

		     by @R0h1rr1m
)";
	std::cout << shoggothHeader << std::endl;
}


BOOL writeBinary(char* outputFileName, PBYTE fileBuffer, DWORD fileSize) {
	HANDLE fileHandle = CreateFileA(outputFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		std::cout << "CreateFileA Error: " << GetLastError() << std::endl;
#endif 
		return FALSE;
	}
	BOOL writeResult = WriteFile(fileHandle, fileBuffer,fileSize,NULL, NULL);
	if (writeResult == FALSE){
#ifdef DEBUG
		std::cout << "WriteFile Error: " << GetLastError() << std::endl;
#endif 
		return FALSE;
	}
	CloseHandle(fileHandle);
	return TRUE;
}

PBYTE readBinary(char* fileName,DWORD &fileSize) {
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
	fileBuffer = (PBYTE) VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

int main(int argc, char *argv[]) {
	printHeader();
	if (argc != 3) {
		std::cout << "[+] Usage: " << argv[0] << " <input exe> <output exe>" << std::endl;
		return -1;
	}
	DWORD fileSize;
	PBYTE fileBuffer = readBinary(argv[1], fileSize);
	if (!fileBuffer) {
		std::cout << "[!] Can't read the input exe" << std::endl;
		return -1;
	}
	std::cout << "[+] Input file is read" << std::endl;
	BOOL result = writeBinary(argv[2], fileBuffer, fileSize);
	if (result == FALSE) {
		std::cout << "[!] Can't write the output exe" << std::endl;
		return -1;
	}
	std::cout << "[+] Output file is written" << std::endl;
	VirtualFree(fileBuffer,0,MEM_RELEASE);
	std::cout << "[+] Enjoy your new file: " << argv[2] << std::endl;
	return 0;
}