#include<Windows.h>
#include<iostream>
#include<vector>
#include <iostream>
#include "PEParser.h"
#include "ShoggothEngine.h"
#include "Packer.h"
#include "AuxFunctions.h"

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



int main(int argc, char *argv[]) {
	/*
	int x = sizeof(unsigned long long);
	//printHeader();
	char szHelloWorld[] = "Hello world!";

	// create an instance of the polymorphic
	// engine
	ShoggothPolyEngine* shoggothEngine = new ShoggothPolyEngine();

	// a pointer to the generated decryption
	// function will be placed here
	PBYTE lpcDecryptionProc = NULL;

	// the size of the decryption code (and
	// its encrypted payload) will go here
	DWORD dwDecryptionProcSize = 0;

	// encrypt the input data and dynamically
	// generate a decryption function
	ERRORCASES errorReturn = shoggothEngine->PolymorphicEncryption(reinterpret_cast<PBYTE>(szHelloWorld), \
		sizeof(szHelloWorld), \
		lpcDecryptionProc, \
		dwDecryptionProcSize);

	// write the generated function to disk
	FILE* hFile = fopen("polymorphic_code.bin", "wb");

	if (hFile != NULL)
	{
		fwrite(lpcDecryptionProc, dwDecryptionProcSize, 1, hFile);
		fclose(hFile);
	}

	// cast the function pointer to the right type --> Make area execeutable
	DecryptionProc lpDecryptionProc = reinterpret_cast<DecryptionProc>(lpcDecryptionProc);

	// the output buffer for the decrypted data
	char szOutputBuffer[128] = { 0x00 };

	// call the decryption function via its
	// function pointer
	DWORD dwOutputSize = lpDecryptionProc(szOutputBuffer);
	*/

	
	/*
	PBYTE garbage = shoggothEngine->GenerateRandomGarbage(garbageSize);

	FILE* hFile = fopen("polymorphic_code.bin", "wb");

	if (hFile != NULL)
	{
		fwrite(garbage, garbageSize, 1, hFile);
		fclose(hFile);
	}
	*/
	int payloadSize = 150;
	int test = 0;
	ShoggothPolyEngine* shoggothEngine = new ShoggothPolyEngine();
	shoggothEngine->SecondDecryptor(payloadSize, test);
	if (argc != 3) {
		std::cout << "[+] Usage: " << argv[0] << " <input exe> <output exe>" << std::endl;
		return -1;
	}
	DWORD fileSize;
	PBYTE inputFileBuffer = ReadBinary(argv[1], fileSize);
	if (!inputFileBuffer) {
		std::cout << "[!] Can't read the input exe" << std::endl;
		return -1;
	}
	
	shoggothEngine->StartEncoding(inputFileBuffer, fileSize);
	ParseInput(inputFileBuffer);
	std::cout << "[+] Input file is read" << std::endl;
	PBYTE outputBuffer = (PBYTE)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (outputBuffer == NULL) {
#ifdef DEBUG
		std::cout << "VirtualAlloc Error: " << GetLastError() << std::endl;
#endif 
		return -1;
	}
	FileSizeWithoutOverlay(inputFileBuffer);
	PreparePackedFile(outputBuffer, inputFileBuffer);
	BOOL result = WriteBinary(argv[2], outputBuffer, fileSize);
	if (result == FALSE) {
		std::cout << "[!] Can't write the output exe" << std::endl;
		return -1;
	}
	std::cout << "[+] Output file is written" << std::endl;
	VirtualFree(inputFileBuffer,0,MEM_RELEASE);
	VirtualFree(outputBuffer, 0, MEM_RELEASE);
	std::cout << "[+] Enjoy your new file: " << argv[2] << std::endl;
	return 0;
}