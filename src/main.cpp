#include<Windows.h>
#include<iostream>
#include<vector>
#include <iostream>
#include "ShoggothEngine.h"
#include "AuxFunctions.h"
#include "Structs.h"

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
	bool shellcodeMode = false;
	int fileSize = 0;
	int newFileSize = 0;
	PBYTE inputFileBuffer = NULL;
	PBYTE encryptedPayload = NULL;
	ShoggothPolyEngine* shoggothEngine = NULL;
	
	if (argc != 3) {
		std::cout << "[+] Usage: " << argv[0] << " <input payload> <output name>" << std::endl;
		return -1;
	}
	inputFileBuffer = ReadBinary(argv[1], fileSize);
	if (!inputFileBuffer || !fileSize) {
		std::cout << "[!] Can't read the input exe" << std::endl;
		return -1;
	}

	std::cout << "[+] " << argv[1] << " is read!" << std::endl;

	if (CheckValidPE(inputFileBuffer)) {
		std::cout << "[+] Input file is a valid x64 PE! PE encoding is choosing..." << std::endl;
		shellcodeMode = false;
	}
	else {
		std::cout << "[+] Input file is not a valid x64 PE! Shellcode encoding is choosing..." << std::endl;
		shellcodeMode = true;
	}
	// Initiate engine
	shoggothEngine = new ShoggothPolyEngine();

	if (!shellcodeMode) {
		inputFileBuffer = shoggothEngine->AddReflectiveLoader(inputFileBuffer, fileSize, fileSize);
	}

	inputFileBuffer = shoggothEngine->StartEncoding(inputFileBuffer, fileSize, newFileSize);

	Func test = (Func ) inputFileBuffer;
	test();

	int secondDecryptorBlockSize = 0;
	int encryptedSize = 0;
	return 0;
}