#include<Windows.h>
#include<iostream>
#include<vector>
#include <iostream>
#include "ShoggothEngine.h"
#include "AuxFunctions.h"
#include "Structs.h"
#include "OptionsHelper.h"


int main(int argc, char *argv[]) {
	bool peMode = false;
	bool coffMode = true;
	int inputSize = 0;
	int encryptedPayloadSize = 0;
	PBYTE inputFileBuffer = NULL;
	PBYTE encryptedPayload = NULL;
	// Polymorphic Engine Object
	ShoggothPolyEngine* shoggothEngine = NULL;
	OPTIONS configurationOptions;
	memset(&configurationOptions, 0x00, sizeof(OPTIONS));
	PrintHeader();
	if (!ParseArgs(argc,argv,configurationOptions)) {
		std::cout << "\n[!] Error on parsing arguments. You may have forgotten mandatory options. Use -h for help.\n" << std::endl;
		return -1;
	}
	// Read the input binary
	inputFileBuffer = ReadBinary(configurationOptions.inputPath, inputSize);
	
	if (!inputFileBuffer || !inputSize) {
		std::cout << "[!] Can't read the input file: " << configurationOptions.inputPath << std::endl;
		return -1;
	}
	if (configurationOptions.isVerbose) {
		std::cout << "[+] " << configurationOptions.inputPath << " is read!" << std::endl;
	}

	// Initiate the engine
	shoggothEngine = new ShoggothPolyEngine(&configurationOptions);

	if (configurationOptions.isVerbose) {
		std::cout << "[+] Shoggoth engine is initiated!" << std::endl;
	}

	if (configurationOptions.operationMode == PE_LOADER_MODE) {
		if (configurationOptions.isVerbose) {
			std::cout << "[+] PE Loader mode is selected!" << std::endl;
		}
		// Check the input file is a PE file or not
		if (CheckValidPE(inputFileBuffer)) {
			// Check it is x64 or not
			if (Checkx64PE(inputFileBuffer) ) {
				if (configurationOptions.isVerbose) {
					std::cout << "[+] Input file is a valid x64 PE! PE encoding is choosing..." << std::endl;
				}
			}
			else {
				std::cout << "[!] x86 PE is detected! Shoggoth doesn't support x86 PE yet!" << std::endl;
				return -1;
			}

		}
		else {
			std::cout << "[!] Given input file is not a PE!" << std::endl;
			return -1;
		}
		inputFileBuffer = shoggothEngine->AddPELoader(inputFileBuffer, inputSize, inputSize);
		if(!inputFileBuffer){
			std::cout << "[!] Error on merging PE loader and payload!" << std::endl;
			return -1;
		}
	}
	else if (configurationOptions.operationMode == COFF_LOADER_MODE) {
		if (configurationOptions.isVerbose) {
			std::cout << "[+] COFF Loader mode is selected!" << std::endl;
		}
		if (configurationOptions.coffArg) {
			inputFileBuffer = shoggothEngine->AddCOFFLoader(inputFileBuffer, inputSize, (PBYTE)configurationOptions.coffArg, strlen(configurationOptions.coffArg), inputSize);
		}
		else {
			inputFileBuffer = shoggothEngine->AddCOFFLoader(inputFileBuffer, inputSize, NULL, 0, inputSize);
		}
		if (!inputFileBuffer) {
			std::cout << "[!] Error on merging COFF loader and payload!" << std::endl;
			return -1;
		}
	}
	else if (configurationOptions.operationMode == RAW_MODE){
		if (configurationOptions.isVerbose) {
			std::cout << "[+] Raw mode is selected!" << std::endl;
			std::cout << "[+] No loader shellcode will be appended to the payload!" << std::endl;
		}
	}
	else {
		std::cout << "[!] Error on mode selection!" << std::endl;
	}
	if (configurationOptions.isVerbose) {
		std::cout << "[+] Polymorphic encryption starts..." << std::endl;
	}
	// Start Encryption Process
	encryptedPayload = shoggothEngine->StartPolymorphicEncrypt(inputFileBuffer, inputSize, encryptedPayloadSize);
	std::cout << "[+] Polymorphic encryption is done!" << std::endl;

	// Write output
	if (WriteBinary(configurationOptions.outputPath, encryptedPayload, encryptedPayloadSize)) {
		if (configurationOptions.isVerbose) {
			std::cout << "[+] Encrypted payload is saved as " << configurationOptions.outputPath << std::endl;
		}
	}
	else {
		std::cout << "[!] Error on writing to " << configurationOptions.outputPath << std::endl;
		return -1;
	}

	// Func test = (Func)encryptedPayload;
	// test();
	return 0;
}