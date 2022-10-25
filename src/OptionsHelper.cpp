#include "OptionsHelper.h"

void PrintHeader() {
	const char* shoggothHeader = R"(
  ______ _                                  _     
 / _____) |                             _  | |    
( (____ | |__   ___   ____  ____  ___ _| |_| |__  
 \____ \|  _ \ / _ \ / _  |/ _  |/ _ (_   _)  _ \ 
 _____) ) | | | |_| ( (_| ( (_| | |_| || |_| | | |
(______/|_| |_|\___/ \___ |\___ |\___/  \__)_| |_|
                    (_____(_____|                                                                          

		     by @R0h1rr1m

                "Tekeli-li! Tekeli-li!" 
)";
	std::cout << shoggothHeader << std::endl;
}

void PrintHelp(char *binaryName) {
	const char* optionsString = R"(
    -h | --help                             Show the help message.
    -v | --verbose                          Enable a more verbose output.
    -i | --input <Input Path>               Input path of payload to be encrypted. (Mandatory) 
    -o | --output <Output Path>             Output path for encrypted input. (Mandatory) 
    -s | --seed <Value>                     Set seed value for randomization.
    -m | --mode <Mode Value>                Set payload encryption mode. Available mods are: (Mandatory) 
                                                [*] raw - Shoggoth doesn't append a loader stub.
                                                [*] PE - Shoggoth appends a PE loader stub. The input should be valid x64 PE.
                                                [*] COFF - Shoggoth appends a COFF loader stub. The input should be valid x64 COFF.
    --coff-arg <Argument>                   Set argument for COFF loader. Only used in COFF loader mode.
    -k | --key <Encryption Key>             Set first encryption key instead of random key.
    --dont-do-first-encryption              Don't do the first (stream cipher) encryption.
    --dont-do-second-encryption             Don't do the second (block cipher) encryption.
    --encrypt-only-decryptor                Encrypt only decryptor stub in the second encryption.
    --save-registers                        Save registers and restore them at the end of the execution.
)";
    std::cout << "Usage of " << binaryName << ":" << std::endl;
    std::cout << optionsString << std::endl;

}

bool ParseArgs(int argc, char* argv[], OPTIONS& configurationOptions) {
    for (int i = 1; i < argc; i++) {
        if (_strcmpi(argv[i], "-v") == 0 || _strcmpi(argv[i], "--verbose") == 0) {
            configurationOptions.isVerbose = true;
        }
        else if (_strcmpi(argv[i], "-h") == 0 || _strcmpi(argv[i], "--help") == 0) {
            PrintHelp(argv[0]);
            exit(0);
        }
        else if (_strcmpi(argv[i], "-i") == 0 || _strcmpi(argv[i], "--input") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            configurationOptions.inputPath = argv[i];
        }
        else if (_strcmpi(argv[i], "-o") == 0 || _strcmpi(argv[i], "--output") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            configurationOptions.outputPath = argv[i];
        }
        else if (_strcmpi(argv[i], "-s") == 0 || _strcmpi(argv[i], "--seed") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            configurationOptions.useSeed = true;
            configurationOptions.seed = atoi(argv[i]);
        }
        else if (_strcmpi(argv[i], "-m") == 0 || _strcmpi(argv[i], "--mode") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            if (_strcmpi(argv[i], "raw") == 0) {
                configurationOptions.operationMode = RAW_MODE;
            }
            else if (_strcmpi(argv[i], "PE") == 0) {
                configurationOptions.operationMode = PE_LOADER_MODE;
            }
            else if (_strcmpi(argv[i], "COFF") == 0) {
                configurationOptions.operationMode = COFF_LOADER_MODE;
            }
            else {
                return false;
            }
        }
        else if (_strcmpi(argv[i], "-k") == 0 || _strcmpi(argv[i], "--key") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            configurationOptions.encryptionKey = argv[i];
        }
        else if (_strcmpi(argv[i], "--dont-do-first-encryption") == 0) {
            configurationOptions.dontDoFirstEncryption = true;
        }
        else if (_strcmpi(argv[i], "--dont-do-second-encryption") == 0) {
            configurationOptions.dontDoSecondEncryption = true;
        }
        else if (_strcmpi(argv[i], "--encrypt-only-decryptor") == 0) {
            configurationOptions.encryptOnlyDecryptor = true;
        }
        else if (_strcmpi(argv[i], "--save-registers") == 0) {
            configurationOptions.saveRegisters = true;
        }
        else if (_strcmpi(argv[i], "--coff-arg") == 0) {
            i++;
            if (i > argc) {
                return false;
            }
            configurationOptions.coffArg = argv[i];
        }
    }
    if (configurationOptions.operationMode == INVALID_MODE || configurationOptions.inputPath == NULL || configurationOptions.outputPath == NULL) {
        return false;
    }
    return true;
}