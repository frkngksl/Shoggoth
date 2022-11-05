#pragma once
#include "asmjit/asmjit.h"


typedef enum
{
    ADD_OPERATION_FOR_CRYPT = 0,
    SUB_OPERATION_FOR_CRYPT,
    XOR_OPERATION_FOR_CRYPT,
    NOT_OPERATION_FOR_CRYPT,
    NEG_OPERATION_FOR_CRYPT,
    INC_OPERATION_FOR_CRYPT,
    DEC_OPERATION_FOR_CRYPT,
    ROL_OPERATION_FOR_CRYPT,
    ROR_OPERATION_FOR_CRYPT,
} OPERATIONS;

typedef struct {
    OPERATIONS operation;
    uint64_t operandValue;
    asmjit::x86::Gp operandRegister;
    bool isRegister;
    bool changeSourceRegister;
    asmjit::x86::Gp oldSourceRegister;
    asmjit::x86::Gp newSourceRegister;
} ENCRYPT_TYPE;


typedef struct {
    uint8_t i;
    uint8_t j;
    uint8_t s[256];
}RC4STATE;


typedef struct
{
	const char* namePtr;
	BOOL isUsed;
} importStruct;

typedef int (*Func)(void);
typedef void (*RUNCOFF)(PBYTE, PCHAR, UINT32);

typedef enum
{
    INVALID_MODE = 0,
    RAW_MODE,
    PE_LOADER_MODE,
    COFF_LOADER_MODE,
} OPERATIONMODE;

typedef struct {
    OPERATIONMODE operationMode;
    LPSTR inputPath;
    LPSTR outputPath;
    LPSTR coffArg;
    LPSTR encryptionKey;
    int encryptionKeySize;
    int seed;
    bool isVerbose;
    bool encryptOnlyDecryptor;
    bool dontDoFirstEncryption;
    bool dontDoSecondEncryption;
    bool useSeed;
} OPTIONS;