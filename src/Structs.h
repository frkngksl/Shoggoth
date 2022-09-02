#pragma once
#include "asmjit/asmjit.h"
enum ERRORCASES { ERR_PARAMS, ERR_MEMORY, ERR_SUCCESS};
typedef long(WINAPI *DecryptionProc)(void*);


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

