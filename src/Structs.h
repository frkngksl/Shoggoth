#pragma once
enum ERRORCASES { ERR_PARAMS, ERR_MEMORY, ERR_SUCCESS};
typedef long(WINAPI *DecryptionProc)(void*);


enum
{
    SPE_CRYPT_OP_ADD = 0,
    SPE_CRYPT_OP_SUB,
    SPE_CRYPT_OP_XOR,
    SPE_CRYPT_OP_NOT,
    SPE_CRYPT_OP_NEG,
};



typedef struct
{
	const char* namePtr;
	BOOL isUsed;
} importStruct;

