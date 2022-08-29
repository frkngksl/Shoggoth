#pragma once
#include <Windows.h>
#include "ShoggothEngine.h"
bool RandomizeBool();
unsigned long long RandomizeQWORD();
unsigned long RandomizeDWORD();
int RandomizeInRange(int min, int max);
DWORD AlignBytes(DWORD currentSize, DWORD alignment);
BOOL WriteBinary(char* outputFileName, PBYTE fileBuffer, DWORD fileSize);
PBYTE ReadBinary(char* fileName, DWORD& fileSize);
char* GenerateRandomString();
PBYTE GetRandomBytes(size_t numberOfBytes);
BYTE GetRandomByte();