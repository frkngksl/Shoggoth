#pragma once
#include <Windows.h>
#include "ShoggothEngine.h"
bool RandomizeBool();
unsigned long long RandomizeQWORD();
unsigned long RandomizeDWORD();
int RandomizeInRange(int min, int max);
int AlignBytes(int currentSize, int alignment);
BOOL WriteBinary(char* outputFileName, PBYTE fileBuffer, int fileSize);
PBYTE ReadBinary(char* fileName, int& fileSize);
char* GenerateRandomString();
PBYTE GetRandomBytes(size_t numberOfBytes);
BYTE GetRandomByte();
PBYTE MergeChunks(PBYTE firstChunk, int firstChunkSize, PBYTE secondChunk, int secondChunkSize);
bool CheckValidPE(PBYTE fileBuffer);
bool Checkx64PE(PBYTE fileBuffer);