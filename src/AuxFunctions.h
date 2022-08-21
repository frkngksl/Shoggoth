#pragma once
#include <Windows.h>
#include "ShoggothEngine.h"

long RandomizeBinary();

bool RandomizeBool();

unsigned long long RandomizeQWORD();

unsigned long RandomizeDWORD();

DWORD AlignBytes(DWORD currentSize, DWORD alignment);

BOOL WriteBinary(char* outputFileName, PBYTE fileBuffer, DWORD fileSize);

PBYTE ReadBinary(char* fileName, DWORD& fileSize);