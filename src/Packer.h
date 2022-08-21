#pragma once
#include <Windows.h>
#include <winnt.h>
#include <iostream>

DWORD FileSizeWithoutOverlay(PBYTE baseAddr);
BOOL PreparePackedFile(PBYTE newFileBuffer, PBYTE unpackedFile);
