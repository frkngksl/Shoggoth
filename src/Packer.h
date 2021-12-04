#pragma once
#include <Windows.h>
#include <winnt.h>
#include <iostream>

DWORD fileSizeWithoutOverlay(PBYTE baseAddr);
BOOL preparePackedFile(PBYTE newFileBuffer, PBYTE unpackedFile);