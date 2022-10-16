#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include "Structs.h"

void PrintHeader();
void PrintHelp(char *binaryName);
bool ParseArgs(int argc, char* argv[], OPTIONS& configurationOptions);