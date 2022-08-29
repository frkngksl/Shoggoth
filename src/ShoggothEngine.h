#pragma once
#include<Windows.h>
#include "asmjit/asmjit.h"
#include<time.h>
#include "Structs.h"

using namespace asmjit;

class ShoggothPolyEngine
{
public:
    ShoggothPolyEngine();

    void StartEncoding(PBYTE input, uint64_t inputSize);

    PBYTE SecondDecryptor(int payloadSize, int& secondDecryptorSize);
private:
    
    CodeHolder asmjitCodeHolder;

    JitRuntime asmjitRuntime;

    x86::Assembler* asmjitAssembler;

    int startOffset = 0;
    int endOffset = 0;

    x86::Gp allRegs[16];

    x86::Gp generalPurposeRegs[14];

    ENCRYPT_TYPE *encryptListForBlocks;

    uint64_t numberOfBlocks;

    x86::Gp addressHolderForSecondEncryption;

    // -----
    void MixupArrayRegs(x86::Reg* registerArr, WORD size);

    void PushAllRegisters();
    void PopAllRegisters();

    x86::Gp GetRandomRegister();
    x86::Gp GetRandomGeneralPurposeRegister();

    void DebugBuffer(PBYTE buffer, int bufferSize);

    void StartAsmjit();
    void ResetAsmjit();

    void GenerateJumpOverRandomData();

    PBYTE GenerateRandomGarbage(int& garbageSize);

    void GenerateGarbageInstructions();

    void GenerateGarbageFunction();
    void GenerateSafeInstruction();
    void GenerateReversedInstructions();
    void GenerateJumpedInstructions();
    
    PBYTE AssembleCodeHolder(int& codeSize);

    void RandomUnsafeGarbage();
    
    PBYTE FirstEncryption(PBYTE plainPayload, int payloadSize);
    PBYTE FirstDecryptor(int payloadSize, int& firstDecryptorSize);

    PBYTE SecondEncryption(PBYTE plainPayload, int payloadSize, int& newPayloadSize);

    PBYTE GetCallInstructionOverPayload(int payloadSize, int &callSize);
    PBYTE GetPopInstructionAfterPayload(int& popSize);

    void GetRandomSecondEncryption(ENCRYPT_TYPE* encryptTypeHolder);
    PBYTE GenerateDecryptorStub(int& decryptorStubSize, int offsetToEncryptedPayload);
    void ApplyRandomSecondEncryption(uint64_t* blockCursor, ENCRYPT_TYPE* encryptTypeHolder);
};