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
    ~ShoggothPolyEngine();

    // Generic Start Function
    ERRORCASES PolymorphicEncryption(PBYTE lpInputBuffer, DWORD dwInputBuffer, PBYTE &lpOutputBuffer, DWORD &lpdwOutputSize);

    void StartEncoding(PBYTE input, uint64_t inputSize);

    void GenerateJumpOverRandomData();
private:
    
    // a structure describing the values of the output registers
    typedef struct _SPE_OUTPUT_REGS {

        // target register
        x86::Gp regDst;

        // value to write in this register
        unsigned long long dwValue;

    } SPE_OUTPUT_REGS, * P_SPE_OUTPUT_REGS;

    // description of an encryption operation
    typedef struct _SPE_CRYPT_OP {

        // TRUE if the operation is performed
        // on two registers; FALSE if it is
        // performed between the target register
        // and the value in dwCryptValue
        BOOL bCryptWithReg;

        x86::Gp regDst;
        x86::Gp regSrc;

        // encryption operation
        BYTE cCryptOp;

        // encryption value
        unsigned long dwCryptValue;

    } SPE_CRYPT_OP, * P_SPE_CRYPT_OP;

    CodeHolder asmjitCodeHolder;

    JitRuntime asmjitRuntime;

    // buffer with the encryption operations
    void *diCryptOps;

    // pointer to the table of encryption
    // operations
    P_SPE_CRYPT_OP lpcoCryptOps;

    // count of encryption operations
    DWORD dwCryptOpsCount;

    // pointer to the encrypted data block
    void *diEncryptedData;

    // number of blocks of encrypted data
    DWORD dwEncryptedBlocks;

    // encryption key
    unsigned long long dwEncryptionKey;

    // AsmJit Assembler instance
    x86::Assembler* asmjitAssembler;

    // the register which will store a pointer
    // to the data which is to be decrypted
    x86::Gp regSrc;

    // the register which will store a pointer
    // to the output buffer
    x86::Gp regDst;

    // the register which hold the size of the
    // encrypted data
    x86::Gp regSize;

    // the register with the encryption key
    x86::Gp regKey;

    // the register on which the decryption
    // instructions will operate
    x86::Gp regData;

    // the preserved registers (r12:r15, rdi, rsi, rbx in random order)
    x86::Gp regSafe1, regSafe2, regSafe3, regSafe4, regSafe5, regSafe6, regSafe7;

    // the delta_offset label
    Label lblDeltaOffset;

    // the position of the delta offset
    size_t posDeltaOffset;

    // the relative address of the encrypted data
    size_t posSrcPtr;

    // the size of the unused code between delta
    // offset and the instructions which get that
    // value from the stack
    DWORD dwUnusedCodeSize;

    int startOffset = 0;
    int endOffset = 0;

    x86::Gp allRegs[16];

    x86::Gp generalPurposeRegs[14];

    // helper methods
    void RandomizeRegisters();
    void GeneratePrologue();
    void GenerateDeltaOffset();
    void EncryptInputBuffer(PBYTE lpInputBuffer, DWORD dwInputBuffer, DWORD dwMinInstr, DWORD dwMaxInstr);
    void SetupDecryptionKeys();
    void GenerateDecryption();
    void SetupOutputRegisters(SPE_OUTPUT_REGS* regOutput, DWORD dwCount);
    void GenerateEpilogue(DWORD dwParamCount);
    void AlignDecryptorBody(DWORD dwAlignment);
    void AppendEncryptedData();
    void UpdateDeltaOffsetAddressing();

    // -----
    void MixupArrayOutputRegs(SPE_OUTPUT_REGS* registerArr, WORD size);
    void MixupArrayRegs(x86::Reg* registerArr, WORD size);

    void PushAllRegisters();
    void PopAllRegisters();

    x86::Gp GetRandomRegister();
    x86::Gp GetRandomGeneralPurposeRegister();

    void DebugCurrentCodeBuffer();

    void StartAsmjit();
    void ResetAsmjit();

    void GenerateRandomGarbage();

    void GenerateGarbageInstructions();

    void GenerateGarbageFunction();
    void GenerateSafeInstruction();
    void GenerateReversedInstructions();
    void GenerateJumpedInstructions();
    

    void RandomUnsafeGarbage();
    
};