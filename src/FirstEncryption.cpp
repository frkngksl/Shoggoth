#include "FirstEncryption.h"

// RC4 Encryption
PBYTE ShoggothPolyEngine::FirstEncryption(PBYTE plainPayload, int payloadSize, PBYTE key, int keySize) {
    RC4STATE state = { 0 };
    this->InitRC4State(&state, key, keySize);
    this->EncryptRC4(&state, plainPayload, payloadSize);
    return plainPayload;
}


void ShoggothPolyEngine::InitRC4State(RC4STATE* state, uint8_t* key, size_t len) {
    // Init State Structure
    for (int i = 0; i < 256; i++) {
        state->s[i] = (uint8_t)i;
    }
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


PBYTE ShoggothPolyEngine::FirstDecryptor(PBYTE cipheredPayload, int cipheredPayloadSize, PBYTE key, int keySize,int& firstDecryptorSize, int& firstEncryptionStubSize) {
    // Dummy Decryptor
    RC4STATE state = { 0 };
    PBYTE RC4DecryptorStub = 0;
    this->InitRC4State(&state, key, keySize);

    RC4DecryptorStub = this->GenerateRC4Decryptor(cipheredPayload, cipheredPayloadSize, &state, firstDecryptorSize, firstEncryptionStubSize);

    return RC4DecryptorStub;
}

PBYTE ShoggothPolyEngine::GenerateRC4Decryptor(PBYTE payload, int payloadSize, RC4STATE* statePtr,int &decryptorSize, int& firstEncryptionStubSize) {
    PBYTE returnPtr = NULL;
    PBYTE codePtr = NULL;
    PBYTE cursor = NULL;
    int RC4DecryptorSize = 0;
    int tempSize = 0;
    int counterForNop = 0;
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

    // Select registers randomly
    this->MixupArrayRegs(this->generalPurposeRegs, _countof(this->generalPurposeRegs));
    x86::Gp currentAddress = this->generalPurposeRegs[0]; // x86::rsi;
    x86::Gp endAddress = this->generalPurposeRegs[1]; // x86::r8;
    x86::Gp rc4StateAddress = this->generalPurposeRegs[2]; // x86::rdi;
    x86::Gp tempSi = this->generalPurposeRegs[3]; // x86::rax;
    x86::Gp tempSj = this->generalPurposeRegs[4]; // x86::rbx;
    x86::Gp tempi = this->generalPurposeRegs[5]; // x86::rcx;
    x86::Gp tempj = this->generalPurposeRegs[6]; // x86::rdx;
    x86::Gp tempPop = this->generalPurposeRegs[7];


    // call randomLabel
    // randomLabel:
    // pop rax (letssay)
    // add offset to stateAddress
    asmjitAssembler->call(randomLabelForCall);
    asmjitAssembler->bind(randomLabelForCall);
    callOffset = asmjitAssembler->offset();
    // Delta offset technique TODO
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
    // 

    if (this->configurationOptions.encryptOnlyDecryptor) {
        // Current length + jmp + add + rc4state
        tempSize = asmjitAssembler->offset() - this->startOffset + 1 + sizeof(RC4STATE);
        
        // jmp is two bytes
        for (counterForNop = 0; tempSize % BLOCK_SIZE && counterForNop < BLOCK_SIZE - (tempSize % BLOCK_SIZE); counterForNop++) {
            asmjitAssembler->nop();
        }

    }
    asmjitAssembler->ret();
    
    // Patch the offset
    currentOffset = asmjitAssembler->offset();
    adjustSize = currentOffset - callOffset;

    asmjitAssembler->setOffset(patchAddress);
    asmjitAssembler->dd(adjustSize);
    asmjitAssembler->setOffset(currentOffset);
    cursor = (PBYTE)statePtr;
    for (int i = 0; i < sizeof(RC4STATE); i++) {
        asmjitAssembler->db(cursor[i], 1);
    }

    codePtr = this->AssembleCodeHolder(RC4DecryptorSize);
    // this->DebugBuffer(codePtr, RC4DecryptorSize);
    returnPtr = MergeChunks(codePtr, RC4DecryptorSize, payload, payloadSize);
    this->asmjitRuntime.release(codePtr);
    // VirtualFree(codePtr, 0, MEM_RELEASE);
    VirtualFree(payload, 0, MEM_RELEASE);
    decryptorSize = RC4DecryptorSize;
    firstEncryptionStubSize = payloadSize + RC4DecryptorSize;
    HeapFree(GetProcessHeap(), NULL, randomStringForLoop);
    HeapFree(GetProcessHeap(), NULL, randomStringForEnd);
    HeapFree(GetProcessHeap(), NULL, randomStringForCall);
    return returnPtr;
}
