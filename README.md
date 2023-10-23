# Shoggoth

<img src="https://github.com/frkngksl/Shoggoth/blob/main/img/logo.png?raw=true">

<div align="center">
 <a href="https://twitter.com/R0h1rr1m">
    <img src="https://img.shields.io/badge/License-MIT-green">
 </a>
 <a href="https://github.com/frkngksl/Shoggoth/issues">
    <img src="https://img.shields.io/github/issues/frkngksl/Shoggoth">
 </a>
 <a href="https://github.com/frkngksl/Shoggoth">
    <img src="https://img.shields.io/github/stars/frkngksl/Shoggoth?color=green&style=flat-square">
 </a>
<a href="https://twitter.com/R0h1rr1m">
    <img src="https://img.shields.io/twitter/follow/R0h1rr1m?style=social">
 </a>
</div>

**Presented at**
- [BlackHat Europe 2022 Arsenal](https://www.blackhat.com/eu-22/arsenal/schedule/index.html#shoggoth-asmjit-based-polymorphic-encryptor-29588) - [Presentation Record](https://www.youtube.com/watch?v=ECbQnbPxz5g)

# Introduction

## Description

Shoggoth is an open-source project based on C++ and asmjit library used to encrypt given shellcode, PE, and COFF files polymorphically.

Shoggoth will generate an output file that stores the payload and its corresponding loader in an obfuscated form. Since the content of the output is position-independent, it can be executed directly as a shellcode. While the payload is executing, it decrypts itself at runtime. In addition to the encryption routine, Shoggoth also adds garbage instructions, that change nothing, between routines.

I started to develop this project to study different dynamic instruction generation approaches, assembly practices, and signature detections. I am planning to regularly update the repository with my new learnings.

# Features

Current features are listed below:

- Works on only x64 inputs
- Ability to merge PIC COFF Loader with COFF or BOF input files
- Ability to merge PIC PE Loader with PE input files
- Stream Cipher with RC4 Algorithm
- Block Cipher with randomly generated operations
- Garbage instruction generation


## Execution Flow

The general execution flow of Shoggoth for an input file can be seen in the image below. You can observe this flow with the default configurations.

<img src="https://github.com/frkngksl/Shoggoth/blob/main/img/ShoggothExecutionFlow.png">

Basically, Shoggoth first merges the precompiled loader shellcode according to the chosen mode (COFF or PE file) and the input file. It then adds multiple garbage instructions it generates to this merged payload. The stub containing the loader, garbage instruction, and payload is encrypted first with RC4 encryption and then with randomly generated block encryption by combining corresponding decryptors. Finally, it adds a garbage instruction to the resulting block.

## Machine Code Generation

While Shoggoth randomly generates instructions for garbage stubs or encryption routines, it uses [AsmJit](https://asmjit.com/) library.

AsmJit is a lightweight library for machine code generation written in C++ language. It can generate machine code for X86, X86_64, and AArch64 architectures and supports baseline instructions and all recent extensions. AsmJit allows specifying operation codes, registers, immediate operands, call labels, and embedding arbitrary values to any offset inside the code. While generating some assembly instructions by using AsmJit, it is enough to call the API function that corresponds to the required assembly operation with assembly operand values from the Assembler class. For each API call, AsmJit holds code and relocation information in its internal CodeHolder structure. After calling API functions of all assembly commands to be generated, its JitRuntime class can be used to copy the code from CodeHolder into memory with executable permission and relocate it.

While I was searching for a code generation library, I encountered with AsmJit, and I saw that it is widely used by many popular projects. That's why I decided to use it for my needs. I don't know whether Shoggoth is the first project that uses it in the red team context, but I believe that it can be a reference for future implementations.

## COFF and PE Loaders

Shoggoth can be used to encrypt given PE and COFF files so that both of them can be executed as a shellcode thanks to precompiled position-independent loaders. I simply used the *C to Shellcode* method to obtain the PIC version of well-known PE and COFF loaders I modified for my old projects. For compilation, I used the Makefile from [HandleKatz](https://github.com/codewhitesec/HandleKatz) project which is an LSASS dumper in PIC form.

Basically, in order to obtain shellcode with the C to Shellcode technique, I removed all the global variables in the loader source code, made all the strings stored in the stack, and resolved the Windows API functions' addresses by loading and parsing the necessary DLLs at runtime. Afterward, I determined the entry point with a linker script and compiled the code by using MinGW with various compilation flags. I extracted the .text section of the generated executable file and obtained the loader shellcode. Since the executable file obtained after editing the code as above does not contain any sections other than the .text section, the code in this section can be used as position-independent.

The source code of these can be seen and edited from [COFFLoader](https://github.com/frkngksl/Shoggoth/tree/main/COFFLoader) and [PELoader](https://github.com/frkngksl/Shoggoth/tree/main/PELoader) directories. Also compiled versions of these source codes can be found in [stub](https://github.com/frkngksl/Shoggoth/tree/main/stub) directory. For now, If you want to edit or change these loaders, you should obey the signatures and replace the precompiled binaries from the stub directory.

## RC4 Cipher

Shoggoth first uses one of the stream ciphers, the RC4 algorithm, to encrypt the payload it gets. After randomly generating the key used here, it encrypts the payload with that key. The decryptor stub, which decrypts the payload during runtime, is dynamically created and assembled by using AsmJit. The registers used in the stub are randomly selected for each sample.

I referenced Nayuki's [code](https://www.nayuki.io/page/rc4-cipher-in-x86-assembly) for the implementation of the RC4 algorithm I used in Shoggoth.

## Random Block Cipher

After the first encryption is performed, Shoggoth uses the second encryption which is a randomly generated block cipher. With the second encryption, it encrypts both the RC4 decryptor and optionally the stub that contains the payload, garbage instructions, and loader encrypted with RC4. It divides the chunk to be encrypted into 8-byte blocks and uses randomly generated instructions for each block. These instructions include ADD, SUB, XOR, NOT, NEG, INC, DEC, ROL, and ROR. Operands for these instructions are also selected randomly.

## Garbage Instruction Generation

Generated garbage instruction logic is heavily inspired by Ege Balci's amazing [SGN](https://github.com/EgeBalci/sgn) project. Shoggoth can select garbage instructions based on jumping over random bytes, instructions with no side effects, fake function calls, and instructions that have side effects but retain initial values. All these instructions are selected randomly, and generated by calling the corresponding API functions of the AsmJit library. Also, in order to increase both size and different combinations, these generation functions are called recursively.

There are lots of places where garbage instructions can be put in the first version of Shoggoth. For example, we can put garbage instructions between block cipher instructions or RC4 cipher instructions. However, for demonstration purposes, I left them for the following versions to avoid the extra complexity of generated payloads.

# Usage

## Requirements

I didn't compile the main project. That's why you have to compile yourself. Optionally, if you want to edit the source code of the PE loader or COFF loader, you should have MinGW on your machine to compile them by using the given Makefiles.

- Visual Studio 2019+
- (Optional) MinGW Compiler

## Command Line Parameters

```

  ______ _                                  _
 / _____) |                             _  | |
( (____ | |__   ___   ____  ____  ___ _| |_| |__
 \____ \|  _ \ / _ \ / _  |/ _  |/ _ (_   _)  _ \
 _____) ) | | | |_| ( (_| ( (_| | |_| || |_| | | |
(______/|_| |_|\___/ \___ |\___ |\___/  \__)_| |_|
                    (_____(_____|

                     by @R0h1rr1m

                "Tekeli-li! Tekeli-li!"

Usage of Shoggoth.exe:

    -h | --help                             Show the help message.
    -v | --verbose                          Enable more verbose output.
    -i | --input <Input Path>               Input path of payload to be encrypted. (Mandatory)
    -o | --output <Output Path>             Output path for encrypted input. (Mandatory)
    -s | --seed <Value>                     Set seed value for randomization.
    -m | --mode <Mode Value>                Set payload encryption mode. Available mods are: (Mandatory)
                                                [*] raw - Shoggoth doesn't append a loader stub. (Default mode)
                                                [*] pe - Shoggoth appends a PE loader stub. The input should be valid x64 PE.
                                                [*] coff - Shoggoth appends a COFF loader stub. The input should be valid x64 COFF.
    --coff-arg <Argument>                   Set argument for COFF loader. Only used in COFF loader mode.
    -k | --key <Encryption Key>             Set first encryption key instead of random key.
    --dont-do-first-encryption              Don't do the first (stream cipher) encryption.
    --dont-do-second-encryption             Don't do the second (block cipher) encryption.
    --encrypt-only-decryptor                Encrypt only decryptor stub in the second encryption.

```

# What does Shoggoth mean?
<p align="center">
<img width="800" height="500" src="https://github.com/frkngksl/Shoggoth/blob/main/img/shoggoth.jpg?raw=true">
</p>

<br>

> "It was a terrible, indescribable thing vaster than any subway train—a shapeless congeries of protoplasmic bubbles, faintly self-luminous, and with myriads of temporary eyes forming and un-forming as pustules of greenish light all over the tunnel-filling front that bore down upon us, crushing the frantic penguins and slithering over the glistening floor that it and its kind had swept so evilly free of all litter."
> ~ H. P. Lovecraft, At the Mountains of Madness

<br>

A Shoggoth is a fictional monster in the Cthulhu Mythos. The beings were mentioned in passing in H. P. Lovecraft's sonnet cycle Fungi from Yuggoth (1929–30) and later described in detail in his novella At the Mountains of Madness (1931). They are capable of forming whatever organs or appendages they require for the task at hand, although their usual state is a writhing mass of eyes, mouths, and wriggling tentacles.

Since these creatures are like a sentient blob of self-shaping, gelatinous flesh and have no fixed shape in Lovecraft's descriptions, I want to give that name to a Polymorphic Encryptor tool. :slightly_smiling_face:

# References

- https://github.com/EgeBalci/sgn
- https://github.com/asmjit/asmjit
- https://www.pelock.com/articles/polymorphic-encryption-algorithms
- https://github.com/codewhitesec/HandleKatz
- https://github.com/vxunderground/MalwareSourceCode
- https://www.nayuki.io/page/rc4-cipher-in-x86-assembly
- https://www.deviantart.com/halycon450/art/Shoggoth-914584713
- https://www.artstation.com/burakkrtak (Logo Designer)
