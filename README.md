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
- [BlackHat Europe 2022](https://www.blackhat.com/eu-22/arsenal/schedule/index.html#shoggoth-asmjit-based-polymorphic-encryptor-29588)

# Introduction

## Description

Shoggoth is an open-source project based on C++ and asmjit library used to encrypt given shellcode, PE and COFF files polymorphically. 

Shoggoth will generate an output file that stores the payload and its corresponding loader in an obfuscated form. Since the content of output is position-independent, it can be executed directly as a shellcode. While the payload is executing, it decrypts itself at the runtime. In addition to encryption routine, Shoggoth also adds garbage instructions, that change nothing, between routines.

I started to develop this project to study different dynamic instruction generation approaches, assembly practices, and signature detections. I am planning to regularly update the repository with my new learnings. 


## What does Shoggoth mean?
<p align="center">
<img width="800" height="500" src="https://github.com/frkngksl/Shoggoth/blob/main/img/shoggoth.jpg?raw=true">
</p>

<br>

> "It was a terrible, indescribable thing vaster than any subway train—a shapeless congeries of protoplasmic bubbles, faintly self-luminous, and with myriads of temporary eyes forming and un-forming as pustules of greenish light all over the tunnel-filling front that bore down upon us, crushing the frantic penguins and slithering over the glistening floor that it and its kind had swept so evilly free of all litter."
> ~ H. P. Lovecraft, At the Mountains of Madness

<br>

A Shoggoth is a fictional monster in the Cthulhu Mythos. The beings were mentioned in passing in H. P. Lovecraft's sonnet cycle Fungi from Yuggoth (1929–30) and later described in detail in his novella At the Mountains of Madness (1931). They are capable of forming whatever organs or appendages they require for the task at hand, although their usual state is a writhing mass of eyes, mouths and wriggling tentacles.



Since these creatures are like a sentient blob of self-shaping, gelatinous flesh and have no fixed shape in Lovecraft's descriptions, I want to give that name to a Polymorphic Encryptor tool. :slightly_smiling_face: 

# Features

# Usage

# References

- https://github.com/EgeBalci/sgn
- https://github.com/asmjit/asmjit
- https://www.pelock.com/articles/polymorphic-encryption-algorithms
- https://github.com/codewhitesec/HandleKatz
- https://github.com/vxunderground/MalwareSourceCode
- https://www.nayuki.io/page/rc4-cipher-in-x86-assembly
- https://www.deviantart.com/halycon450/art/Shoggoth-914584713

# Disclaimer

I shared this tool only for showing the code snippets of well known TTPs. I'm not responsible for the use of this tool for malicious activities.
