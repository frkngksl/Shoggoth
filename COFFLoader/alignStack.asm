extern RunCOFF
global alignstack

segment .text

alignstack:
    push rdi
    mov rdi, rsp
    and rsp, byte -0x10
    sub rsp, byte +0x20
    call RunCOFF
    mov rsp, rdi
    pop rdi
    ret
