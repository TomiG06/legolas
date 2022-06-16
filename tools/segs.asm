global _start
section .data
    var db 1
    var16 dw 1
    var32 dd 1
section .text
_start:
    sbb ah, ah
    sbb eax, ebx
    sbb al, [var]
    sbb eax, [var32]
    sbb al, 8
    sbb eax, 80000
    push ds
    pop ds
