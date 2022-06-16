section .data
    hw: db "Hello World", 0xa, 0x0
    len: equ $-hw
section .text
global _start
_start:
    mov eax, 4
    mov ebx, 1
    mov ecx, hw
    mov edx, len
    int 0x80

    mov eax, 1
    mov ebx, 0
    int 0x80
