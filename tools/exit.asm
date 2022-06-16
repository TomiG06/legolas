section .text
global _start
exit:
    mov eax, 1
    mov ebx, 0
    int 0x80
    ret
_start:
    call exit
