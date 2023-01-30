# legolas

## Description
Legolas is an IA-32 x86 disassembler that uses a NASM like syntax.
It takes ELF files as input.

## Point of Existence
I have been building this program for 3 main reasons:
* Learn C
* Learn to maintain medium sized projects
* Learn more about machine language and how an x86 CPU works

## Notes
* the project is still under development
* extended opcodes (`0x0F` prefixed) under developement
* instructions prefixed with `FWAIT` (`0x9B`) are not disassembled as different instructions (check opcodes like 0xD9)
* x86 32-bit opcodes reference can be found [here](http://ref.x86asm.net/coder32.html)
