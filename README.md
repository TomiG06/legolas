# legolas

## Description
Legolas is an IA-32 x86 disassembler that uses a NASM like syntax.
It takes ELF files as input.

The reason this repo exists is the fact that I was bored and wanted to spend my summer holidays on a project like this.

## Notes
* extended opcodes (`0x0F` prefixed) coming soon
* instructions prefixed with `FWAIT` (`0x9B`) are not disassembled as different instructions (check opcodes like 0xD9)
* x86 32-bit opcodes reference can be found [here](http://ref.x86asm.net/coder32.html)
