#include "middleware.h"
#include <stdio.h>
#include <stdint.h>

char is_elf_32_x86(FILE* f) {
    uint32_t mag;
    uint8_t class;
    uint8_t machine;

    fread(&mag, SIZE32, 1, f);  //Magic Number
    fread(&class, SIZE8, 1, f); //Class (32 xpctd)

    fseek(f, 0x12, SEEK_SET);
    fread(&machine, SIZE8, 1, f);   //Machine (x86)


    return class == F32 && machine == X86 && mag == MAGIC_NUM;
    
}

int main(int argc, char* argv[]) {
    FILE* f = fopen(argv[1], "rb");
    char mw = is_elf_32_x86(f);
    fclose(f);
    return !mw;
}

