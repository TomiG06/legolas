#include "middleware.h"
#include <stdio.h>
#include <stdint.h>

char is_elf_32_x86(FILE* f) {
    uint32_t mag;
    uint8_t class;
    uint8_t data;
    uint8_t machine;

    fread(&mag, SIZE32, 1, f);  //Magic Number
    fread(&class, SIZE8, 1, f); //Class (32/64)
    fread(&data, SIZE8, 1, f);  //Data  (big/little endian)

    fseek(f, 0x12, SEEK_SET);
    fread(&machine, SIZE8, 1, f);   //Machine (x86)


    return class == f32 && machine == 3 &&
        ((mag == LITTLE_END && data == little) ||
         (mag == BIG_END    && data == big));
    
}

int main(int argc, char* argv[]) {
    FILE* f = fopen(argv[1], "rb");

    char mw = is_elf_32_x86(f);
    putchar(mw  +48);
    fclose(f);

    return !mw;
}

