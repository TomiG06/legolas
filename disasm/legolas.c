#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>
#include "legolas.h"
#include "middleware.h"
#include "helf.h"

Elf32_Ehdr* elf_header(FILE* f) {
    static Elf32_Ehdr hdr;
    fread(hdr.e_ident, sizeof(char), EI_NIDENT, f);
    fread(&hdr.e_type, SHalf, 1, f);
    fread(&hdr.e_machine, SHalf, 1, f);
    fread(&hdr.e_version, SWord, 1, f); 
    fread(&hdr.e_entry, SAddr, 1, f); 
    fread(&hdr.e_phoff, SOff, 1, f); 
    fread(&hdr.e_shoff, SOff, 1, f);
    fread(&hdr.e_flags, SWord, 1, f); 
    fread(&hdr.e_ehsize, SHalf, 1, f); 
    fread(&hdr.e_phentsize, SHalf, 1, f); 
    fread(&hdr.e_phnum, SHalf, 1, f);
    fread(&hdr.e_shentsize, SHalf, 1, f);
    fread(&hdr.e_shnum, SHalf, 1, f);
    fread(&hdr.e_shstrndx, SHalf, 1, f);
    return &hdr;
}

int main(int argc, char* argv[]) {
    if(argc == 1) {
        printf("No input file\n");
        return 1;
    }

    if(access(argv[1], F_OK)) {
        printf("File '%s' does not exist\n", argv[1]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");

    Elf32_Ehdr* hdr = elf_header(f);

    if(!is_elf_32_x86(hdr)) {
        printf("File '%s' is not ELF\n", argv[1]);
        return 1;
    }

    char** sh = extract_sheaders(hdr, f);

    uint32_t text_loc, text_size;
    
    fseek(f, SEQ_EL(DotText), SEEK_SET);
    fread(&text_loc, sizeof(uint32_t), 1, f);
    fread(&text_size, sizeof(uint32_t), 1, f);

    fseek(f, text_loc, SEEK_SET);

    uint32_t buff;

    for(int x = 0; x < text_size; x += 4) {
        fread(&buff, sizeof(uint32_t), 1, f);
        printf("%x\n", buff);
    }

    fclose(f);
    return 0;
}

