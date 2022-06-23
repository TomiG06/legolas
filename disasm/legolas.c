#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include "legolas.h"
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

static const char magic_num[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

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


    //Check if file is ELF
    if(strncmp(magic_num, hdr->e_ident, sizeof(magic_num))) {
        printf("File '%s' is not ELF\n", argv[1]);
        return 1;
    }

    //Check if ELF file is target ABI is System V (Linux outputs the same, at least Ubuntu)
    if(hdr->e_ident[EI_OSABI]) {
        printf("File's target ABI is not System V\n");
        return 1;
    }

    //Check if ELF file's target is i386
    if(hdr->e_machine != EM_386) {
        printf("File '%s' is not compatible with i386\n", argv[1]);
        return 1;
    }

    //Check if ELF file is 32-bit format
    if(hdr->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("File '%s' is not 32-bit\n", argv[1]);
        return 1;
    }

    char** sh = extract_sheaders(hdr, f);
    int16_t text_index = shindexof(".text", sh, hdr);

    uint32_t text_loc, text_size;
    
    fseek(f, SEQ_EL(text_index), SEEK_SET);
    fread(&text_loc, sizeof(uint32_t), 1, f);
    fread(&text_size, sizeof(uint32_t), 1, f);

    fseek(f, text_loc, SEEK_SET);

    fclose(f);
    return 0;
}

