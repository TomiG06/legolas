#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include "legolas.h"
#include "helf.h"
#include "disasm.h"

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

    Elf32_Ehdr hdr;

    fread(&hdr, sizeof(Elf32_Ehdr), 1, f);

    //Check if file is ELF
    if(strncmp(magic_num, hdr.e_ident, sizeof(magic_num))) {
        printf("File '%s' is not ELF\n", argv[1]);
        return 1;
    }

    //Check if ELF file's target ABI is System V (Linux outputs the same, at least Ubuntu does)
    if(hdr.e_ident[EI_OSABI]) {
        printf("File's target ABI is not System V\n");
        return 1;
    }

    //Check if ELF file's target is i386
    if(hdr.e_machine != EM_386) {
        printf("File '%s' is not compatible with i386\n", argv[1]);
        return 1;
    }

    //Check if ELF file is in 32-bit format
    if(hdr.e_ident[EI_CLASS] != ELFCLASS32) {
        printf("File '%s' is not 32-bit\n", argv[1]);
        return 1;
    }

    //Read section headers

    //Creating an array where section header data will be stored
    Elf32_Shdr* section_headers = malloc(sizeof(Elf32_Shdr) * hdr.e_shnum);

    //Go to the start of the section header table
    fseek(f, hdr.e_shoff, SEEK_SET);

    //Read and store section headers
    for(size_t i = 0; i < hdr.e_shnum; i++) fread(&section_headers[i], sizeof(Elf32_Shdr), 1, f);

    char** sh = read_str(f, section_headers[hdr.e_shstrndx].sh_offset, section_headers[hdr.e_shstrndx].sh_size, hdr.e_shnum);


    /*
        NASM elf contains an empty sheader
        not visible on the shstrtab, so for
        the time being these will be +1
    */
    int16_t dottext_index = index_of_str(".text", sh, hdr.e_shnum) + 1;
    int16_t symtab_index = index_of_str(".symtab", sh, hdr.e_shnum) + 1;


    if(dottext_index < 0) {
        printf(".text section not found\n");
        return 1;
    }

    /*
    fseek(f, SEQ_EL(symtab_index), SEEK_SET); //Some day
    fread(&loc, sizeof(uint32_t), 1, f);
    fread(&size, sizeof(uint32_t), 1, f);
    */
    
    fseek(f, section_headers[dottext_index].sh_offset, SEEK_SET);

    start_disassembly(f, section_headers[dottext_index].sh_size);

    fclose(f);
    return 0;
}

