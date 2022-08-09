#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include "helf.h"
#include "disasm.h"
#include "helpers.h"

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
    if(!section_headers) malloc_fail_and_exit();

    //Go to the start of the section header table
    fseek(f, hdr.e_shoff, SEEK_SET);

    //Read and store section headers
    for(size_t i = 0; i < hdr.e_shnum; i++) fread(&section_headers[i], sizeof(Elf32_Shdr), 1, f);

    //Read section header table
    char* sh = (char*)malloc(section_headers[hdr.e_shstrndx].sh_size);
    if(!sh) malloc_fail_and_exit();

    fseek(f, section_headers[hdr.e_shstrndx].sh_offset, SEEK_SET);

    fread(sh, section_headers[hdr.e_shstrndx].sh_size, 1, f);


    /*
        NASM elf contains an empty section header
        not visible on the shstrtab, so for
        the time being these will be +1
    */
    int16_t dottext_index = index_of_str_in_sh(".text", sh, section_headers, hdr.e_shnum);
    int16_t dotsymtab_index = index_of_str_in_sh(".symtab", sh, section_headers, hdr.e_shnum);
    int16_t dotstrtab_index = index_of_str_in_sh(".strtab", sh, section_headers, hdr.e_shnum);

    if(dottext_index < 0) {
        printf(".text section not found\n");
        return 1;
    }

    //Number of entries in .symtab
    size_t entries = section_headers[dotsymtab_index].sh_size / section_headers[dotsymtab_index].sh_entsize;

    Elf32_Sym* symtab = malloc(sizeof(Elf32_Sym) * entries);
    if(!symtab) malloc_fail_and_exit();
    
    //Go to the beginning of .symtab
    fseek(f, section_headers[dotsymtab_index].sh_offset, SEEK_SET);

    //Read entries
    for(size_t i = 0; i < entries; i++) fread(&symtab[i], sizeof(Elf32_Sym), 1, f);

    //Read .strtab
    char* strtab = malloc(section_headers[dotstrtab_index].sh_size);
    fseek(f, section_headers[dotstrtab_index].sh_offset, SEEK_SET);
    fread(strtab, section_headers[dotstrtab_index].sh_size, 1, f);

    //Filter out symbols that belong in .text
    size_t text_syms_count = 0;
    for(size_t i = 0; i < entries; i++) if(symtab[i].st_shndx == dottext_index && !ELF32_ST_TYPE(symtab[i].st_info)) text_syms_count++;

    Elf32_Sym* dottext_syms = malloc(sizeof(Elf32_Sym) * text_syms_count);

    for(size_t i = 0, c = 0; i < entries; i++) if(symtab[i].st_shndx == dottext_index && !ELF32_ST_TYPE(symtab[i].st_info)) dottext_syms[c++] = symtab[i];
    
    //Go to the beginning of .text
    fseek(f, section_headers[dottext_index].sh_offset, SEEK_SET);

    start_disassembly(f, section_headers[dottext_index].sh_size, strtab, dottext_syms, text_syms_count);

    free(section_headers);
    free(sh);

    fclose(f);
    return 0;
}

