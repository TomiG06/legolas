#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include "disasm.h"
#include "helpers.h"

static const char magic_num[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

//This function returns the index of a section, or -1 if the section does not exist
int16_t index_of_str_in_sh(char* str, char* tab, Elf32_Shdr* array, size_t len) {
    for(size_t x = 0; x < len; x++) if(!strcmp(str, tab + array[x].sh_name)) return x;
    return -1;
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

    Elf32_Ehdr hdr;

    fread(&hdr, sizeof(Elf32_Ehdr), 1, f);

    //Check if file is ELF
    if(strncmp(magic_num, (const char*) hdr.e_ident, sizeof(magic_num))) {
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

    //Get indexes of .symtab and .strtab

    int16_t dotsymtab_index = index_of_str_in_sh(".symtab", sh, section_headers, hdr.e_shnum);
    int16_t dotstrtab_index = index_of_str_in_sh(".strtab", sh, section_headers, hdr.e_shnum);

    char* strtab = NULL;
    size_t entries;
    Elf32_Sym* symtab = NULL;

    if(dotsymtab_index > 0) {

       //Number of entries in .symtab

       entries = section_headers[dotsymtab_index].sh_size / sizeof(Elf32_Sym);

       symtab = malloc(sizeof(Elf32_Sym) * entries);
       if(!symtab) malloc_fail_and_exit();
    
       //Go to the beginning of .symtab
       fseek(f, section_headers[dotsymtab_index].sh_offset, SEEK_SET);

       //Read entries
       for(size_t i = 0; i < entries; i++) fread(&symtab[i], sizeof(Elf32_Sym), 1, f);

       //Read .strtab
       strtab = malloc(section_headers[dotstrtab_index].sh_size);
       fseek(f, section_headers[dotstrtab_index].sh_offset, SEEK_SET);
       fread(strtab, section_headers[dotstrtab_index].sh_size, 1, f);
    }

    /*
        Loop through each section
    */
    for(size_t i = 0; i < hdr.e_shnum; i++) {
        //Check if section holds holds instructions 
        //TODO: .rodata section shall not pass (it passes for the time being)

        if(section_headers[i].sh_type != SHT_PROGBITS) continue;
        if(section_headers[i].sh_flags & SHF_WRITE) continue;
        
        //Filter out symbols that belong in the section
        size_t section_syms_count = 0;

        Elf32_Sym* section_syms = NULL;

        if(dotsymtab_index > 0) {
            for(size_t j = 0; j < entries; j++) if(symtab[j].st_shndx == i && !ELF32_ST_TYPE(symtab[j].st_info)) section_syms_count++;

            section_syms = malloc(sizeof(Elf32_Sym) * section_syms_count);

            for(size_t j = 0, c = 0; j < entries; j++) if(symtab[j].st_shndx == i && !ELF32_ST_TYPE(symtab[j].st_info)) section_syms[c++] = symtab[j];
        }

        //Go to the beginning of the section
        fseek(f, section_headers[i].sh_offset, SEEK_SET);

        machine_code = malloc(section_headers[i].sh_size);
        if(!machine_code) malloc_fail_and_exit();

        fread(machine_code, section_headers[i].sh_size, 1, f);

        //Inform the user which section is being disassembled
        printf("\nDisassembly of section %s:\n\n", sh+section_headers[i].sh_name);

        //Actually disassembling the section
        start_disassembly(section_headers[i], strtab, section_syms, section_syms_count);

        if(section_syms) free(section_syms);

        //Zero the counter
        counter = 0;
    }

    //Free allocated memory
    free(section_headers);
    free(sh);
    if(symtab) free(symtab);
    if(strtab) free(strtab);

    //Close the file
    fclose(f);

    return 0;
}

