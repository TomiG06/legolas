//Help + elf = Helf XD

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "helf.h"
#include "helpers.h"

/*
    The function below returns a string array
    of the section headers

    It first finds the location and size of
    the section header table, it then reads the
    contents of it and finally stores them in
    a string array
*/

char** extract_sheaders(Elf32_Ehdr* elf_h, FILE* f) {
    uint32_t sh_loc, sh_size;
    fseek(f, START + (elf_h->e_shstrndx-1) * 40, SEEK_SET);
    fread(&sh_loc, sizeof(uint32_t), 1, f);
    fread(&sh_size, sizeof(uint32_t), 1, f);
    char* section_headers = (char*) malloc(sh_size);
    char** sh = (char**) malloc(elf_h->e_shnum * sizeof(char*));

    if(!section_headers || !sh) malloc_fail_and_exit();

    fseek(f, sh_loc, SEEK_SET);

    fread(section_headers, sizeof(char), sh_size, f);

    section_headers++;
    for(size_t i = 0; i < elf_h->e_shnum; i++) {
        sh[i] = (char*) calloc(strlen(section_headers), 1);
        if(!sh[i]) malloc_fail_and_exit();
        strcpy(sh[i], section_headers);
        while(*section_headers) section_headers++;
        section_headers++;
    }

    return sh;
}

//This function returns the index of a section, or -1 if the section does not exist
int16_t shindexof(char* str, char** sh, Elf32_Ehdr* hdr) {
    for(int16_t x = 0; x < hdr->e_shnum; x++) {
        if(!strcmp(str, sh[x])) return x;
    }
    return -1;
}

