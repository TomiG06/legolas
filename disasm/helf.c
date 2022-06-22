//Help + elf = Helf XD

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "helf.h"

int16_t DotText = -1;

char startswith(char* a, char* b) {
    if(strlen(a) < strlen(b)) return 0;
    for(size_t i = 0; i < strlen(b); i++) {
        if(a[i] != b[i]) return 0;
    }

    return 1;
}

char** extract_sheaders(Elf32_Ehdr* elf_h, FILE* f) {
    uint32_t sh_loc, sh_size;
    fseek(f, SEQ_EL(elf_h->e_shstrndx), SEEK_SET);
    fread(&sh_loc, sizeof(uint32_t), 1, f);
    fread(&sh_size, sizeof(uint32_t), 1, f);
    char* section_headers = (char*) malloc(sh_size);
    char** sh = (char**) malloc(elf_h->e_shnum * sizeof(char*));

    if(!section_headers || !sh) {
        printf("Malloc failed\n");
        exit(1);
    }

    fseek(f, sh_loc, SEEK_SET);

    fread(section_headers, sizeof(char), sh_size, f);

    section_headers++;
    for(size_t i = 0; i < elf_h->e_shnum; i++) {
        sh[i] = (char*) calloc(strlen(section_headers), 1);
        if(!sh[i]) {
            printf("Malloc failed\n");
            exit(1);
        }
        strcpy(sh[i], section_headers);
        while(*section_headers) section_headers++;
        section_headers++;
    }

    return sh;

}

int16_t shindexof(char* str, char** sh, Elf32_Ehdr* hdr) {
    for(int16_t x = 0; x < hdr->e_shnum; x++) {
        if(startswith(str, sh[x])) return x+1;
    }
    return -1;
}

