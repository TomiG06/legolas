#ifndef HELF_H
#define HELF_H

#include <stdint.h>

#define START 0x78 //I somehow reverse engineered that number so it might be wrong
#define SEQ_EL(idx) START + (idx) * 40

char** extract_sheaders(Elf32_Ehdr* elf_h, FILE* f);
int16_t shindexof(char* header, char** headers, Elf32_Ehdr* h);

#endif
