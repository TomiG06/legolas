#ifndef HELF_H
#define HELF_H

#include <stdint.h>

int16_t index_of_str_in_sh(char* str, char* tab, Elf32_Shdr* array, size_t len);

#endif
