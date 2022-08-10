#include <stdint.h>
#include <string.h>
#include <elf.h>
#include "helf.h"

//This function returns the index of a section, or -1 if the section does not exist
int16_t index_of_str_in_sh(char* str, char* tab, Elf32_Shdr* array, size_t len) {
    for(int16_t x = 0; x < len; x++) if(!strcmp(str, tab + array[x].sh_name)) return x;
    return -1;
}

