#include "middleware.h"
#include <stdint.h>
#include <stdio.h>
#include <elf.h>

char is_elf_32_x86(Elf32_Ehdr* h) {
    return h->e_machine == EM_386 && 
           h->e_ident[EI_CLASS] == ELFCLASS32 &&
           h->e_ident[EI_MAG0] == ELFMAG0 &&
           h->e_ident[EI_MAG1] == ELFMAG1 &&
           h->e_ident[EI_MAG2] == ELFMAG2 &&
           h->e_ident[EI_MAG3] == ELFMAG3;
}
