#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <elf.h>

#define MAG_N  0x464c457f

char is_elf_32_x86(Elf32_Ehdr* h);


#endif
