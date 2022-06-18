#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define SIZE32      sizeof(uint32_t)
#define SIZE8       sizeof(uint8_t)

#define MAGIC_NUM   0x464c457f
#define X86         3
#define F32         1

char is_elf_and_32_bits(FILE* f);

#endif
