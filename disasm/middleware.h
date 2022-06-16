#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define SIZE32      sizeof(uint32_t)
#define SIZE8       sizeof(uint8_t)

#define LITTLE_END  0x464c457f
#define BIG_END     0x7f454c46

enum {
    f32 = 1,
    f64 // Not used for the momment
};

enum {
    little = 1,
    big
};

char is_elf_and_32_bits(FILE* f);

#endif
