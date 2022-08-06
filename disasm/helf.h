#ifndef HELF_H
#define HELF_H

#include <stdint.h>

char** read_str(FILE* f, size_t loc, size_t size, size_t len);
int16_t index_of_str(char* str, char** array, size_t len);

#endif
