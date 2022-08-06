#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "helf.h"
#include "helpers.h"

char** split0(char* str, char** array, size_t strsize) {
    str++;
    for(size_t i = 0; i < strsize; i++) {
        array[i] = (char*) calloc(strlen(str), 1);
        if(!array[i]) malloc_fail_and_exit();
        strcpy(array[i], str);
        while(*str) str++;
        str++;
    }
}

/*
    The function below reads a string from a file 
    and splits it using NULL as delimiter

    used in shstrtab and strtab
*/


char** read_str(FILE* f, size_t loc, size_t size, size_t len) {
    char* buff = (char*) malloc(size);
    char** ret = (char**) malloc(len * sizeof(char*));

    if(!buff || !ret) malloc_fail_and_exit();

    fseek(f, loc, SEEK_SET);
    fread(buff, sizeof(char), size, f);
    split0(buff, ret, len);

    return ret;
}

//This function returns the index of a section, or -1 if the section does not exist
int16_t index_of_str(char* str, char** array, size_t len) {
    for(int16_t x = 0; x < len; x++) if(!strcmp(str, array[x])) return x;
    return -1;
}

