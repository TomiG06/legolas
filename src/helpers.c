#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
    We are using it because we want to keep track of the bytes read so that
    they will not exceed the size of the .text section
*/
uint32_t counter = 0;

//Used a lot
void malloc_fail_and_exit() {
    puts("Malloc Failed");
    exit(1);
}

//custom fread in order to also keep track of the bytes
void read_b(FILE* f, uint8_t nb, uint32_t* ptr) {
    fread(ptr, nb, 1, f);
    counter += nb;
}

