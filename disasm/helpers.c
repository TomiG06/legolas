#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

