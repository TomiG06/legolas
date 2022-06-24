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
uint8_t* read_b(FILE* f, uint32_t nb) {
    uint8_t* ret = (uint8_t*) malloc(nb);
    if(!ret) malloc_fail_and_exit();
    fread(ret, nb, 1, f);
    counter += nb;
    return ret;
}

