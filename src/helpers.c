#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
    We are using it because we want to keep track of the bytes read so that
    we won't exceed the size of the section we are reading
*/
uint32_t counter = 0;

/* stores the machine code (i am bored of passing it in every function) */
uint8_t* machine_code;

//Used a lot
void malloc_fail_and_exit() {
    puts("Malloc Failed");
    exit(1);
}

//Custom fread in order to also keep track of the bytes
void read_b(FILE* f, uint8_t nb, uint32_t* ptr) {
    switch(nb) {
        case 1:
            *ptr = *(uint8_t*)  (machine_code + counter);
            break;
        case 2:
            *ptr = *(uint16_t*) (machine_code + counter);
            break;
        case 4:
            *ptr = *(uint32_t*) (machine_code + counter);
            break;
    }

    counter += nb;
}

