#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <stdint.h>

extern uint32_t counter;
extern uint8_t* machine_code;

void malloc_fail_and_exit();
void read_b(FILE* f, uint8_t nb, uint32_t* ptr);

#endif
