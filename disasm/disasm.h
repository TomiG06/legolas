#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>

struct instr {
    uint8_t op;
    uint8_t addr;
    uint8_t seg;
    uint8_t rep;
    uint8_t repn;
    uint8_t lock;

    uint8_t extended;

    uint8_t mod;
    uint8_t rm;
    uint8_t reg;

    uint8_t opcode;
    char mnemonic[16]; //it isn't that long
    uint8_t opernum;
    uint32_t oper1;
    uint32_t oper2;
    uint32_t oper3;
    uint32_t oper4;
};

void start_disassembly(FILE* f, uint32_t text_size);

#endif
