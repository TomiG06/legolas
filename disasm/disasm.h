#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>

/*
    r
    m
    imm
    seg
    rel
    ptr
    moffs
    sti
*/

struct modrm {
    uint8_t mod:2;
    uint8_t reg:3;
    uint8_t rm:3;
};

struct instr {
    uint8_t op;
    uint8_t addr;
    uint8_t seg;
    uint8_t rep;
    uint8_t repn;
    uint8_t lock;

    uint8_t extended;

    struct modrm mrm;

    uint8_t opernum;
    char descr_opers[32];

    uint8_t opcode;
    char mnemonic[16]; //it isn't that long
    uint32_t operands[4];
};

void start_disassembly(FILE* f, uint32_t text_size);

#endif
