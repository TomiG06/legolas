#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>

enum {
    r = 1,
    rm,
    m,
    imm,
    sreg,
    ptr,
    moffs,
    sti
};


struct SIB {
    uint8_t scale;
    uint8_t index;
    uint32_t base;
};

struct MODRM {
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

    struct MODRM mrm;
    struct SIB sb;

    uint8_t opernum;
    char description[4];

    uint8_t opcode;
    char mnemonic[16]; //it isn't that long
    uint32_t operands[4];
};

void start_disassembly(FILE* f, uint32_t text_size);

#endif
