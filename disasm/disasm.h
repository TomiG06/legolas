#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>

//operand descriptions
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

/*
    indicates register size
    (bitmask)

    if size is the same as instruction.op
    then there is no need for it
*/
enum {
    r8 = 8,
    r16,
    r32
};


struct SIB {
    uint8_t scale:2;
    uint8_t index:3;
    uint8_t base:3;
};

struct MODRM {
    uint8_t mod:2;
    uint8_t reg:3;
    uint8_t rm:3;
};

struct instr {
    //prefixes
    uint8_t op;
    uint8_t addr;
    uint8_t seg;
    uint8_t rep;
    uint8_t repn;
    uint8_t lock;

    uint8_t extended;

    //check opcodes like 0x90 (PAUSE)
    uint8_t f3_not_rep;

    //bytes
    struct MODRM mrm;
    struct SIB sb;

    //number of operands
    uint8_t opernum;

    //description of each operand (4 operands are the maximum amount)
    char description[4];

    //if sib byte exists, this is set to 1
    uint8_t hasSIB;

    uint8_t mnem_is_set;

    uint8_t opcode;
    char mnemonic[16]; //it isn't that long
    uint32_t operands[4];
};

void start_disassembly(FILE* f, uint32_t text_size);

#endif
