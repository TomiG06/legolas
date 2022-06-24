#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "disasm.h"
#include "opcodes.h"
#include "helpers.h"

static uint8_t prefixes[] = {OP_SIZE, ADDR_SIZE, REP_REPE, REPNE, LOCK, SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS, EXTENDED};
static const size_t pfx_size = sizeof(prefixes);

char contained(uint8_t el, uint8_t arr[], const size_t size) {
    for(size_t i = 0; i < size; i++) {
        if(el == arr[i]) return 1;
    }

    return 0;
}

uint8_t* set_prefixes(FILE* f, struct instr* inst) {
    uint8_t* pfx = read_b(f, 1);
    while(contained(*pfx, prefixes, pfx_size)) {
        switch(*pfx) {
            case OP_SIZE:
                inst->op = 16;
                break;
            case ADDR_SIZE:
                inst->addr = 16;
                break;
            case REP_REPE:
                inst->rep = 1;
                break;
            case REPNE:
                inst->repn = 1;
                break;
            case LOCK:
                inst->lock = 1;
                break;
            case EXTENDED:
                inst->extended = 1;
            default:
                inst->seg = *pfx;
                break;
        }

        pfx = read_b(f, 1);
    }

    return pfx;
}

void start_disassembly(FILE* f, uint32_t text_size) {
    while(counter < text_size) {
        struct instr instruction = {32, 32, 0, 0, 0, 0, 0, 0, 0, 0};
        instruction.opcode = *set_prefixes(f, &instruction);
        printf("%d %d %d %d %d %d\nOpcode: %d\n", instruction.op, instruction.addr, instruction.rep, instruction.repn, instruction.lock, instruction.seg, instruction.opcode);
        exit(1);

        //These functions are to be built
        //set_instruction(f, &instruction);
        //print_instr(&instruction);
    }
}
