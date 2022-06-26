#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "disasm.h"
#include "opcodes.h"
#include "registers.h"
#include "helpers.h"

static uint8_t prefixes[] = {OP_SIZE, ADDR_SIZE, REP_REPE, REPNE, LOCK, SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS, EXTENDED};
static const size_t pfx_size = sizeof(prefixes);

char contained(uint8_t el, uint8_t arr[], const size_t size) {
    for(size_t i = 0; i < size; i++) {
        if(el == arr[i]) return 1;
    }

    return 0;
}

uint8_t set_prefixes(FILE* f, struct instr* inst) {
    uint32_t pfx = 0;
    read_b(f, 1, &pfx);
    printf("Pfx: %x\n", pfx);
    //if 'pfx' is not contained in prefixes, this means that 'pfx' is an opcode
    while(contained(pfx, prefixes, pfx_size)) {
        switch(pfx) {
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
                inst->seg = pfx;
                break;
        }

        read_b(f, 1, &pfx);
    }

    return (uint8_t)pfx;
}

void mod_rm(uint8_t* byte, struct instr* inst) {
    inst->mrm.mod = *byte >> 6;
    inst->mrm.reg = *byte >> 3 & 7;
    inst->mrm.rm  = *byte & 7;
}

void set_mn(struct instr* i, char* mnemonic) { strcpy(i->mnemonic, mnemonic); }

void rm81632_r81632(FILE* f, char* mnemonic, uint8_t rm8_r8_op, struct instr* inst) {
    if(inst->opcode == rm8_r8_op) {
        inst->op = 8;
        inst->addr = 8;
    } else if(inst->op == 16) inst->addr = 16;

    uint32_t buff;
    read_b(f, 1, &buff);
    set_mn(inst, mnemonic);
    strcpy(inst->descr_opers, "rm_r");
    mod_rm((uint8_t*)&buff, inst);

    switch(inst->mrm.mod) {
        case 0:
            inst->oper1 = inst->mrm.reg;
            read_b(f, 4, &inst->oper2);
            break;
        case 3:
            inst->oper1 = inst->mrm.rm;
            inst->oper2 = inst->mrm.reg;
            break;
    }
}

void r81632_rm81632(FILE* f, char* mnemonic, uint8_t r8_rm8_op, struct instr* inst) {
    uint32_t buff;
    read_b(f, 1, &buff);
    mod_rm((uint8_t*)&buff, inst);

    set_mn(inst, mnemonic);
    strcpy(inst->descr_opers, "r_rm");

    if(inst->opcode == r8_rm8_op) {
        inst->op = 8;
        inst->addr = 8;
    } else if(inst->op == 16) inst->addr = 16;

    inst->oper1 = inst->mrm.reg;
    read_b(f, 4, &inst->oper2);
}

void smth_aleax(FILE* f, char* mnemonic, uint8_t imm8, struct instr* inst) {
    inst->oper1 = eax;
    set_mn(inst, mnemonic);
    strcpy(inst->descr_opers, "ra_imm");

    if(inst->opcode == imm8) inst->op = 8;

    read_b(f, inst->op/8, &inst->oper2);
    printf("%d %x\n", inst->op, inst->oper2);
}

void set_instruction(FILE* f, struct instr* inst) {
    switch(inst->opcode) {
        case ADD_rm8_r8:
        case ADD_rm1632_r1632:
            rm81632_r81632(f, "add", ADD_rm8_r8, inst);
            break;
        case ADD_r8_rm8:
        case ADD_r1632_rm1632:
            r81632_rm81632(f, "add", ADD_r8_rm8, inst);
            break;
        case ADD_al_imm8:
        case ADD_eax_imm1632:
            smth_aleax(f, "add", ADD_al_imm8, inst);
            break;
        case PUSH_es:
        case POP_es:
            strcpy(inst->mnemonic, inst->opcode == POP_es ? "pop" : "push");
            inst->isoper1seg = 1;
            inst->oper1 = SEG_ES;
            break;
        case OR_rm8_r8:
        case OR_rm1632_r1632:
            rm81632_r81632(f, "or", OR_rm8_r8, inst);
            break;
        case OR_r8_rm8:
        case OR_r1632_rm1632:
            r81632_rm81632(f, "or", OR_r8_rm8, inst);
            break;
        case OR_al_imm8:
        case OR_eax_imm1632:
            smth_aleax(f, "or", OR_al_imm8, inst);
            break;
        case PUSH_cs:
            strcpy(inst->mnemonic, "push");
            inst->isoper1seg = 1;
            inst->oper1 = SEG_ES;
            break;
    }
}

void start_disassembly(FILE* f, uint32_t text_size) {
    while(counter < text_size) {
        struct instr instruction = {32, 32, 0, 0, 0, 0, 0, 0, 0, 0};
        
        instruction.opcode = set_prefixes(f, &instruction);
        set_instruction(f, &instruction);
        printf("%d %s %u %u\n", instruction.op, instruction.mnemonic, instruction.oper1, instruction.oper2);

        //These functions are to be built
        //print_instr(&instruction);
    }
}
