#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "disasm.h"
#include "opcodes.h"
#include "helpers.h"

static uint8_t prefixes[] = {OP_SIZE, ADDR_SIZE, REP_REPE, REPNE, LOCK, SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS, EXTENDED};
static uint8_t segs[] = {SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS};

static const size_t pfx_size = sizeof(prefixes);
static const size_t seg_size = sizeof(segs);

char contained(uint8_t el, uint8_t arr[], const size_t size) {
    for(size_t i = 0; i < size; i++) {
        if(el == arr[i]) return 1;
    }

    return 0;
}

uint8_t set_prefixes(FILE* f, struct instr* inst) {
    uint32_t pfx = 0;
    read_b(f, 1, &pfx);
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

void sib(uint8_t* byte, struct instr* inst) {
    inst->sb.scale = pow(2, *byte >> 6);
    inst->sb.index = *byte >> 3 & 7;
    inst->sb.base = *byte & 7;
}

void set_mn(struct instr* i, char* mnemonic) { strcpy(i->mnemonic, mnemonic); }
void set_desc(struct instr* i, char* description) { strcpy(i->descr_opers, description); }

void get_operands(FILE* f, struct instr* inst, char reverse, char* descr) {
    /*
        This function is used in
        rm81632_r81632 and r81632_rm81632

        reverse must be either 1 or 0
    */
    uint8_t r_operand = reverse;
    uint8_t rm_operand = !reverse;

    uint32_t buff;
    switch(inst->mrm.mod) {
        case 0:
            switch(inst->mrm.rm) {
                case 4:
                    read_b(f, 1, &buff);
                    sib((uint8_t*)&buff, inst);
                    break;
                case 5:
                    read_b(f, 4, &inst->operands[rm_operand]);
                    break;
            }
            set_desc(inst, descr);
            inst->operands[r_operand] = inst->mrm.reg;
            break;
        case 1:
        case 2:
            set_desc(inst, descr);
            read_b(f, 1, &buff);
            sib((uint8_t*)&buff, inst);
            read_b(f, inst->mrm.mod*2, &inst->operands[rm_operand]);
            break;
        case 3:
            set_desc(inst, "r_r");
            inst->operands[r_operand] = inst->mrm.rm;
            inst->operands[rm_operand] = inst->mrm.reg;
            break;
    }
}


void rm81632_r81632(FILE* f, char* mnemonic, uint8_t rm8_r8_op, struct instr* inst) {
    if(inst->opcode == rm8_r8_op) {
        inst->op = 8;
        inst->addr = 8;
    } else if(inst->op == 16) inst->addr = 16;

    inst->opernum = 2;

    uint32_t buff;
    read_b(f, 1, &buff);
    set_mn(inst, mnemonic);
    mod_rm((uint8_t*)&buff, inst);
    get_operands(f, inst, 0, "rm_r");
}

void r81632_rm81632(FILE* f, char* mnemonic, uint8_t r8_rm8_op, struct instr* inst) {
    uint32_t buff;
    read_b(f, 1, &buff);
    mod_rm((uint8_t*)&buff, inst);
    inst->opernum = 2;

    set_mn(inst, mnemonic);

    if(inst->opcode == r8_rm8_op) {
        inst->op = 8;
        inst->addr = 8;
    } else if(inst->op == 16) inst->addr = 16;

    get_operands(f, inst, 1, "r_rm");

/*    inst->operands[0] = inst->mrm.reg;
    read_b(f, 4, &inst->operands[1]);*/
}

void smth_aleax(FILE* f, char* mnemonic, uint8_t imm8, struct instr* inst) {
    inst->operands[0] = eax;
    inst->opernum = 2;
    set_mn(inst, mnemonic);
    set_desc(inst, "r_imm");

    if(inst->opcode == imm8) inst->op = 8;

    read_b(f, inst->op/8, &inst->operands[1]);
}

//Stuck instructions used with seg registers
void stack_seg(struct instr* inst, char* mnemonic, uint8_t seg) {
    set_mn(inst, mnemonic);
    set_desc(inst, "sreg");
    inst->operands[0] = seg;
    inst->opernum = 1;
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
            stack_seg(inst, inst->opcode == POP_es ? "pop" : "push", SEG_ES);
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
            stack_seg(inst, "push", SEG_CS);
            break;
        case ADC_rm8_r8:
        case ADC_rm1632_r1632:
            rm81632_r81632(f, "adc", ADC_rm8_r8, inst);
            break;
        case ADC_r8_rm8:
        case ADC_r1632_rm1632:
            r81632_rm81632(f, "adc", ADC_rm8_r8, inst);
            break;
        case ADC_al_imm8:
        case ADC_eax_imm1632:
            smth_aleax(f, "adc", ADC_al_imm8, inst);
            break;
        case PUSH_ss:
        case POP_ss:
            stack_seg(inst, inst->opcode == POP_ss? "pop": "push", SEG_SS);
            break;
        case SBB_rm8_r8:
        case SBB_rm1632_r1632:
            rm81632_r81632(f, "sbb", SBB_rm8_r8, inst);
            break;
        case SBB_r8_rm8:
        case SBB_r1632_rm1632:
            r81632_rm81632(f, "sbb", SBB_r8_rm8, inst);
            break;
        case SBB_al_imm8:
        case SBB_eax_imm1632:
            smth_aleax(f, "sbb", SBB_al_imm8, inst);
            break;
        case PUSH_ds:
        case POP_ds:
            stack_seg(inst, inst->opcode == POP_ds ? "pop" : "push", SEG_DS);
            break;
        case AND_rm8_r8:
        case AND_rm1632_r1632:
            rm81632_r81632(f, "and", AND_rm8_r8, inst);
            break;
        case AND_r8_rm8:
        case AND_r1632_rm1632:
            r81632_rm81632(f, "and", AND_r8_rm8, inst);
            break;
        case AND_al_imm8:
        case AND_eax_imm1632:
            smth_aleax(f, "and", AND_al_imm8, inst);
            break;
        case DAA:
            set_mn(inst, "daa");
            break;

        case SUB_rm8_r8:
        case SUB_rm1632_r1632:
            rm81632_r81632(f, "sub", SUB_rm8_r8, inst);
            break;
        case SUB_r8_rm8:
        case SUB_r1632_rm1632:
            r81632_rm81632(f, "sub", SUB_r8_rm8, inst);
            break;
        case SUB_al_imm8:
        case SUB_eax_imm1632:
            smth_aleax(f, "sub", SUB_al_imm8, inst);
            break;
        case DAS:
            set_mn(inst, "das");
            break;
        case XOR_rm8_r8:
        case XOR_rm1632_r1632:
            rm81632_r81632(f, "xor", XOR_rm8_r8, inst);
            break;
        case XOR_r8_rm8:
        case XOR_r1632_rm1632:
            r81632_rm81632(f, "xor", XOR_r8_rm8, inst);
            break;
        case XOR_al_imm8:
        case XOR_eax_imm1632:
            smth_aleax(f, "xor", XOR_al_imm8, inst);
            break;
        case AAA:
            set_mn(inst, "aaa");
            break;
        case CMP_rm8_r8:
        case CMP_rm1632_r1632:
            rm81632_r81632(f, "cmp", CMP_rm8_r8, inst);
            break;
        case CMP_r8_rm8:
        case CMP_r1632_rm1632:
            r81632_rm81632(f, "cmp", CMP_r8_rm8, inst);
            break;
        case CMP_al_imm8:
        case CMP_eax_imm1632:
            smth_aleax(f, "cmp", CMP_al_imm8, inst);
            break;
        case AAS:
            set_mn(inst, "aas");
            break;
        case INC_r1632 + eax:
        case INC_r1632 + ecx:
        case INC_r1632 + edx:
        case INC_r1632 + ebx:
        case INC_r1632 + esp:
        case INC_r1632 + ebp:
        case INC_r1632 + esi:
        case INC_r1632 + edi:
        case DEC_r1632 + eax:
        case DEC_r1632 + ecx:
        case DEC_r1632 + edx:
        case DEC_r1632 + ebx:
        case DEC_r1632 + esp:
        case DEC_r1632 + ebp:
        case DEC_r1632 + esi:
        case DEC_r1632 + edi:
        case PUSH_r1632 + eax:
        case PUSH_r1632 + ecx:
        case PUSH_r1632 + edx:
        case PUSH_r1632 + ebx:
        case PUSH_r1632 + esp:
        case PUSH_r1632 + ebp:
        case PUSH_r1632 + esi:
        case PUSH_r1632 + edi:
        case POP_r1632 + eax:
        case POP_r1632 + ecx:
        case POP_r1632 + edx:
        case POP_r1632 + ebx:
        case POP_r1632 + esp:
        case POP_r1632 + ebp:
        case POP_r1632 + esi:
        case POP_r1632 + edi:
           
            inst->opernum = 1;
            inst->operands[0] = inst->opcode & 7;

            switch(inst->opcode >> 3) {
                case 0x8:   //INC
                    set_mn(inst, "inc");
                    break;
                case 0x9:   //DEC
                    set_mn(inst, "dec");
                    break;
                case 0xa:   //PUSH
                    set_mn(inst, "push");
                    break;
                case 0xb:   //POP
                    set_mn(inst, "pop");
                    break;
            } 
            break;

        case PUSHA:
            set_mn(inst, "pusha");
            break;
        case POPA:
            set_mn(inst, "popa");
            break;
        case BOUND_r1632_m1632:
        case ARPL_rm16_r16:
        case PUSH_imm1632:
            set_mn(inst, "push");
            read_b(f, 4, &inst->operands[0]);
            break;
        case IMUL_r1632_rm1632_imm1632:
        case IMUL_r1632_rm1632_imm8:
            //its really the same, just with a 3rd immediate operand
            r81632_rm81632(f, "imul", 0, inst);
            read_b(f, inst->opcode == IMUL_r1632_rm1632_imm8? 1 : 4, &inst->operands[2]);
            strcat(inst->descr_opers, "_imm");
            break;
        case PUSH_imm8:
            set_mn(inst, "push");
            read_b(f, 1, &inst->operands[0]);
            break;
        case INSB:
            set_mn(inst, "insb");
            break;
        case INS_WD:
            set_mn(inst, inst->op == 32? "insd": "insw");
        case OUTSB:
            set_mn(inst, "outsb");
            break;
        case OUTS_WD:
            set_mn(inst, inst->op == 32? "outsd": "outsw");
            break;

    }
}

void start_disassembly(FILE* f, uint32_t text_size) {
    while(counter < text_size) {
        struct instr instruction = {32, 32, 0, 0, 0, 0, 0, 0, 0, 0};
        
        instruction.opcode = set_prefixes(f, &instruction);
        set_instruction(f, &instruction);
        printf("%d %s %x %x %x %s\n", instruction.op, instruction.mnemonic, instruction.operands[0], instruction.operands[1], instruction.operands[2], instruction.descr_opers);
        printf("[%x+%x*%x+%x]\n", instruction.sb.base, instruction.sb.index, instruction.sb.scale, instruction.operands[strcmp(instruction.descr_opers, "r_rm")? 1:0]);
        //print_instr(&instruction);
    }
}

