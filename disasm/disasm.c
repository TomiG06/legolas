#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "disasm.h"
#include "opcodes.h"
#include "display.h"
#include "helpers.h"

static uint8_t prefixes[] = {OP_SIZE, ADDR_SIZE, REP_REPE, REPNE, LOCK, SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS, EXTENDED};
static uint8_t eight_opcodes_rm_imm[] = {0x80, 0x81, 0x82, 0x83};

//Function to check if a number is in an array
char contained(uint8_t el, uint8_t arr[], const size_t size) {
    for(size_t i = 0; i < size; i++) {
        if(el == arr[i]) return 1;
    }

    return 0;
}

/*
    The function below runs every time in order to check
    for prefixes. When a byte is not in prefixes, it means
    that it is the opcode
*/
uint8_t set_prefixes(FILE* f, struct instr* inst) {
    uint32_t pfx = 0;
    read_b(f, 1, &pfx);

    while(contained(pfx, prefixes, sizeof(prefixes))) {
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

    inst->opcode = pfx;
}

//decode Mod R/M byte
void mod_rm(uint8_t* byte, struct instr* inst) {
    inst->mrm.mod = *byte >> 6;
    inst->mrm.reg = *byte >> 3 & 7;
    inst->mrm.rm  = *byte & 7;
}

//decode SIB byte
void sib(uint8_t* byte, struct instr* inst) {
    inst->sb.scale = *byte >> 6;
    inst->sb.index = *byte >> 3 & 7;
    inst->sb.base = *byte & 7;

    inst->hasSIB = 1;
}

void set_mn(struct instr* i, char* mnemonic) { 
    if(!i->mnem_is_set) {
        strcpy(i->mnemonic, mnemonic);
        i->mnem_is_set = 1;
    }
}

void set_desc(struct instr* inst, char* desc) { strcpy(inst->description, desc); }

void get_operands(FILE* f, struct instr* inst, char rm_index) {
    /*
        The purpose of this function is
        to analyze the Mod R/M and SIB bytes
        and set the rm operand accordingly
    */
    inst->description[rm_index] = rm;
    uint32_t buff = 0;

    if(inst->addr == 32) {
        switch(inst->mrm.mod) {
            case 0:
                switch(inst->mrm.rm) {
                    case 4:
                        read_b(f, 1, &buff);
                        sib((uint8_t*)&buff, inst);
                        break;
                    case 5:
                        read_b(f, 4, &inst->operands[rm_index]);
                        break;
                }
                break;
            case 1:
            case 2:
                if(inst->mrm.rm == 4) {
                    read_b(f, 1, &buff);
                    sib((uint8_t*)&buff, inst);
                }
                read_b(f, inst->mrm.mod*2, &inst->operands[rm_index]);
                break;
            case 3:
                inst->description[rm_index] = r;
                inst->operands[rm_index] = inst->mrm.rm;
                break;
        }
    } else if(inst->addr == 16) {
        switch(inst->mrm.mod) {
            case 0:
                if(inst->mrm.rm == 6) read_b(f, 2, &inst->operands[rm_index]);
                break;
            case 1:
            case 2:
                read_b(f, inst->mrm.mod, &inst->operands[rm_index]);
                break;
            case 3:
                inst->description[rm_index] = r;
                inst->operands[rm_index] = inst->mrm.rm;
                break;
        }
    }
}


void rm81632_r81632(FILE* f, char* mnemonic, uint8_t rm8_r8_op, struct instr* inst) {
    if(inst->opcode == rm8_r8_op) inst->op = 8;

    inst->opernum = 2;

    uint32_t buff = 0;
    read_b(f, 1, &buff);
    set_mn(inst, mnemonic);
    mod_rm((uint8_t*)&buff, inst);

    inst->operands[1] = inst->mrm.reg;
    inst->description[1] = r;

    get_operands(f, inst, 0);
}

void r81632_rm81632(FILE* f, char* mnemonic, uint8_t r8_rm8_op, struct instr* inst) {
    uint32_t buff = 0;
    read_b(f, 1, &buff);
    mod_rm((uint8_t*)&buff, inst);
    inst->opernum = 2;

    set_mn(inst, mnemonic);

    if(inst->opcode == r8_rm8_op) inst->op = 8;

    inst->description[0] = r;
    inst->operands[0] = inst->mrm.reg;

    get_operands(f, inst,1);
}

void smth_aleax(FILE* f, char* mnemonic, uint8_t imm8, struct instr* inst) {
    inst->operands[0] = eax;

    inst->description[0] = r;
    inst->description[1] = imm;
    inst->opernum = 2;
    
    set_mn(inst, mnemonic);

    if(inst->opcode == imm8) inst->op = 8;

    read_b(f, inst->op/8, &inst->operands[1]);
}

//Stuck instructions used with seg registers
void stack_seg(struct instr* inst, char* mnemonic, uint8_t seg) {
    set_mn(inst, mnemonic);
    inst->operands[0] = seg;
    inst->description[0] = sreg;
    inst->opernum = 1;
}

void rm81632_imm81632(FILE* f, char* mnemonic, uint8_t is_rm8, uint8_t is_imm8, struct instr* inst) {
    uint32_t buff;
    read_b(f, 1, &buff);
    mod_rm((uint8_t*)&buff, inst);
    inst->opernum = 2;

    if(contained(inst->opcode, eight_opcodes_rm_imm, sizeof(eight_opcodes_rm_imm))) {
        switch(inst->mrm.reg) {
            case 0:
                set_mn(inst, "add");
                break;
            case 1:
                set_mn(inst, "or");
                break;
            case 2:
                set_mn(inst, "adc");
                break;
            case 3:
                set_mn(inst, "sbb");
                break;
            case 4:
                set_mn(inst, "and");
                break;
            case 5:
                set_mn(inst, "sub");
                break;
            case 6:
                set_mn(inst, "xor");
                break;
            case 7:
                set_mn(inst, "cmp");
                break;
        }
    }

    if(is_rm8) inst->op = 8;

    set_mn(inst, mnemonic);

    get_operands(f, inst, 0);
    read_b(f, is_imm8? 1: inst->op/8, &inst->operands[1]);
    inst->description[1] = imm;
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
            stack_seg(inst, inst->opcode == POP_es ? "pop" : "push", es);
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
            stack_seg(inst, "push", cs);
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
            stack_seg(inst, inst->opcode == POP_ss? "pop": "push", ss);
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
            stack_seg(inst, inst->opcode == POP_ds ? "pop" : "push", ds);
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
            inst->description[0] = r;

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
            r81632_rm81632(f, "bound", 0, inst);
            inst->description[1] = m;
            break;
        case ARPL_rm16_r16:
            inst->op = 16;
            rm81632_r81632(f, "arpl", 0, inst);
            break;
        case PUSH_imm1632:
            set_mn(inst, "push");
            read_b(f, 4, &inst->operands[0]);
            inst->description[0] = imm;
            inst->opernum = 1;
            break;
        case IMUL_r1632_rm1632_imm1632:
        case IMUL_r1632_rm1632_imm8:
            //its really the same, just with a 3rd immediate operand
            r81632_rm81632(f, "imul", 0, inst);
            read_b(f, inst->opcode == IMUL_r1632_rm1632_imm8? 1 : 4, &inst->operands[2]);
            inst->description[2] = imm;
            inst->opernum = 3;
            break;
        case PUSH_imm8:
            set_mn(inst, "push");
            read_b(f, 1, &inst->operands[0]);
            inst->description[0] = imm;
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

        //Don't break these
        case JO_rel8:
            set_mn(inst, "jo");
        case JNO_rel8:
            set_mn(inst, "jno");
        case JB_rel8:
            set_mn(inst, "jb");
        case JNB_rel8:
            set_mn(inst, "jnb");
        case JZ_rel8:
            set_mn(inst, "jz");
        case JNZ_rel8:
            set_mn(inst, "jnz");
        case JBE_rel8:
            set_mn(inst, "jbe");
        case JNBE_rel8:
            set_mn(inst, "jnbe");
        case JS_rel8:
            set_mn(inst, "js");
        case JNS_rel8:  
            set_mn(inst, "jns");
        case JP_rel8:
            set_mn(inst, "jp");
        case JNP_rel8:
            set_mn(inst, "jnp");
        case JL_rel8:
            set_mn(inst, "jl");
        case JNL_rel8:
            set_mn(inst, "jnl");
        case JLE_rel8:
            set_mn(inst, "jle");
        case JNLE_rel8:
            set_mn(inst, "jnle");
            inst->opernum = 1;

            read_b(f, 1, &inst->operands[0]);

            //TODO: decode rel8 (we are going to process it as an immediate value for the time being)
            inst->description[0] = imm;

            break;
        
        case 0x80:
        case 0x82:
            rm81632_imm81632(f, "", 1, 1, inst);
            break;
        case 0x81:
            rm81632_imm81632(f, "", 0, 0, inst);
            break;
        case 0x83:
            rm81632_imm81632(f, "", 0, 1, inst);
            break;

        case TEST_rm8_r8:
        case TEST_rm1632_r1632:
            rm81632_r81632(f, "test", TEST_rm8_r8, inst);
            break;
        case XCHG_r8_rm8:
        case XCHG_r1632_rm1632:
            r81632_rm81632(f, "xchg", XCHG_r8_rm8, inst);
            break;
        case MOV_rm8_r8:
        case MOV_rm1632_r1632:
            rm81632_r81632(f, "mov", MOV_rm8_r8, inst);
            break;
        case MOV_r8_rm8:
        case MOV_r1632_rm1632:
            r81632_rm81632(f, "mov", MOV_r8_rm8, inst);
            break;
        case MOV_m16r1632_sreg:
            {
                uint32_t buff;
                read_b(f, 1, &buff);
                mod_rm((uint8_t*)&buff, inst);
                set_mn(inst, "mov");

                get_operands(f, inst, 0);
                if(inst->description[0] == rm) inst->description[0] = m;
                inst->operands[1] = inst->mrm.reg;
                inst->description[1] = sreg;
                inst->opernum = 2;
            }
            break;
        case LEA_r1632_m:
            {
                uint32_t buff;
                read_b(f, 1, &buff);
                mod_rm((uint8_t*)&buff, inst);
                set_mn(inst, "lea");

                get_operands(f, inst, 1);
                inst->operands[0] = inst->mrm.reg;
                inst->description[0] = r;
                inst->description[1] = m;
                inst->opernum = 2;
            }
            break;
        case MOV_sreg_rm16:
            {
                inst->op = 16;
                uint32_t buff;
                read_b(f, 1, &buff);
                mod_rm((uint8_t*)&buff, inst);
                set_mn(inst, "mov");

                get_operands(f, inst, 1);
                inst->operands[0] = inst->mrm.reg;
                inst->description[0] = sreg;
                inst->opernum = 2;
            }
            break;
        case POP_rm1632:
            {
                uint32_t buff;
                read_b(f, 1, &buff);
                mod_rm((uint8_t*)&buff, inst);
                set_mn(inst, "pop");

                get_operands(f, inst, 0);
                inst->opernum = 1;
            }
            break;
    }
}

void start_disassembly(FILE* f, uint32_t text_size) {
    while(counter < text_size) {
        struct instr instruction = {32, 32, 0, 0, 0, 0, 0, 0, 0, 0};
        
        //get prefixes
        set_prefixes(f, &instruction);

        //set instruction
        set_instruction(f, &instruction);

        //display instruction
        display_instr(&instruction);
    }
}

