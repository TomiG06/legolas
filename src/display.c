#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "opcodes.h"
#include "helpers.h"
#include "disasm.h"

void get_sregister(char* buff, uint8_t num) {
    switch(num) {
        case SEG_ES:
            strcpy(buff, "es");
            break;
        case SEG_CS:
            strcpy(buff, "cs");
            break;
        case SEG_SS:
            strcpy(buff, "ss");
            break;
        case SEG_DS:
            strcpy(buff, "ds");
            break;
        case SEG_FS:
            strcpy(buff, "fs");
            break;
        case SEG_GS:
            strcpy(buff, "gs");
            break;
        default:
            break;
    }
}

const char* get_ptr_type(struct instr* inst, uint8_t idx) {
    uint8_t size = inst->op;

    switch(inst->description[idx]) {
        case m16:
            size = 16;
            break;
        case m64:
            size = 64;
            break;
        case m80:
            return "tbyte";
        case far:
            return "fword";
        case m:
            return "";
        case xmm:
            return "xmmword";
    }
 
     return rm_ptr[(int)log2(size)-3];
}

void display_instr(struct instr* inst, char* strtab, Elf32_Sym* text_syms, size_t ts_count) {
    
    putchar('\t');

    //print prefixes
    if(inst->rep)   printf("repe ");
    if(inst->repn)  printf("repne ");
    if(inst->lock)  printf("lock ");

    //print mnemonic
    printf("%-10s", inst->mnemonic);

    char* buff = (char*)malloc(100);
    char sreg_buff[3] = "";

    if(!buff) malloc_fail_and_exit();
    get_sregister(sreg_buff, inst->seg);

    for(size_t i = 0; i < inst->opernum; i++) {
        switch(inst->description[i]) {
            case r:
                {
                    uint8_t reg_size;
                    if(inst->operands[i] < 8) reg_size = inst->op;
                    else reg_size = pow(2, 2 + (inst->operands[i] >> 3));

                    inst->operands[i] &= 7;
                    
                    strcpy(buff, reg32[inst->operands[i]]);
                    if(reg_size == 16) {
                        for(size_t i = 0; i < 3; i++) buff[i] = buff[i+1];
                    } else if(reg_size == 8) {
                        strcpy(buff, reg8[inst->operands[i]]);
                        buff[2] = 0;
                    }
                }
                break;
            case rm:
            case m:
            case m16:
            case m32:
            case m64:
            case m80:
            case far:
            case xmm:
                sprintf(buff, "%s[%s%s", get_ptr_type(inst, i), sreg_buff, inst->seg? ":": "");

                switch(inst->addr) {
                    case 16:
                        if(!inst->mrm.mod && inst->mrm.rm == 6) sprintf(buff, "%s0x%x]", buff, inst->operands[i]);
                        else {
                            sprintf(buff, "%s%s", buff, rm16[inst->mrm.rm]);
                            if(inst->mrm.mod) sprintf(buff, "%s%c0x%x", buff, '+', inst->operands[i]);
                            sprintf(buff, "%s]", buff);
                        }
                        break;
                    case 32:
                        if(inst->hasSIB) {
                            sprintf(buff, "%s%s%s%s*%.0f", buff, inst->mrm.mod || inst->sb.base != ebp? reg32[inst->sb.base]: "", inst->mrm.mod || inst->sb.base != ebp? "+": "", reg32[inst->sb.index], pow(2, inst->sb.scale));
                            if(inst->mrm.mod || inst->sb.base == ebp) sprintf(buff, "%s+0x%x", buff, inst->operands[i]);
                            sprintf(buff, "%s]", buff);
                        } else {
                            if(!inst->mrm.mod) {
                                if(inst->mrm.rm == 5) sprintf(buff, "%s0x%x]", buff, inst->operands[i]);
                                else sprintf(buff, "%s%s]", buff, reg32[inst->mrm.rm]);
                            } else sprintf(buff, "%s%s+0x%x]", buff, reg32[inst->mrm.rm], inst->operands[i]);
                        }
                        break;
                }
                break;
            case imm:
            default:
                sprintf(buff, "0x%x", inst->operands[i]);
                break;
            case sreg:
                strcpy(buff, sreg_operand[inst->operands[i]]);
                break;
            case sti:
                sprintf(buff, "st%d", inst->operands[i]);
                break;
            case rxmm:
                sprintf(buff, "xmm%d", inst->operands[i]);
                break;
            case ptr:
                sprintf(buff, "0x%x:0x%x", inst->operands[i+1], inst->operands[i]);
                break;
            case rel8:
            case rel1632:
                {
                    if(inst->description[i] == rel8) inst->op = 8;

                    int32_t rel_addr;

                    if(inst->op == 8)       rel_addr = (int8_t)  inst->operands[i];
                    else if(inst->op == 16) rel_addr = (int16_t) inst->operands[i];
                    else                    rel_addr = (int32_t) inst->operands[i];
                    
                    if(ts_count) {
                        for(size_t j = 0; j < ts_count; j++) {
                            if(counter + rel_addr == text_syms[j].st_value) {
                                sprintf(buff, "<%s>", strtab + text_syms[j].st_name);
                                break;
                            }

                            if(j + 1 == ts_count) sprintf(buff, "0x%x", inst->operands[i] + counter);
                        }

                    } else sprintf(buff, "0x%x", inst->operands[i] + counter);
                }
                break;
        }
        
        printf(" %s%s", buff, i +1 != inst->opernum? ",": "");
    }

    putchar(10);

    free(buff);
}
