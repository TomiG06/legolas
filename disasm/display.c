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

void display_instr(struct instr* inst) {
    //print prefixes
    if(inst->rep)   printf("repe ");
    if(inst->repn)  printf("repne ");
    if(inst->lock)  printf("lock ");

    //print mnemonic
    printf("%s", inst->mnemonic);

    char* buff = (char*)malloc(100);
    char sreg_buff[3] = "";

    if(!buff) malloc_fail_and_exit();
    get_sregister(sreg_buff, inst->seg);

    for(size_t i = 0; i < inst->opernum; i++) {
        switch(inst->description[i]) {
            case r:
                strcpy(buff, reg32[inst->operands[i]]);
                if(inst->op == 16) {
                    for(size_t i = 0; i < 3; i++) buff[i] = buff[i+1];
                } else if(inst->op == 8) {
                    strcpy(buff, reg8[inst->operands[i]]);
                    buff[2] = 0;
                }
                break;
            case rm:
            case m:
                sprintf(buff, "%s[%s%s", inst->description[i] == rm? rm_ptr[(int)log2(inst->op)-3]: "", sreg_buff, inst->seg? ":": "");

                switch(inst->addr) {
                    case 16:
                        if(!inst->mrm.mod && inst->mrm.rm == 6) sprintf(buff, "%s0x%X]", buff, inst->operands[i]);
                        else {
                            sprintf(buff, "%s%s", buff, rm16[inst->mrm.rm]);
                            if(inst->mrm.mod) sprintf(buff, "%s%c0x%X", buff, '+', inst->operands[i]);
                            sprintf(buff, "%s]", buff);
                        }
                        break;
                    case 32:
                        if(inst->hasSIB) {
                            sprintf(buff, "%s%s+%s*%.0f", buff, reg32[inst->sb.base], reg32[inst->sb.index], pow(2, inst->sb.scale));
                            if(inst->mrm.mod) sprintf(buff, "%s+0x%X", buff, inst->operands[i]);
                            sprintf(buff, "%s]", buff);
                        } else {
                            if(!inst->mrm.mod) {
                                if(inst->mrm.rm == 5) sprintf(buff, "%s0x%X]", buff, inst->operands[i]);
                                else sprintf(buff, "%s%s]", buff, reg32[inst->mrm.rm]);
                            } else sprintf(buff, "%s%s+0x%X]", buff, reg32[inst->mrm.rm], inst->operands[i]);
                        }
                        break;
                }
                break;
            case imm:
            default:
                sprintf(buff, "0x%x", inst->operands[i]);
                break;
            case sreg:
                get_sregister(buff, inst->operands[i]);
                break;
        }
        
        printf(" %s%s", buff, i +1 != inst->opernum? ",": "");
    }

    putchar(10);

    free(buff);
}
