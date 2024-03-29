#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <math.h>

#include "disasm.h"
#include "opcodes.h"
#include "display.h"
#include "helpers.h"

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

/* Fallthroughs are part of the functionality */

static uint8_t prefixes[] = {OP_SIZE, ADDR_SIZE, REP_REPE, REPNE, LOCK, SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS, EXTENDED};

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
void set_prefixes(struct instr* inst) {
    uint32_t pfx = 0;
    read_b(1, &pfx);

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
                break;
            default:
                inst->seg = pfx;
                break;
        }
        
        if(!inst->extended) inst->before_extended = pfx;

        read_b(1, &pfx);

        if(inst->extended) break;
    }

    inst->opcode = pfx;
}

//decode Mod R/M byte
void mod_rm(struct instr* inst) {
    uint32_t byte = 0;
    read_b(1, &byte);

    inst->mrm.mod = byte >> 6;
    inst->mrm.reg = byte >> 3 & 7;
    inst->mrm.rm  = byte & 7;
}

//assemble Mod R/M byte
uint8_t asm_modrm(struct instr* inst) { return (inst->mrm.mod << 6) | (inst->mrm.reg << 3) | inst->mrm.rm; }


//decode SIB byte
void sib(uint8_t rmidx, struct instr* inst) {
    uint32_t byte = 0;
    read_b(1, &byte);

    inst->sb.scale = byte >> 6;
    inst->sb.index = byte >> 3 & 7;
    inst->sb.base = byte & 7;

    inst->hasSIB = 1;

    if(inst->sb.base == ebp && !inst->mrm.mod) read_b(4, &inst->operands[rmidx]);
}

//Sets mnemonic if not already set
void set_mn(struct instr* i, char* mnemonic) { 
    if(!i->mnem_is_set) {
        strcpy(i->mnemonic, mnemonic);
        i->mnem_is_set = 1;
    }
}

void get_operands(struct instr* inst, uint8_t rm_index) {
    /*
        The purpose of this function is
        to analyze the Mod R/M and SIB bytes
        and set the rm operand accordingly
    */
    inst->description[rm_index] = rm;

    if(inst->addr == 32) {
        switch(inst->mrm.mod) {
            case 0:
                switch(inst->mrm.rm) {
                    case 4:
                        sib(rm_index, inst);
                        break;
                    case 5:
                        read_b(4, &inst->operands[rm_index]);
                        break;
                }
                break;
            case 1:
            case 2:
                if(inst->mrm.rm == 4) sib(rm_index, inst);
                read_b((int)pow(inst->mrm.mod, 2), &inst->operands[rm_index]);
                break;
            case 3:
                inst->description[rm_index] = r;
                inst->operands[rm_index] = inst->mrm.rm;
                break;
        }
    } else if(inst->addr == 16) {
        switch(inst->mrm.mod) {
            case 0:
                if(inst->mrm.rm == 6) read_b(2, &inst->operands[rm_index]);
                break;
            case 1:
            case 2:
                read_b(inst->mrm.mod, &inst->operands[rm_index]);
                break;
            case 3:
                inst->description[rm_index] = r;
                inst->operands[rm_index] = inst->mrm.rm;
                break;
        }
    }
}

//Fetch immediate operand and assign immediate description
void get_imm(struct instr* inst, uint8_t size, uint8_t imm_idx) {
    read_b(size, &inst->operands[imm_idx]);
    inst->description[imm_idx] = imm;
}

//opcdes with rm_r operands
void rm81632_r81632(char* mnemonic, uint8_t rm8_r8_op, struct instr* inst) {
    if(inst->opcode == rm8_r8_op) inst->op = 8;

    inst->opernum = 2;

    set_mn(inst, mnemonic);
    mod_rm(inst);

    inst->operands[1] = inst->mrm.reg;
    inst->description[1] = r;

    get_operands(inst, 0);
}

//opcodes with r_rm operands
void r81632_rm81632(char* mnemonic, uint8_t r8_rm8_op, struct instr* inst) {
    mod_rm(inst);
    inst->opernum = 2;

    set_mn(inst, mnemonic);

    if(inst->opcode == r8_rm8_op) inst->op = 8;

    inst->description[0] = r;
    inst->operands[0] = inst->mrm.reg;

    get_operands(inst, 1);
}

//opcodes with (al or eax)_imm operands
void smth_aleax(char* mnemonic, uint8_t imm8, struct instr* inst) {
    inst->operands[0] = eax;

    inst->description[0] = r;
    inst->opernum = 2;
    
    set_mn(inst, mnemonic);

    if(inst->opcode == imm8) inst->op = 8;

    get_imm(inst, inst->op/8, 1);
}

//Stuck instructions used with seg registers
void stack_seg(struct instr* inst, char* mnemonic, uint8_t seg) {
    set_mn(inst, mnemonic);
    inst->operands[0] = seg;
    inst->description[0] = sreg;
    inst->opernum = 1;
}

//opcodes with rm_imm operands
void rm81632_imm81632(char* mnemonic, uint8_t is_rm8, uint8_t is_imm8, struct instr* inst) {
    /*
        modrm must already be fetched
    */
    inst->opernum = 2;
    if(is_rm8) inst->op = 8;

    set_mn(inst, mnemonic);

    get_operands(inst, 0);
    get_imm(inst, is_imm8? 1: inst->op/8, 1);
}

void ptr1632(char* mnemonic, struct instr* inst) {
    /*
        sets ptr16:32 operands

        1st operand: 32 bit part
        2nd operand: 16 bit part
    */
    set_mn(inst, mnemonic);
    read_b(4, &inst->operands[0]);
    read_b(2, &inst->operands[1]);
    inst->description[0] = ptr;
    inst->opernum = 1;
}

//set description for floating point arithmetic (?) instructions
void setfdesc(struct instr* inst, uint8_t rm_replacement) {
    for(size_t i = 0; i < inst->opernum; i++) {
        if(inst->description[i] == r) inst->description[i] = sti;
        else if(inst->description[i] == rm) inst->description[i] = rm_replacement;
    }
}

void set_xdesc(struct instr* inst, int on_reg, int none, int on66, int onf2, int onf3, uint8_t m_idx) {
    int was_reg = 0;
    for(uint8_t i = 0; i < inst->opernum; i++) {
        if(inst->description[i] == r && i != m_idx) inst->description[i] = on_reg;

        if(i == m_idx) {
            if(inst->description[i] == r) was_reg = 1; //r\m cases

            if(inst->before_extended == OP_SIZE) {
                if(on66) inst->description[i] = on66;
                inst->op = 32;
            } else if(inst->before_extended == REPNE) {
                if(onf2) inst->description[i] = onf2;
                inst->repn = 0;
            } else if(inst->before_extended == REP_REPE) {
                if(onf3) inst->description[i] = onf3;
                inst->rep = 0;
            } else {
                if(none) inst->description[i] = none;
            }

            if(was_reg) inst->description[i] = r;
        }
    }
}

void set_xmnem(struct instr* inst, char* none, char* on66, char* onf2, char* onf3) {
    inst->mnem_is_set = 0;
    if(inst->before_extended == OP_SIZE)        set_mn(inst, on66);
    else if(inst->before_extended == REPNE)     set_mn(inst, onf2);
    else if(inst->before_extended == REP_REPE)  set_mn(inst, onf3);
    else                                        set_mn(inst, none);
}

void sec_op(struct instr* inst) {
    /*
        we are passing it as a uint ptr in order to remove the warning
    */
    read_b(1, (uint32_t*)&inst->sec_opcode);
}

//Check opcode and set mnemonic/operands accordingly
void set_instruction(struct instr* inst) {
    if(inst->extended) {
        switch(inst->opcode) {
            case 0x0:
                mod_rm(inst);
                get_operands(inst, 0);
                inst->opernum = 1;

                switch(inst->mrm.reg) {
                    case 0:
                        set_mn(inst, "sldt");
                        break;
                    case 1:
                        set_mn(inst, "str");
                        break;
                    case 2:
                        set_mn(inst, "lldt");
                        break;
                    case 3:
                        set_mn(inst, "ltr");
                        break;
                    case 4:
                        set_mn(inst, "verr");
                        break;
                    case 5:
                        set_mn(inst, "verw");
                        break;
                }

                if(inst->description[0] == rm) inst->op = 16;

                break;
            case 0x1:
                mod_rm(inst);

                switch(asm_modrm(inst)) {
                    case 0xC1:
                        set_mn(inst, "vmcall");
                        break;
                    case 0xC2:
                        set_mn(inst, "vmlaunch");
                        break;
                    case 0xC3:
                        set_mn(inst, "vmresume");
                        break;
                    case 0xC4:
                        set_mn(inst, "vmxoff");
                        break;
                    case 0xC8:
                        set_mn(inst, "monitor");
                        break;
                    case 0xC9:
                        set_mn(inst, "mwait");
                        break;
                    case 0xD0:
                        set_mn(inst, "xgetbv");
                        break;
                    case 0xD1:
                        set_mn(inst, "xsetbv");
                        break;
                    case 0xF9:
                        set_mn(inst, "rdtscp");
                        break;

                    default:
                        get_operands(inst, 0);
                        inst->opernum = 1;
                        switch(inst->mrm.reg) {
                            case 0:
                                set_mn(inst, "sgdt");
                            case 1:
                                set_mn(inst, "sidt");
                            case 2:
                                set_mn(inst, "lgdt");
                            case 3:
                                set_mn(inst, "lidt");
                                inst->description[0] = m;
                                break;
                            case 4:
                                set_mn(inst, "smsw");
                            case 6:
                                set_mn(inst, "lmsw");
                                if(inst->description[0] == rm) inst->op = 16;
                                break;
                            case 7:
                                set_mn(inst, "invlpg");
                                inst->op = 8;
                                break;
                        }
                }
                break;
            case 0x2:
            case 0x3:
                r81632_rm81632(inst->opcode == 0x2? "lar": "lsl", 0, inst);
                if(inst->description[1] == r) inst->operands[1] = r16 | inst->operands[1];
                break;
            case 0x6:
                set_mn(inst, "clts");
                break;
            case 0x8:
                set_mn(inst, "invd");
                break;
            case 0x9:
                set_mn(inst, "wbinvd");
                break;
            case 0xB:
                set_mn(inst, "ud2");
                break;
            case 0xD:
            case 0x1f:
                set_mn(inst, "nop");
                mod_rm(inst);
                get_operands(inst, 0);
                inst->opernum = 1;
                break;

            case 0x10:
            case 0x11:
                set_xmnem(inst, "movups", "movupd", "movsd", "movss");
                if(inst->opcode == 0x10)    r81632_rm81632("", 0, inst);
                else                        rm81632_r81632("", 0, inst);
                
                set_xdesc(inst, rxmm, xmm, xmm, m64, m32, inst->opcode == 0x10);
                break;
            case 0x12:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, inst->description[1] == rm? "movlps": "movhlps", "movlpd", "movddup", "movsldup");
                set_xdesc(inst, rxmm, m64, m64, m64, xmm, 1);
                break;
            case 0x13:
                rm81632_r81632(inst->op == 16? "movlpd": "movlps", 0, inst);
                set_xdesc(inst, rxmm, m64, m64, 0, 0, 0);
                break;
            case 0x14:
                r81632_rm81632(inst->op == 16? "unpcklpd": "unpcklps", 0, inst);
                set_xdesc(inst, rxmm, xmm, xmm, 0, 0, 1);
                break;
            case 0x15:
                r81632_rm81632(inst->op == 16? "unpckhpd": "unpckhps", 0, inst);
                set_xdesc(inst, rxmm, xmm, xmm, 0, 0, 1);
                break;
            case 0x16:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, inst->description[1] == rm? "movhps": "movlhps", "movhpd", "", "movshdup");
                set_xdesc(inst, rxmm, m64, xmm, 0, xmm, 1);
                break;
            case 0x17:
                rm81632_r81632("", 0, inst);
                set_xmnem(inst, "movhps", "movhpd", "", "");
                set_xdesc(inst, rxmm, m64, m64, 0, 0, 0);
                break;
            case 0x20:
            case 0x21:
                r81632_rm81632("mov", 0, inst);
                inst->description[1] = inst->opcode == 0x20? cr: dr;
                break;
            case 0x22:
            case 0x23:
                r81632_rm81632("mov", 0, inst);
                inst->description[0] = inst->opcode == 0x22? cr: dr;
                break;
            case 0x28:
            case 0x29:
                if(inst->opcode == 0x28) r81632_rm81632("", 0, inst);
                else rm81632_r81632("", 0, inst);
                set_xmnem(inst, "movaps", "movapd", "", "");
                set_xdesc(inst, rxmm, xmm, xmm, 0, 0, inst->opcode == 0x28);
                break;
            case 0x2A:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, "cvtpi2ps", "cvtpi2pd", "cvtsi2sd", "cvtsi2ss");
                set_xdesc(inst, rxmm, m64, m64, 0, 0, 1);
                if(inst->description[1] == rxmm) inst->description[1] = r;
                break;
            case 0x2B:
                rm81632_r81632("", 0, inst);
                set_xmnem(inst, "movntps", "movntpd", "", "");
                set_xdesc(inst, rxmm, xmm, xmm, 0, 0, 0);
                break;
            case 0x2C:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, "cvttps2pi", "cvttpd2pi", "cvttsd2si", "cvtsss2si");
                set_xdesc(inst, inst->rep|inst->repn? r: rmm, m64, xmm, m64, m32, 1);
                break;
            case 0x2D:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, "cvtps2pi", "cvtpd2pi", "cvtsd2si", "cvtss2pi");
                set_xdesc(inst, inst->rep|inst->repn? r: rmm, m64, xmm, m64, m32, 1);
                break;
            case 0x2E:
            case 0x2F:
                r81632_rm81632("", 0, inst);
                set_xmnem(inst, inst->opcode == 0x2e? "ucomiss": "comiss", inst->opcode == 0x2e? "ucomisd": "comisd", "", "");
                set_xdesc(inst, rxmm, m32, m64, 0, 0, 1);
                break;
            case 0x30:
                set_mn(inst, "wrmsr");
                break;
            case 0x31:
                set_mn(inst, "rdtsc");
                break;
            case 0x32:
                set_mn(inst, "rdmsr");
                break;
            case 0x33:
                set_mn(inst, "rdpmc");
                break;
            case 0x34:
                set_mn(inst, "sysenter");
                break;
            case 0x35:
                set_mn(inst, "sysexit");
                break;
            case 0x37:
                set_mn(inst, "getsec");
                break;
            case 0x38:
            {
                    
                    sec_op(inst);
                    if(inst->sec_opcode == 0xF1 && inst->before_extended != 0xF2) rm81632_r81632("", 0, inst);
                    else r81632_rm81632("", 0, inst);
                    inst->opernum = 2;
                    inst->mnem_is_set = 0;


                    uint8_t sec_oper = 0;
                
                    switch(inst->sec_opcode) {
                        case 0x00:
                            set_mn(inst, "pshufb");
                        case 0x01:
                            set_mn(inst, "phaddw");
                        case 0x02:
                            set_mn(inst, "phaddd");
                        case 0x03:
                            set_mn(inst, "phaddsw");
                        case 0x04:
                            set_mn(inst, "pmaddubsw");
                        case 0x05:
                            set_mn(inst, "phsubw");
                        case 0x06:
                            set_mn(inst, "phsubd");
                        case 0x07:
                            set_mn(inst, "phsubsw");
                        case 0x08:
                            set_mn(inst, "psignb");
                        case 0x09:
                            set_mn(inst, "psignw");
                        case 0x0A:
                            set_mn(inst, "psignd");
                        case 0x0B:
                            set_mn(inst, "pmulhrsw");
                        case 0x10:
                            set_mn(inst, "pblendvb");
                        case 0x14:
                            set_mn(inst, "blendvps");
                        case 0x15:
                            set_mn(inst, "blendvpd");
                        case 0x17:
                            set_mn(inst, "ptest");
                        case 0x1C:
                            set_mn(inst, "pabsb");
                        case 0x1D:
                            set_mn(inst, "pabsw");
                        case 0x1E:
                            set_mn(inst, "pabsd");
                            inst->description[0] = inst->before_extended == 0x66? rxmm: rmm;
                            sec_oper = m64;
                            break;
                        case 0x20:
                        case 0x30:
                            set_mn(inst, "pmovsxbw");
                        case 0x23:
                        case 0x33:
                            set_mn(inst, "pmovsxwd");
                        case 0x25:
                        case 0x35:
                            set_mn(inst, "pmovsxdq");
                            sec_oper = m64;
                            break;
                        case 0x21:
                        case 0x31:
                            set_mn(inst, "pmovsxbd");
                        case 0x24:
                        case 0x34:
                            set_mn(inst, "pmovsxwq");
                            sec_oper = m32;
                            break;
                        case 0x22:
                        case 0x32:
                            set_mn(inst, "pmovsxbq");
                            sec_oper = m16;
                            break;
                        case 0x2A:
                            set_mn(inst, "movntdqa");
                            sec_oper = m128;
                            break;
                        case 0x28:
                            set_mn(inst, "pmuldq");
                        case 0x29:
                            set_mn(inst, "pcmpeqq");
                        case 0x2B:
                            set_mn(inst, "packusdw");
                        case 0x37:
                            set_mn(inst, "pcmpgtq");
                        case 0x38:
                            set_mn(inst, "pminsb");
                        case 0x39:
                            set_mn(inst, "pminsd");
                        case 0x3A:
                            set_mn(inst, "pminuw");
                        case 0x3B:
                            set_mn(inst, "pminud");
                        case 0x3C:
                            set_mn(inst, "pmaxsb");
                        case 0x3D:
                            set_mn(inst, "pmaxsd");
                        case 0x3E:
                            set_mn(inst, "pmaxuw");
                        case 0x3F:
                            set_mn(inst, "pmaxud");
                        case 0x40:
                            set_mn(inst, "pmulld");
                        case 0x41:
                            set_mn(inst, "phminposuw");
                            sec_oper = xmm;
                            break;
                        case 0x80:
                            set_mn(inst, "invept");
                        case 0x81:
                            set_mn(inst, "invvpid");
                            inst->operands[0] = r32 | inst->operands[0];
                            inst->description[1] = m128;
                            break;
                        case 0xF0:
                            set_xmnem(inst, "movbe", "movbe", "crc32", "movbe");
                            if(inst->before_extended == 0xF2) {
                                inst->op = 8;
                                inst->operands[0] = r32 | inst->operands[0];
                                inst->repn = 0;
                            }
                            break;
                        case 0xF1:
                            if(inst->before_extended == 0xF2) {
                                set_mn(inst, "crc32");
                                inst->operands[0] = r32 | inst->operands[0];
                                inst->repn = 0;
                            } else {
                                set_mn(inst, "movbe");
                            }
                            break;
                    }

                    if(inst->sec_opcode > 0x1E && inst->sec_opcode < 0x80) inst->description[0] = rxmm;
                    if(inst->sec_opcode < 0x80) set_xdesc(inst, 0, sec_oper, xmm, 0, 0, 1);

                }

                break;

            //Don't break these
            case 0x80:
                set_mn(inst, "jo");
            case 0x81:
                set_mn(inst, "jno");
            case 0x82:
                set_mn(inst, "jb");
            case 0x83:
                set_mn(inst, "jnb");
            case 0x84:
                set_mn(inst, "jz");
            case 0x85:
                set_mn(inst, "jnz");
            case 0x86:
                set_mn(inst, "jbe");
            case 0x87:
                set_mn(inst, "jnbe");
            case 0x88:
                set_mn(inst, "js");
            case 0x89:
                set_mn(inst, "jns");
            case 0x8A:
                set_mn(inst, "jp");
            case 0x8B:
                set_mn(inst, "jnp");
            case 0x8C:
                set_mn(inst, "jl");
            case 0x8D:
                set_mn(inst, "jnl");
            case 0x8E:
                set_mn(inst, "jle");
            case 0x8F:
                set_mn(inst, "jnle");

                inst->opernum = 1;

                inst->description[0] = rel1632;

                read_b(4, &inst->operands[0]);
                break;
        }

        return;
    }

    switch(inst->opcode) {
        case ADD_rm8_r8:
        case ADD_rm1632_r1632:
            rm81632_r81632("add", ADD_rm8_r8, inst);
            break;
        case ADD_r8_rm8:
        case ADD_r1632_rm1632:
            r81632_rm81632("add", ADD_r8_rm8, inst);
            break;
        case ADD_al_imm8:
        case ADD_eax_imm1632:
            smth_aleax("add", ADD_al_imm8, inst);
            break;
        case PUSH_es:
        case POP_es:
            stack_seg(inst, inst->opcode == POP_es ? "pop" : "push", es);
            break;
        case OR_rm8_r8:
        case OR_rm1632_r1632:
            rm81632_r81632("or", OR_rm8_r8, inst);
            break;
        case OR_r8_rm8:
        case OR_r1632_rm1632:
            r81632_rm81632("or", OR_r8_rm8, inst);
            break;
        case OR_al_imm8:
        case OR_eax_imm1632:
            smth_aleax("or", OR_al_imm8, inst);
            break;
        case PUSH_cs:
            stack_seg(inst, "push", cs);
            break;
        case ADC_rm8_r8:
        case ADC_rm1632_r1632:
            rm81632_r81632("adc", ADC_rm8_r8, inst);
            break;
        case ADC_r8_rm8:
        case ADC_r1632_rm1632:
            r81632_rm81632("adc", ADC_rm8_r8, inst);
            break;
        case ADC_al_imm8:
        case ADC_eax_imm1632:
            smth_aleax("adc", ADC_al_imm8, inst);
            break;
        case PUSH_ss:
        case POP_ss:
            stack_seg(inst, inst->opcode == POP_ss? "pop": "push", ss);
            break;
        case SBB_rm8_r8:
        case SBB_rm1632_r1632:
            rm81632_r81632("sbb", SBB_rm8_r8, inst);
            break;
        case SBB_r8_rm8:
        case SBB_r1632_rm1632:
            r81632_rm81632("sbb", SBB_r8_rm8, inst);
            break;
        case SBB_al_imm8:
        case SBB_eax_imm1632:
            smth_aleax("sbb", SBB_al_imm8, inst);
            break;
        case PUSH_ds:
        case POP_ds:
            stack_seg(inst, inst->opcode == POP_ds ? "pop" : "push", ds);
            break;
        case AND_rm8_r8:
        case AND_rm1632_r1632:
            rm81632_r81632("and", AND_rm8_r8, inst);
            break;
        case AND_r8_rm8:
        case AND_r1632_rm1632:
            r81632_rm81632("and", AND_r8_rm8, inst);
            break;
        case AND_al_imm8:
        case AND_eax_imm1632:
            smth_aleax("and", AND_al_imm8, inst);
            break;
        case DAA:
            set_mn(inst, "daa");
            break;
        case SUB_rm8_r8:
        case SUB_rm1632_r1632:
            rm81632_r81632("sub", SUB_rm8_r8, inst);
            break;
        case SUB_r8_rm8:
        case SUB_r1632_rm1632:
            r81632_rm81632("sub", SUB_r8_rm8, inst);
            break;
        case SUB_al_imm8:
        case SUB_eax_imm1632:
            smth_aleax("sub", SUB_al_imm8, inst);
            break;
        case DAS:
            set_mn(inst, "das");
            break;
        case XOR_rm8_r8:
        case XOR_rm1632_r1632:
            rm81632_r81632("xor", XOR_rm8_r8, inst);
            break;
        case XOR_r8_rm8:
        case XOR_r1632_rm1632:
            r81632_rm81632("xor", XOR_r8_rm8, inst);
            break;
        case XOR_al_imm8:
        case XOR_eax_imm1632:
            smth_aleax("xor", XOR_al_imm8, inst);
            break;
        case AAA:
            set_mn(inst, "aaa");
            break;
        case CMP_rm8_r8:
        case CMP_rm1632_r1632:
            rm81632_r81632("cmp", CMP_rm8_r8, inst);
            break;
        case CMP_r8_rm8:
        case CMP_r1632_rm1632:
            r81632_rm81632("cmp", CMP_r8_rm8, inst);
            break;
        case CMP_al_imm8:
        case CMP_eax_imm1632:
            smth_aleax("cmp", CMP_al_imm8, inst);
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
            r81632_rm81632("bound", 0, inst);
            inst->description[1] = m;
            break;
        case ARPL_rm16_r16:
            inst->op = 16;
            rm81632_r81632("arpl", 0, inst);
            break;
        case PUSH_imm1632:
            set_mn(inst, "push");
            get_imm(inst, inst->op == 32? 4: 2, 0);
            inst->opernum = 1;
            break;
        case IMUL_r1632_rm1632_imm1632:
        case IMUL_r1632_rm1632_imm8:
            //its really the same, just with a 3rd immediate operand
            r81632_rm81632("imul", 0, inst);
            get_imm(inst, inst->opcode == IMUL_r1632_rm1632_imm8? 1: 4, 2);
            inst->opernum = 3;
            break;
        case PUSH_imm8:
            set_mn(inst, "push");
            get_imm(inst, 1, 0);
            inst->opernum = 1;
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

            read_b(1, &inst->operands[0]);

            inst->description[0] = rel8;

            inst->op = 8;

            break;
        
        case 0x80:
        case 0x81:
        case 0x82:
        case 0x83:
            mod_rm(inst);
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
            rm81632_imm81632("", !(inst->opcode&1), inst->opcode != 0x81, inst);
            break;
        case TEST_rm8_r8:
        case TEST_rm1632_r1632:
            rm81632_r81632("test", TEST_rm8_r8, inst);
            break;
        case XCHG_r8_rm8:
        case XCHG_r1632_rm1632:
            r81632_rm81632("xchg", XCHG_r8_rm8, inst);
            break;
        case MOV_rm8_r8:
        case MOV_rm1632_r1632:
            rm81632_r81632("mov", MOV_rm8_r8, inst);
            break;
        case MOV_r8_rm8:
        case MOV_r1632_rm1632:
            r81632_rm81632("mov", MOV_r8_rm8, inst);
            break;
        case MOV_m16r1632_sreg:
            {
                mod_rm(inst);
                set_mn(inst, "mov");

                get_operands(inst, 0);
                if(inst->description[0] == rm) inst->description[0] = m;
                inst->operands[1] = inst->mrm.reg;
                inst->description[1] = sreg;
                inst->opernum = 2;
            }
            break;
        case LEA_r1632_m:
            {
                mod_rm(inst);
                set_mn(inst, "lea");

                get_operands(inst, 1);
                inst->operands[0] = inst->mrm.reg;
                inst->description[0] = r;
                inst->description[1] = m;
                inst->opernum = 2;
            }
            break;
        case MOV_sreg_rm16:
            {
                inst->op = 16;
                mod_rm(inst);
                set_mn(inst, "mov");

                get_operands(inst, 1);
                inst->operands[0] = inst->mrm.reg;
                inst->description[0] = sreg;
                inst->opernum = 2;
            }
            break;
        case POP_rm1632:
            {
                mod_rm(inst);
                set_mn(inst, "pop");

                get_operands(inst, 0);
                inst->opernum = 1;
            }
            break;
        case NOP:
            set_mn(inst, inst->rep? "pause": "nop");
            if(inst->rep) inst->rep = 0;
            break;
 
        case XCHG_r1632_eax + ecx:
        case XCHG_r1632_eax + edx:
        case XCHG_r1632_eax + ebx:
        case XCHG_r1632_eax + esp:
        case XCHG_r1632_eax + ebp:
        case XCHG_r1632_eax + esi:
        case XCHG_r1632_eax + edi:
            set_mn(inst, "xchg");
            inst->operands[0] = inst->opcode & 7;
            inst->description[0] = r;
            inst->operands[1] = eax;
            inst->description[1] = r;
            inst->opernum = 2;
            break;

        case CBW:
            set_mn(inst, inst->op == 16? "cbw": "cwde");
            break;
        case CWD:
            set_mn(inst, inst->op == 16? "cwd": "cdq");
            break;
        case CALLF_ptr1632:
            ptr1632("call", inst);
            break;
        case FWAIT:
            set_mn(inst, "fwait");
            break;
        case PUSHF:
            set_mn(inst, "pushf");
            break;
        case POPF:
            set_mn(inst, "popf");
            break;
        case SAHF:
            set_mn(inst, "sahf");
            break;
        case LAHF:
            set_mn(inst, "lahf");
            break;
        case MOV_al_moffs8:
        case MOV_eax_moffs1632: //Playing with bits
        case MOV_moffs8_al:
        case MOV_moffs1632_eax: 
            {
                uint8_t moffs_idx = !(inst->opcode & 2);
                read_b(4, &inst->operands[moffs_idx]);
                inst->operands[!moffs_idx] = eax;

                set_mn(inst, "mov");
                if(inst->opcode&1) inst->op = 8;

                inst->description[moffs_idx] = moffs;
                inst->description[!moffs_idx] = r;
                inst->opernum = 2;
            }
            break;
        case MOVSB:
            set_mn(inst, "movsb");
            break;
        case MOVSD:
            set_mn(inst, inst->op == 32? "movsd": "movsw");
            break;
        case CMPSB:
            set_mn(inst, "cmpsb");
            break;
        case CMPSD:
            set_mn(inst, inst->op == 32? "cmpsd": "cmpsw");
            break;
        case TEST_al_imm8:
        case TEST_eax_imm1632:
            smth_aleax("test", TEST_al_imm8, inst);
            break;
        case STOSB:
            set_mn(inst, "stosb");
            break;
        case STOSD:
            set_mn(inst, inst->op == 32? "stosd": "stosw");
            break;
        case LODSB:
            set_mn(inst, "lodsb");
            break;
        case LODSD:
            set_mn(inst, inst->op == 32? "lodsd": "lodsw");
            break;
        case SCASB:
            set_mn(inst, "scasb");
            break;
        case SCASD:
            set_mn(inst, inst->op == 32? "scasd": "scasw");
            break;
        case MOV_r8_imm8 + al:
        case MOV_r8_imm8 + cl:
        case MOV_r8_imm8 + dl:
        case MOV_r8_imm8 + bl:
        case MOV_r8_imm8 + ah:
        case MOV_r8_imm8 + ch:
        case MOV_r8_imm8 + dh:
        case MOV_r8_imm8 + bh:
        case MOV_r1632_imm1632 + eax:
        case MOV_r1632_imm1632 + ecx:
        case MOV_r1632_imm1632 + edx:
        case MOV_r1632_imm1632 + ebx:
        case MOV_r1632_imm1632 + esp:
        case MOV_r1632_imm1632 + ebp:
        case MOV_r1632_imm1632 + esi:
        case MOV_r1632_imm1632 + edi:
            set_mn(inst, "mov");

            inst->operands[0] = inst->opcode & 7;
            inst->description[0] = r;

            if(inst->opcode < MOV_r1632_imm1632) inst->op = 8;

            get_imm(inst, inst->op/8, 1);
            inst->opernum = 2;
            break;
        case 0xC0:
        case 0xC1:
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
            mod_rm(inst);
            switch(inst->mrm.reg) {
                case 0:
                    set_mn(inst, "rol");
                    break;
                case 1:
                    set_mn(inst, "ror");
                    break;
                case 2:
                    set_mn(inst, "rcl");
                    break;
                case 3:
                    set_mn(inst, "rcr");
                    break;
                case 4:
                    set_mn(inst, "shl");
                    break;
                case 5:
                    set_mn(inst, "shr");
                    break;
                case 6:
                    set_mn(inst, "sal");
                    break;
                case 7:
                    set_mn(inst, "sar");
                    break;
            }
            if(inst->opcode <= 0xC1) rm81632_imm81632("", !(inst->opcode & 1), 1, inst);
            else {
                get_operands(inst, 0);
                inst->opernum = 2;

                if(!(inst->opcode & 1)) inst->op = 8;

                if(inst->opcode < 0xD2) {
                    inst->description[1] = imm;
                    inst->operands[1] = 1;
                } else {
                    inst->description[1] = r;
                    inst->operands[1] = r8 | cl;
                }
            }
            break;
        case RET:
        case RET_imm16:
            set_mn(inst, "ret");
            if(!(inst->opcode & 1)) {
                inst->opernum = 1;
                get_imm(inst, 2, 0);
            }
            break;
        case LES_r1632_m1632:
        case LDS_r1632_m1632:
            r81632_rm81632(inst->opcode & 1? "lds": "les", 0, inst);
            break;
        case MOV_rm8_imm8:
        case MOV_rm1632_imm1632:
            rm81632_imm81632("mov", !(inst->opcode&1), !(inst->opcode&1), inst);
            break;
        case ENTER_imm16_imm8:
            set_mn(inst, "enter");
            inst->opernum = 2;
            get_imm(inst, 2, 0);
            get_imm(inst, 1, 1);
            break;
        case LEAVE:
            set_mn(inst, "leave");
            break;
        case RETF_imm16:
        case RETF:
            set_mn(inst, "retf");
            if(!(inst->opcode&1)) {
                get_imm(inst, 2, 0);
                inst->opernum = 1;
            }
            break;
        case INT3:
            set_mn(inst, "int3");
            break;
        case INT_imm8:
            set_mn(inst, "int");
            get_imm(inst, 1, 0);
            inst->opernum = 1;
            break;
        case INTO:
        case IRET:
            set_mn(inst, inst->opcode == IRET? "iret": "into");
            break;
        case AAM_imm8:
            set_mn(inst, "aam");
        case AAD_imm8:
            set_mn(inst, "aad");
            get_imm(inst, 1, 0);
            inst->opernum = 1;
            break;
        case SALC:
            set_mn(inst, "salc");
            break;
        case XLATB:
            set_mn(inst, "xlatb");
            break;
        case 0xD8:
        case 0xDC:
            mod_rm(inst);

            switch(inst->mrm.reg) {
                case FADD:
                    set_mn(inst, "fadd");
                    break;
                case FMUL:
                    set_mn(inst, "fmul");
                    break;
                case FCOM:
                    set_mn(inst, "fcom");
                    break;
                case FCOMP:
                    set_mn(inst, "fcomp");
                    break;
                case FSUB:
                    set_mn(inst, "fsub");
                    break;
                case FSUBR:
                    set_mn(inst, "fsubr");
                    break;
                case FDIV:
                    set_mn(inst, "fdiv");
                    break;
                case FDIVR:
                    set_mn(inst, "fdivr");
                    break;
            }

            if(inst->opcode == 0xDC) inst->op = 64;

            get_operands(inst, 0);
            inst->opernum = 1;
            setfdesc(inst, inst->opcode == 0xD8? m32: m64);

            break;
        case 0xD9:
            mod_rm(inst);
            switch(inst->mrm.reg) {
                case FLD:
                    set_mn(inst, "fld");
                case FXCH:
                    set_mn(inst, "fxch");
                case 2:
                    if(inst->mrm.reg == 2 && asm_modrm(inst) == FNOP) {
                        set_mn(inst, "fnop");
                        break;
                    }
                    
                    //FST
                    set_mn(inst, "fst");
                case FSTP:
                    set_mn(inst, "fstp");
                    get_operands(inst, 0);
                    inst->opernum = 1;
                    setfdesc(inst, m32);
                    break;
                case 4:
                    switch(asm_modrm(inst)) {
                        case FACHS:
                            set_mn(inst, "fchs");
                            break;
                        case FABS:
                            set_mn(inst, "fabs");
                            break;
                        case FTST:
                            set_mn(inst, "ftst");
                            break;
                        case FXAM:
                            set_mn(inst, "fxam");
                            break;
                        default:
                            //FLDENV
                            set_mn(inst, "fldenv");
                            get_operands(inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst, m);
                            break;
                    }
                    break;
                case 5:
                    switch(asm_modrm(inst)) {
                        case FLD1:
                            set_mn(inst, "fld1");
                            break;
                        case FLDL2T:
                            set_mn(inst, "fldl2t");
                            break;
                        case FLDL2E:
                            set_mn(inst, "fldl2e");
                            break;
                        case FLDPI:
                            set_mn(inst, "fldpi");
                            break;
                        case FLDLG2:
                            set_mn(inst, "fldlg2");
                            break;
                        case FLDLN2:
                            set_mn(inst, "fldln2");
                            break;
                        case FLDZ:
                            set_mn(inst, "fldz");
                            break;
                        default:
                            //FLDCW
                            set_mn(inst, "fldcw");
                            get_operands(inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst, m16);
                            break;
                    }
                    break;
                case 6:
                    switch(asm_modrm(inst)) {
                        case F2XM1:
                            set_mn(inst, "f2xm1");
                            break;
                        case FYL2X:
                            set_mn(inst, "fyl2x");
                            break;
                        case FPTAN:
                            set_mn(inst, "fptan");
                            break;
                        case FPATAN:
                            set_mn(inst, "fpatan");
                            break;
                        case FXTRACT:
                            set_mn(inst, "fxtract");
                            break;
                        case FPREM1:
                            set_mn(inst, "fprem1");
                            break;
                        case FDECSTP:
                            set_mn(inst, "fdecstp");
                            break;
                        case FINCSTP:
                            set_mn(inst, "fincstp");
                            break;
                        default:
                            //FNSTENV
                            set_mn(inst, "fnstenv");
                            get_operands(inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst, m);
                            break;
                    }
                    break;
                case 7:
                    switch(asm_modrm(inst)) {
                        case FPREM:
                            set_mn(inst, "fprem");
                            break;
                        case FYL2XP1:
                            set_mn(inst, "fyl2xp1");
                            break;
                        case FSQRT:
                            set_mn(inst, "fsqrt");
                            break;
                        case FSINCOS:
                            set_mn(inst, "fsincos");
                            break;
                        case FRNDINT:
                            set_mn(inst, "frndint");
                            break;
                        case FSCALE:
                            set_mn(inst, "fscale");
                            break;
                        case FSIN:
                            set_mn(inst, "fsin");
                            break;
                        case FCOS:
                            set_mn(inst, "fcos");
                            break;
                        default:
                            //FNSTCW
                            set_mn(inst, "fnstcw");
                            get_operands(inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst, m16);
                            break;
                    }
                    break;
            }
            break;
        case 0xDA:
            mod_rm(inst);
            get_operands(inst, 0);

            switch(inst->mrm.reg) {
                case 0:
                    set_mn(inst, inst->description[0] == r? "fcmovb": "fiadd");
                case 1:
                    set_mn(inst, inst->description[0] == r? "fcmove": "fimul");
                case 2:
                    set_mn(inst, inst->description[0] == r? "fcmovbe": "ficom");
                case 3:
                    set_mn(inst, inst->description[0] == r? "fcmovu": "ficomp");
                case 5:
                    if(asm_modrm(inst) == 0xE9) {
                        set_mn(inst, "fucompp");
                        break;
                    }
                    set_mn(inst, "fisubr");
                case FISUB:
                    set_mn(inst, "fisub");
                case FIDIV:
                    set_mn(inst, "fidiv");
                case FIDIVR:
                    set_mn(inst, "fidivr");
                    inst->opernum = 1;
                    setfdesc(inst, m32);
                    break;
                    
            }
            break;
        case 0xDB:
            mod_rm(inst);
            get_operands(inst, 0);

            switch(inst->mrm.reg) {
                case 0:
                    if(inst->description[0] == r) set_mn(inst, "fcmovnb");
                    else set_mn(inst, "fild");
                case 1:
                    if(inst->description[0] == r) set_mn(inst, "fcmovne");
                    else set_mn(inst, "fisttp");
                case 2:
                    if(inst->description[0] == r) set_mn(inst, "fcmovnbe");
                    else set_mn(inst, "fist");
                case 3:
                    if(inst->description[0] == r) set_mn(inst, "fcmovnu");
                    else set_mn(inst, "fistp");
                case 5:
                    if(inst->description[0] == r) set_mn(inst, "fucomi");
                    else set_mn(inst, "fld");
                case FCOMI:
                    set_mn(inst, "fcomi");
                case FSTP_DB:
                    set_mn(inst, "fstp");
                    inst->opernum = 1;
                    setfdesc(inst, inst->mrm.reg < 5? m32: m80);
                    break;
                case 4:
                    switch(asm_modrm(inst)) {
                        case 0xE0:
                            set_mn(inst, "fneni");
                            break;
                        case 0xE1:
                            set_mn(inst, "fndisi");
                            break;
                        case 0xE2:
                            set_mn(inst, "fnclex");
                            break;
                        case 0xE3:
                            set_mn(inst, "fninit");
                            break;
                        case 0xE4:
                            set_mn(inst, "fnsetpm");
                            break;
                    }
                    break;
            };
           break;
        case 0xDD:
            mod_rm(inst);
            get_operands(inst, 0);

            switch(inst->mrm.reg) {
                case 0:
                    if(inst->description[0] == r) set_mn(inst, "ffree");
                    else set_mn(inst, "fld");
                case FISTTP:
                    set_mn(inst, "fisttp");
                    break;
                case FST:
                    set_mn(inst, "fst");
                    break;
                case FSTP:
                    set_mn(inst, "fstp");
                    break;
                case 4:
                    if(inst->description[0] == r) set_mn(inst, "frstor");
                    else set_mn(inst, "fucom");
                    break;
                case FUCOMP:
                    set_mn(inst, "fucomp");
                    break;
                case FNSAVE:
                    set_mn(inst, "fnsave");
                    break;
                case FNSTSW_DD:
                    set_mn(inst, "fnstsw");
                    break;
            }

            inst->opernum = 1;
            if(inst->mrm.reg == 7) setfdesc(inst, m16);
            else setfdesc(inst, inst->opcode == 6? m: m64);
            break;

        case 0xDE:
            mod_rm(inst);
            get_operands(inst, 0);
            inst->opernum = 1;

            switch(inst->mrm.reg) {
                case FADD:
                    set_mn(inst, inst->description[0] == r? "faddp": "fiadd");
                    break;
                case FMUL:
                    set_mn(inst, inst->description[0] == r? "fmulp": "fimul");
                    break;
                case FCOM:
                    set_mn(inst, "ficom");
                    break;
                case FCOMP:
                    set_mn(inst, inst->description[0] == r? "fcompp": "ficomp");
                    break;
                case FSUB:
                    set_mn(inst, inst->description[0] == r? "fsubrp": "fisub");
                    break;
                case FSUBR:
                    set_mn(inst, inst->description[0] == r? "fsubp": "fisubr");
                    break;
                case FDIV:
                    set_mn(inst, inst->description[0] == r? "fdivrp": "fidiv");
                    break;
                case FDIVR:
                    set_mn(inst, inst->description[0] == r? "fdivp": "fidivr");
                    break;
            }

            setfdesc(inst, m16);
            break;

        case 0xDF:
            mod_rm(inst);
            get_operands(inst, 0);
            inst->opernum = 1;

            switch(inst->mrm.reg) {
                case 0:
                    set_mn(inst, inst->description[0] == r? "ffreep": "fild");
                    break;
                case FISTTP:
                    set_mn(inst, "fisttp");
                    break;
                case FIST:
                    set_mn(inst, "fist");
                    break;
                case FISTP16:
                    set_mn(inst, "fistp");
                    break;
                case 4:
                    set_mn(inst, inst->description[0] == r? "fnstsw": "fbld");
                    break;
                case 5:
                    set_mn(inst, inst->description[0] == r? "fucomip": "fild");
                    break;
                case 6:
                    set_mn(inst, inst->description[0] == r? "fcomip": "fbstp");
                    break;
                case FISTP64:
                    set_mn(inst, "fistp");
                    break;
            }

            if(asm_modrm(inst) == 0xE0 && inst->mrm.reg == 4) inst->op = 16;
            else if(inst->mrm.reg < 4) setfdesc(inst, m16);
            else setfdesc(inst, inst->mrm.reg == 6 || inst->mrm.reg == 4? m80: m64);
            break;

        case LOOPNZ_rel8:
            set_mn(inst, "loopnz");
        case LOOPZ_rel8:
            set_mn(inst, "loopz");
        case LOOP_rel8:
            set_mn(inst, "loop");
        case JECXZ_rel8:
            set_mn(inst, inst->addr == 32? "jecxz": "jcxz");
            read_b(1, &inst->operands[0]);
            inst->description[0] = rel8;
            inst->opernum = 1;
            break;
        case IN_al_imm8:
        case IN_eax_imm8:
            set_mn(inst, "in");
            get_imm(inst, 1, 1);
            if(!(inst->opcode&1)) inst->op = 8;
            inst->description[0] = r;
            inst->opernum = 2;
            break;
        case OUT_imm8_al:
        case OUT_imm8_eax:
            set_mn(inst, "out");
            get_imm(inst, 1, 0);
            if(!(inst->opcode&1)) inst->op = 8;
            inst->description[1] = r;
            inst->operands[1] = eax;
            inst->opernum = 2;
            break;
        case CALL_rel1632:
        case JMP_rel8:
        case JMP_rel1632:
            if(inst->opcode == JMP_rel8) {
                inst->op = 8;
                inst->description[0] = rel8;
            } else inst->description[0] = rel1632;

            read_b(inst->op/8, &inst->operands[0]);

            set_mn(inst, inst->opcode&1? "jmp": "call");
            inst->opernum = 1;
            break;
        case JMP_ptr16col1632:
            ptr1632("jmp", inst);
            break;
        case IN_al_dx:
        case IN_eax_dx:
            set_mn(inst, "in");
            inst->description[0] = r;
            inst->operands[0] = eax;
            if(!(inst->opcode&1)) inst->op = 8;

            inst->description[1] = r;
            inst->operands[1] = r16 | edx;

            inst->opernum = 2;
            break;
        case OUT_dx_al:
        case OUT_dx_eax:
            set_mn(inst, "out");
            inst->description[0] = r;
            inst->operands[0] = r16 | edx;

            inst->description[1] = r;
            inst->operands[1] = eax;
            if(!(inst->opcode&1)) inst->op = 8;

            inst->opernum = 2;
            break;
        case INT1:
            set_mn(inst, "int1");
            break;
        case HLT:
            set_mn(inst, "hlt");
            break;
        case CMC:
            set_mn(inst, "cmc");
            break;
        case 0xF6:
            inst->op = 8;
        case 0xF7:
            mod_rm(inst);
            get_operands(inst, 0);
            inst->opernum = 1;
            switch(inst->mrm.reg) {
                case TEST:
                case 1:
                    set_mn(inst, "test");
                    get_imm(inst, inst->op/8, 1);
                    inst->opernum = 2;
                    break;
                case NOT:
                    set_mn(inst, "not");
                    break;
                case NEG:
                    set_mn(inst, "neg");
                    break;
                case MUL:
                    set_mn(inst, "mul");
                    break;
                case IMUL:
                    set_mn(inst, "imul");
                    break;
                case DIV:
                    set_mn(inst, "div");
                    break;
                case IDIV:
                    set_mn(inst, "idiv");
                    break;
            }
            break;
        case CLC:
            set_mn(inst, "clc");
            break;
        case STC:
            set_mn(inst, "stc");
            break;
        case CLI:
            set_mn(inst, "cli");
            break;
        case STI:
            set_mn(inst, "sti");
            break;
        case CLD:
            set_mn(inst, "cld");
            break;
        case STD:
            set_mn(inst, "std");
            break;
        case 0xFE:
            inst->op = 8;
        case 0xFF:
            mod_rm(inst);
            get_operands(inst, 0);
            inst->opernum = 1;
            
            switch(inst->mrm.reg) {
                case INC:
                    set_mn(inst, "inc");
                    break;
                case DEC:
                    set_mn(inst, "dec");
                    break;
                case CALL_FF:
                case CALLF_FF:
                    set_mn(inst, "call");
                    break;
                case JMP_FF:
                case JMPF_FF:
                    set_mn(inst, "jmp");
                    break;
                case PUSH:
                    set_mn(inst, "push");
                    break;
            }

            if(inst->mrm.reg == CALLF_FF ||
               inst->mrm.reg == JMPF_FF  ) inst->description[0] = far;
               break;
    }
}

#pragma GCC diagnostic pop

static char hex_byte[8] = "";
static char hex_code[64] = "";

void add_byte(uint8_t byte) {
    sprintf(hex_byte, " %02x", byte);
    strcat(hex_code, hex_byte);
}

void print_bytes(char nl) {
    printf(" %-20s", hex_code);
    if(nl) putchar(10);
    memset(hex_code, 0, sizeof(hex_code));
}

void start_disassembly(Elf32_Shdr shdr, char* strtab, Elf32_Sym* text_syms, size_t ts_count) {
    struct instr* instruction;
    uint32_t starting_position = 0;

    while(counter < shdr.sh_size) {
        
        for(size_t i = 0; i < ts_count; i++) {
            if(text_syms[i].st_value == counter + shdr.sh_addr) {
                printf("\n%08x <%s>:\n", text_syms[i].st_value, strtab + text_syms[i].st_name);
            }
        }

        instruction = (struct instr*) calloc(sizeof(struct instr), 1);

        if(!instruction) malloc_fail_and_exit();
        instruction->op = instruction->addr = 32;
        
        //get prefixes
        set_prefixes(instruction);

        //set instruction
        set_instruction(instruction);

        //display instruction
        printf("%4x:", starting_position + shdr.sh_addr); /* instruction position */

        uint32_t idx;
        for(idx = starting_position; idx < counter && idx < starting_position+7; idx++) {
            add_byte(machine_code[idx]);
        }

        print_bytes(0);

        display_instr(instruction, strtab, text_syms, ts_count, shdr.sh_addr);    /* instruction in assembly */

        if(idx < counter) {
            printf("%4x:", starting_position + shdr.sh_addr + 7);
            for(; idx < counter; idx++) {
                add_byte(machine_code[idx]);
            }

            print_bytes(1);
        }

        free(instruction);
        starting_position = counter;
    }
}

