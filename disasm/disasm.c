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
void mod_rm(FILE* f, struct instr* inst) {
    uint32_t byte = 0;
    read_b(f, 1, &byte);

    inst->mrm.mod = byte >> 6;
    inst->mrm.reg = byte >> 3 & 7;
    inst->mrm.rm  = byte & 7;
}

//decode SIB byte
void sib(FILE* f, uint8_t rmidx, struct instr* inst) {
    uint32_t byte = 0;
    read_b(f, 1, &byte);

    inst->sb.scale = byte >> 6;
    inst->sb.index = byte >> 3 & 7;
    inst->sb.base = byte & 7;

    inst->hasSIB = 1;

    if(inst->sb.base == ebp && !inst->mrm.mod) read_b(f, 4, &inst->operands[rmidx]);
}

//Sets mnemonic if not already set
void set_mn(struct instr* i, char* mnemonic) { 
    if(!i->mnem_is_set) {
        strcpy(i->mnemonic, mnemonic);
        i->mnem_is_set = 1;
    }
}

//Set description (not really used)
void set_desc(struct instr* inst, char* desc) { strcpy(inst->description, desc); }

void get_operands(FILE* f, struct instr* inst, char rm_index) {
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
                        sib(f, rm_index, inst);
                        break;
                    case 5:
                        read_b(f, 4, &inst->operands[rm_index]);
                        break;
                }
                break;
            case 1:
            case 2:
                if(inst->mrm.rm == 4) sib(f, rm_index, inst);
                read_b(f, (int)pow(inst->mrm.mod, 2), &inst->operands[rm_index]);
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

//Fetch immediate operand and assign immediate description
void get_imm(FILE* f, struct instr* inst, uint8_t size, uint8_t imm_idx) {
    read_b(f, size, &inst->operands[imm_idx]);
    inst->description[imm_idx] = imm;
}

//opcdes with rm_r operands
void rm81632_r81632(FILE* f, char* mnemonic, uint8_t rm8_r8_op, struct instr* inst) {
    if(inst->opcode == rm8_r8_op) inst->op = 8;

    inst->opernum = 2;

    set_mn(inst, mnemonic);
    mod_rm(f, inst);

    inst->operands[1] = inst->mrm.reg;
    inst->description[1] = r;

    get_operands(f, inst, 0);
}

//opcodes with r_rm operands
void r81632_rm81632(FILE* f, char* mnemonic, uint8_t r8_rm8_op, struct instr* inst) {
    mod_rm(f, inst);
    inst->opernum = 2;

    set_mn(inst, mnemonic);

    if(inst->opcode == r8_rm8_op) inst->op = 8;

    inst->description[0] = r;
    inst->operands[0] = inst->mrm.reg;

    get_operands(f, inst,1);
}

//opcodes with (al or eax)_imm operands
void smth_aleax(FILE* f, char* mnemonic, uint8_t imm8, struct instr* inst) {
    inst->operands[0] = eax;

    inst->description[0] = r;
    inst->opernum = 2;
    
    set_mn(inst, mnemonic);

    if(inst->opcode == imm8) inst->op = 8;

    get_imm(f, inst, inst->op/8, 1);
}

//Stuck instructions used with seg registers
void stack_seg(struct instr* inst, char* mnemonic, uint8_t seg) {
    set_mn(inst, mnemonic);
    inst->operands[0] = seg;
    inst->description[0] = sreg;
    inst->opernum = 1;
}

//opcodes with rm_imm operands
void rm81632_imm81632(FILE* f, char* mnemonic, uint8_t is_rm8, uint8_t is_imm8, struct instr* inst) {
    /*
        modrm must already be fetched
    */
    inst->opernum = 2;
    if(is_rm8) inst->op = 8;

    set_mn(inst, mnemonic);

    get_operands(f, inst, 0);
    get_imm(f, inst, is_imm8? 1: inst->op/8, 1);
}

void ptr1632(FILE* f, char* mnemonic, struct instr* inst) {
    /*
        sets ptr16:32 operands

        1st operand: 32 bit part
        2nd operand: 16 bit part
    */
    set_mn(inst, mnemonic);
    read_b(f, 4, &inst->operands[0]);
    read_b(f, 2, &inst->operands[1]);
    inst->description[0] = ptr;
    inst->opernum = 1;
}

//set description for floating point arithmetic (?) instructions
void setfdesc(struct instr* inst) {
    for(size_t i = 0; i < inst->opernum; i++) {
        if(inst->description[i] == r) inst->description[i] = sti;
        else if(inst->description[i] == rm) inst->description[i] = m;
    }
}

//assemble Mod R/M byte
uint8_t asm_modrm(struct instr* inst) { return (inst->mrm.mod << 6) | (inst->mrm.reg << 3) | inst->mrm.rm; }

//Check opcode and set mnemonic/operands accordingly
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
            get_imm(f, inst, 4, 0);
            inst->opernum = 1;
            break;
        case IMUL_r1632_rm1632_imm1632:
        case IMUL_r1632_rm1632_imm8:
            //its really the same, just with a 3rd immediate operand
            r81632_rm81632(f, "imul", 0, inst);
            get_imm(f, inst, inst->opcode == IMUL_r1632_rm1632_imm8? 1: 4, 2);
            inst->opernum = 3;
            break;
        case PUSH_imm8:
            set_mn(inst, "push");
            get_imm(f, inst, 1, 0);
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
        case 0x81:
        case 0x82:
        case 0x83:
            mod_rm(f, inst);
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
            rm81632_imm81632(f, "", !(inst->opcode&1), inst->opcode != 0x81, inst);
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
                mod_rm(f, inst);
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
                mod_rm(f, inst);
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
                mod_rm(f, inst);
                set_mn(inst, "mov");

                get_operands(f, inst, 1);
                inst->operands[0] = inst->mrm.reg;
                inst->description[0] = sreg;
                inst->opernum = 2;
            }
            break;
        case POP_rm1632:
            {
                mod_rm(f, inst);
                set_mn(inst, "pop");

                get_operands(f, inst, 0);
                inst->opernum = 1;
            }
            break;
        case NOP:
            set_mn(inst, inst->rep? "nop": "pause");
            if(inst->rep) inst->f3_not_rep = 1;
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
            ptr1632(f, "call", inst);
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
                read_b(f, 4, &inst->operands[moffs_idx]);
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
            smth_aleax(f, "test", TEST_al_imm8, inst);
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

            get_imm(f, inst, inst->op/8, 1);
            inst->opernum = 2;
            break;
        case 0xC0:
        case 0xC1:
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
            mod_rm(f, inst);
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
            if(inst->opcode <= 0xC1) rm81632_imm81632(f, "", !(inst->opcode & 1), 1, inst);
            else {
                get_operands(f, inst, 0);
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
                get_imm(f, inst, 2, 0);
            }
            break;
        case LES_r1632_m1632:
        case LDS_r1632_m1632:
            r81632_rm81632(f, inst->opcode & 1? "lds": "les", 0, inst);
            break;
        case MOV_rm8_imm8:
        case MOV_rm1632_imm1632:
            rm81632_imm81632(f, "mov", !(inst->opcode&1), !(inst->opcode&1), inst);
            break;
        case ENTER_imm16_imm8:
            set_mn(inst, "enter");
            inst->opernum = 2;
            get_imm(f, inst, 2, 0);
            get_imm(f, inst, 1, 1);
            break;
        case LEAVE:
            set_mn(inst, "leave");
            break;
        case RETF_imm16:
        case RETF:
            set_mn(inst, "retf");
            if(!(inst->opcode&1)) {
                get_imm(f, inst, 2, 0);
                inst->opernum = 1;
            }
            break;
        case INT3:
            set_mn(inst, "int3");
            break;
        case INT_imm8:
            set_mn(inst, "int");
            get_imm(f, inst, 1, 0);
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
            get_imm(f, inst, 1, 0);
            inst->opernum = 1;
            break;
        case SALC:
            set_mn(inst, "salc");
            break;
        case XLATB:
            set_mn(inst, "xlatb");
            break;
        case 0xD8:
            mod_rm(f, inst);

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

            get_operands(f, inst, 0);
            inst->opernum = 1;
            setfdesc(inst);

            break;
        case 0xD9:
            mod_rm(f, inst);
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
                    get_operands(f, inst, 0);
                    inst->opernum = 1;
                    setfdesc(inst);
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
                            get_operands(f, inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst);
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
                            get_operands(f, inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst);
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
                            get_operands(f, inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst);
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
                            get_operands(f, inst, 0);
                            inst->opernum = 1;
                            setfdesc(inst);
                            break;
                    }
                    break;
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

