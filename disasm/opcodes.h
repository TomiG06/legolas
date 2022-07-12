#ifndef OPCODES_H
#define OPCODES_H

#define ADD_rm8_r8                  0x00
#define ADD_rm1632_r1632            0x01
#define ADD_r8_rm8                  0x02
#define ADD_r1632_rm1632            0x03
#define ADD_al_imm8                 0x04
#define ADD_eax_imm1632             0x05
#define PUSH_es                     0x06
#define POP_es                      0x07
#define OR_rm8_r8                   0x08
#define OR_rm1632_r1632             0x09
#define OR_r8_rm8                   0x0A
#define OR_r1632_rm1632             0x0B
#define OR_al_imm8                  0x0C
#define OR_eax_imm1632              0x0D
#define PUSH_cs                     0x0E
#define EXTENDED                    0x0F
#define ADC_rm8_r8                  0x10
#define ADC_rm1632_r1632            0x11
#define ADC_r8_rm8                  0x12
#define ADC_r1632_rm1632            0x13
#define ADC_al_imm8                 0x14
#define ADC_eax_imm1632             0x15
#define PUSH_ss                     0x16
#define POP_ss                      0x17
#define SBB_rm8_r8                  0x18
#define SBB_rm1632_r1632            0x19
#define SBB_r8_rm8                  0x1A
#define SBB_r1632_rm1632            0x1B
#define SBB_al_imm8                 0x1C
#define SBB_eax_imm1632             0x1D
#define PUSH_ds                     0x1E
#define POP_ds                      0x1F
#define AND_rm8_r8                  0x20
#define AND_rm1632_r1632            0x21
#define AND_r8_rm8                  0x22
#define AND_r1632_rm1632            0x23
#define AND_al_imm8                 0x24
#define AND_eax_imm1632             0x25
#define SEG_ES                      0x26
#define DAA                         0x27
#define SUB_rm8_r8                  0x28
#define SUB_rm1632_r1632            0x29
#define SUB_r8_rm8                  0x2A
#define SUB_r1632_rm1632            0x2B
#define SUB_al_imm8                 0x2C
#define SUB_eax_imm1632             0x2D
#define SEG_CS                      0x2E
#define DAS                         0x2F
#define XOR_rm8_r8                  0x30
#define XOR_rm1632_r1632            0x31
#define XOR_r8_rm8                  0x32
#define XOR_r1632_rm1632            0x33
#define XOR_al_imm8                 0x34
#define XOR_eax_imm1632             0x35
#define SEG_SS                      0x36
#define AAA                         0x37
#define CMP_rm8_r8                  0x38
#define CMP_rm1632_r1632            0x39
#define CMP_r8_rm8                  0x3A
#define CMP_r1632_rm1632            0x3B
#define CMP_al_imm8                 0x3C
#define CMP_eax_imm1632             0x3D
#define SEG_DS                      0x3E
#define AAS                         0x3F
#define INC_r1632                   0x40
#define DEC_r1632                   0x48
#define PUSH_r1632                  0x50
#define POP_r1632                   0x58
#define PUSHA                       0x60
#define POPA                        0x61
#define BOUND_r1632_m1632           0x62
#define ARPL_rm16_r16               0x63
#define SEG_FS                      0x64
#define SEG_GS                      0x65
#define OP_SIZE                     0x66
#define ADDR_SIZE                   0x67
#define PUSH_imm1632                0x68
#define IMUL_r1632_rm1632_imm1632   0x69
#define PUSH_imm8                   0x6A
#define IMUL_r1632_rm1632_imm8      0x6B
#define INSB                        0x6C
#define INS_WD                      0x6D
#define OUTSB                       0x6E
#define OUTS_WD                     0x6F
#define JO_rel8                     0x70
#define JNO_rel8                    0x71
#define JB_rel8                     0x72
#define JNB_rel8                    0x73
#define JZ_rel8                     0x74
#define JNZ_rel8                    0x75
#define JBE_rel8                    0x76
#define JNBE_rel8                   0x77
#define JS_rel8                     0x78
#define JNS_rel8                    0x79
#define JP_rel8                     0x7A
#define JNP_rel8                    0x7B
#define JL_rel8                     0x7C
#define JNL_rel8                    0x7D
#define JLE_rel8                    0x7E
#define JNLE_rel8                   0x7F

//0x80                              R/M 
#define ADD_rm8_imm8                0x00
#define OR_rm8_imm8                 0x01
#define ADC_rm8_imm8                0x02
#define SBB_rm8_imm8                0x03
#define AND_rm8_imm8                0x04
#define SUB_rm8_imm8                0x05
#define XOR_rm8_imm8                0x06
#define CMP_rm8_imm8                0x07

//0x81
#define ADD_rm1632_imm1632          0x00
#define OR_rm1632_imm1632           0x01
#define ADC_rm1632_imm1632          0x02
#define SBB_rm1632_imm1632          0x03
#define AND_rm1632_imm1632          0x04
#define SUB_rm1632_imm1632          0x05
#define XOR_rm1632_imm1632          0x06
#define CMP_rm1632_imm1632          0x07
/*
#define ADD_rm8_imm8                0x82    For some reason
#define OR_rm8_imm8                 0x82    these opcodes are
#define ADC_rm8_imm8                0x82    the same as 0x80
#define SBB_rm8_imm8                0x82
#define AND_rm8_imm8                0x82
#define SUB_rm8_imm8                0x82
#define XOR_rm8_imm8                0x82
*/
//0x83
#define ADD_rm1632_imm8             0x00
#define OR_rm1632_imm8              0x01
#define ADC_rm1632_imm8             0x02
#define SBB_rm1632_imm8             0x03
#define AND_rm1632_imm8             0x04
#define SUB_rm1632_imm8             0x05
#define XOR_rm1632_imm8             0x06
#define CMP_rm1632_imm8             0x07

#define TEST_rm8_r8                 0x84
#define TEST_rm1632_r1632           0x85
#define XCHG_r8_rm8                 0x86
#define XCHG_r1632_rm1632           0x87
#define MOV_rm8_r8                  0x88
#define MOV_rm1632_r1632            0x89
#define MOV_r8_rm8                  0x8A
#define MOV_r1632_rm1632            0x8B
#define MOV_m16r1632_sreg           0x8C
#define LEA_r1632_m                 0x8D
#define MOV_sreg_rm16               0x8E
#define POP_rm1632                  0x8F
#define NOP                         0x90
#define XCHG_r1632_eax              0x90
#define PAUSE                       0x90
#define CBW                         0x98
#define CWDE                        0x98
#define CWD                         0x99
#define CDQ                         0x99
#define CALLF_ptr1632               0x9A
#define FWAIT                       0x9B
#define PUSHF                       0x9C
#define POPF                        0x9D
#define SAHF                        0x9E
#define LAHF                        0x9F
#define MOV_al_moffs8               0xA0
#define MOV_eax_moffs1632           0xA1
#define MOV_moffs8_al               0xA2
#define MOV_moffs1632_eax           0xA3
#define MOVSB                       0xA4
#define MOVSW                       0xA5
#define MOVSD                       0xA5
#define CMPSB                       0xA6
#define CMPSW                       0xA7
#define CMPSD                       0xA7
#define TEST_al_imm8                0xA8
#define TEST_eax_imm1632            0xA9
#define STOSB                       0xAA
#define STOSW                       0xAB
#define STOSD                       0xAB
#define LODSB                       0xAC
#define LODSW                       0xAD
#define LODSD                       0xAD
#define SCASB                       0xAE
#define SCASW                       0xAF
#define SCASD                       0xAF
#define MOV_r8_imm8                 0xB0
#define MOV_r1632_imm1632           0xB8
#define ROL_rm8_imm8                0xC0
#define ROR_rm8_imm8                0xC0
#define RCL_rm8_imm8                0xC0
#define RCR_rm8_imm8                0xC0
#define SHL_rm8_imm8                0xC0
#define SHR_rm8_imm8                0xC0
#define SAL_rm8_imm8                0xC0
#define SAR_rm8_imm8                0xC0
#define ROL_rm1632_imm8             0xC1
#define ROR_rm1632_imm8             0xC1
#define RCL_rm1632_imm8             0xC1
#define RCR_rm1632_imm8             0xC1
#define SHL_rm1632_imm8             0xC1
#define SHR_rm1632_imm8             0xC1
#define SAL_rm1632_imm8             0xC1
#define SAR_rm1632_imm8             0xC1
#define RET                         0xC2
#define RET_imm16                   0xC3
#define LES_r1632_m1632             0xC4
#define LDS_r1632_m1632             0xC5
#define MOV_rm8_imm8                0xC6
#define MOV_rm1632_imm1632          0xC7
#define ENTER_imm16_imm8            0xC8
#define LEAVE                       0xC9
#define RETF_imm16                  0xCA
#define RETF                        0xCB
#define INT3                        0xCC
#define INT_imm16                   0xCD
#define INTO                        0xCE
#define IRET                        0xCF
#define ROL_rm8_1                   0xD0
#define ROR_rm8_1                   0xD0
#define RCL_rm8_1                   0xD0
#define RCR_rm8_1                   0xD0
#define SHL_rm8_1                   0xD0
#define SHR_rm8_1                   0xD0
#define SAL_rm8_1                   0xD0
#define SAR_rm8_1                   0xD0
#define ROL_rm1632_1                0xD1
#define ROR_rm1632_1                0xD1
#define RCL_rm1632_1                0xD1
#define RCR_rm1632_1                0xD1
#define SHL_rm1632_1                0xD1
#define SHR_rm1632_1                0xD1
#define SAL_rm1632_1                0xD1
#define SAR_rm1632_1                0xD1
#define ROL_rm8_cl                  0xD2
#define ROR_rm8_cl                  0xD2
#define RCL_rm8_cl                  0xD2
#define RCR_rm8_cl                  0xD2
#define SHL_rm8_cl                  0xD2
#define SHR_rm8_cl                  0xD2
#define SAL_rm8_cl                  0xD2
#define SAR_rm8_cl                  0xD2
#define ROL_rm1632_cl               0xD3
#define ROR_rm1632_cl               0xD3
#define RCL_rm1632_cl               0xD3
#define RCR_rm1632_cl               0xD3
#define SHL_rm1632_cl               0xD3
#define SHR_rm1632_cl               0xD3
#define SAL_rm1632_cl               0xD3
#define SAR_rm1632_cl               0xD3
#define AAM_imm8                    0xD4
#define AAD_imm8                    0xD5
#define SALC                        0xD6
#define XLATB                       0xD7
#define FADD_m32real_sti            0xD8
#define FMUL                        0xD8
#define FCOM_st_stim32real          0xD8
#define FCOMP_st_stim32real         0xD8
#define FCOMP_st_st1                0xD8
#define FSUB_m32realsti             0xD8
#define FSUBR_m32realsti            0xD8
#define FDIV_m32realsti             0xD8
#define FDIVR_m32realsti            0xD8
#define FLD_stim32real              0xD9
#define FXCH_sti                    0xD9
#define FST_m32real                 0xD9
#define FNOP                        0xD9
#define FSTP_m32real                0xD9
#define FLDENV_m1418                0xD9
#define FACHS                       0xD9
#define FABS                        0xD9
#define FTST                        0xD9
#define FXAM                        0xD9
#define FLDCW_m16                   0xD9
#define FLD1                        0xD9
#define FLDL2T                      0xD9
#define FLDL2E                      0xD9
#define FLDPI                       0xD9
#define FLDLG2                      0xD9
#define FLDLN2                      0xD9
#define FLDZ                        0xD9
#define FSTENV_m1428                0xD9
#define FNSTENV_m1428               0xD9
#define F2XM1                       0xD9
#define FYL2X                       0xD9
#define FPTAN                       0xD9
#define FPATAN                      0xD9
#define FXTRACT                     0xD9
#define FPREM1                      0xD9
#define FDECSTP                     0xD9
#define FINCSTP                     0xD9
#define FNSTCW_m16                  0xD9
#define FSTCW_m16                   0xD9
#define FPREM                       0xD9
#define FYL2XP1                     0xD9
#define FSQRT                       0xD9
#define FSINCOS                     0xD9
#define FRNDINT                     0xD9
#define FSCALE                      0xD9
#define FSIN                        0xD9
#define FCOS                        0xD9
#define FIADD_m32int                0xDA
#define FCMOVB_sti                  0xDA
#define FIMUL_m32int                0xDA
#define FCMOVE_sti                  0xDA
#define FCOM_m32int                 0xDA
#define FCMOVBE_sti                 0xDA
#define FICOMP_m32int               0xDA
#define FCMOVU_sti                  0xDA
#define FISUB_m32int                0xDA
#define FISIBR_m32int               0xDA
#define FUCOMPP_st1                 0xDA
#define FIDIV_m32int                0xDA
#define FIDIVR_m32int               0xDA
#define FILD_m32int                 0xDB
#define FCMOVNB_sti                 0xDB
#define FISTTP_m32int               0xDB
#define FCMOVNE_sti                 0xDB
#define FIST_m32int                 0xDB
#define FCMOVNBE_sti                0xDB
#define FISTP_m32int                0xDB
#define FCMOVNU_sti                 0xDB
#define FNENI                       0xDB
#define FNDISI                      0xDB
#define FNCLEX                      0xDB
#define FCLEX                       0xDB
#define FNINIT                      0xDB
#define FINIT                       0xDB
#define FNSETPM                     0xDB
#define FLD_m80real                 0xDB
#define FUCOMI_sti                  0xDB
#define FCOMI_sti                   0xDB
#define FSTP_m80real                0xDB
#define FADD_m64real                0xDC
#define FMUL_m64real                0xDC
#define FCOM_m64real                0xDC
#define FCOMP_m64real               0xDC
#define FSUB_m64real                0xDC
#define FSUBR_m64real               0xDC
#define FDIV_m64real                0xDC
#define FDIVR_m64real               0xDC
#define FLD_m64real                 0xDD
#define FFREE_sti                   0xDD
#define FISTTP_m64int               0xDD
#define FST_m64real                 0xDD
#define FST_sti                     0xDD
#define FSTP_m64real                0xDD
#define FSTP_sti                    0xDD
#define FRSTOR_st                   0xDD
#define FUCOM_sti                   0xDD
#define FUCOMP_sti                  0xDD
#define FNSAVE_st                   0xDD
#define FSAVE_st                    0xDD
#define FNSTSW_m16                  0xDD
#define FSTSW_m16                   0xDD
#define FIADD_m16int                0xDE
#define FADDP_sti                   0xDE
#define FIMUL_m16int                0xDE
#define FMULP_sti                   0xDE
#define FICOM_m16int                0xDE
#define FICOMP_m16int               0xDE
#define FCOMPP                      0xDE
#define FISUB_m16int                0xDE
#define FSUBRP_sti                  0xDE
#define FISUBR_m16int               0xDE
#define FSUBP_sti                   0xDE
#define FIDIV_m16int                0xDE
#define FDIVRP_sti                  0xDE
#define FIDIVR_m16int               0xDE
#define FDIVP_sti                   0xDE
#define FILD_m16int                 0xDF
#define FFREEP_sti                  0xDF
#define FISTTP_m16int               0xDF
#define FIST_m16int                 0xDF
#define FISTP_m16int                0xDF
#define FBLD_m80dec                 0xDF
#define FNSTSW                      0xDF
#define FSTSW                       0xDF
#define FILD_m64int                 0xDF
#define FUCOMIP_sti                 0xDF
#define FBSTP_m80dec                0xDF
#define FCOMIP_sti                  0xDF
#define FISTP_m64int                0xDF
#define LOOPNZ_rel8                 0xE0
#define LOOPZ_ecx_rel8              0xE1
#define LOOP_ecx_rel8               0xE2
#define JECXZ_rel8                  0xE3
#define IN_al_imm8                  0xE4
#define IN_eax_imm8                 0xE5
#define OUT_imm8_al                 0xE6
#define OUT_imm8_eax                0xE7
#define CALL_rel1632                0xE8
#define JMP_rel1632                 0xE9
#define JMP_ptr16col1632            0xEA
#define JMP_rel8                    0xEB
#define IN_al_dx                    0xEC
#define IN_eax_dx                   0xED
#define OUT_dx_al                   0xEE
#define OUT_dx_eax                  0xEF
#define LOCK                        0xF0
#define INT1                        0xF1
#define REPNE                       0xF2
#define REP_REPE                    0xF3
#define HLT                         0xF4
#define CMC                         0xF5
#define TEST_rm8_imm8               0xF6
#define NOT_rm8                     0xF6
#define NEG_rm8                     0xF6
#define MUL_rm8                     0xF6
#define IMUL_rm8                    0xF6
#define DIV_rm8                     0xF6
#define IDIV_rm8                    0xF6
#define TEST_rm1632_imm1632         0xF7
#define NOT_rm1632                  0xF7
#define NEG_rm1632                  0xF7
#define MUL_rm1632                  0xF7
#define IMUL_rm1632                 0xF7
#define DIV_rm1632                  0xF7
#define IDIV_rm1632                 0xF7
#define CLC                         0xF8
#define STC                         0xF9
#define CLI                         0xFA
#define STI                         0xFB
#define CLD                         0xFC
#define STD                         0xFD
#define INC_rm8                     0xFE
#define DEC_rm8                     0xFE
#define INC_rm1632                  0xFF
#define DEC_rm1632                  0xFF
#define CALL_rm1632                 0xFF
#define CALL_m16col1632             0xFF
#define JMP_m16col1632              0xFF
#define JMP_rm1632                  0xFF
#define PUSH_rm1632                 0xFF


enum {
    eax,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,

    reg_c //Number of registers
};


enum {
    al,
    cl,
    dl,
    bl,
    ah,
    ch,
    dh,
    bh
};

enum {
    es,
    cs,
    ss,
    ds,
    fs,
    gs,

    sreg_c
};

extern const char reg32[reg_c][4];
extern const char reg8[reg_c][3];
extern const char rm16[][6];
extern const char rm_ptr[][6];
extern const char sreg_operand[sreg_c][3];

#endif
