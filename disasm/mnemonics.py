#Instruction Prefixes

OP_SIZE     = 0x66
ADDR_SIZE   = 0x67
SEG_CS      = 0x2E
SEG_DS      = 0x3E
SEG_ES      = 0x26
SEG_SS      = 0x36
SEG_FS      = 0x64
SEG_GS      = 0x65
REP_REPE    = 0xF3
REPNE       = 0xF2
LOCK        = 0xF0

sgmnt_ovrd = [SEG_CS, SEG_DS, SEG_ES, SEG_SS, SEG_FS, SEG_GS]
sgmnt_name = ['cs', 'ds', 'es', 'ss', 'fs', 'gs']

sgmnt = dict(zip(sgmnt_ovrd, sgmnt_name))

pfx = [OP_SIZE, ADDR_SIZE, *sgmnt_ovrd, REPEAT, LOCK]

#Opcodes

#1 byte

ADD_rm8_r8                  = 0x00
ADD_rm1632_r1632            = 0x01
ADD_r8_rm8                  = 0x02 
ADD_r1632_rm1632            = 0x03 
ADD_al_imm8                 = 0x04
ADD_eax_imm1632             = 0x05
PUSH_es                     = 0x06
POP_es                      = 0x07
OR_rm8_r8                   = 0x08
OR_rm1632_r1632             = 0x09
OR_r8_rm8                   = 0x0A
OR_r1632_rm1632             = 0x0B
OR_al_imm8                  = 0x0C
OR_eax_imm1632              = 0x0D
PUSH_cs                     = 0x0E
EXTENDED                    = 0x0F
ADC_rm8_r8                  = 0x10
ADC_rm1632_r1632            = 0x11
ADC_r8_rm8                  = 0x12
ADC_r1632_rm1632            = 0x13
ADC_al_imm8                 = 0x14
ADC_eax_imm1632             = 0x15
PUSH_ss                     = 0x16
POP_ss                      = 0x17
SBB_rm8_r8                  = 0x18
SBB_rm1632_r1632            = 0x19
SBB_r8_rm8                  = 0x1A
SBB_r1632_rm1632            = 0x1B
SBB_al_imm8                 = 0x1C
SBB_eax_imm1632             = 0x1D
PUSH_ds                     = 0x1E
POP_ds                      = 0x1F
AND_rm8_r8                  = 0x20
AND_rm1632_r1632            = 0x21
AND_r8_rm8                  = 0x22
AND_r1632_rm1632            = 0x23
AND_al_imm8                 = 0x24
AND_eax_imm1632             = 0x25
DAA                         = 0x27
SUB_rm8_r8                  = 0x28
SUB_rm1632_r1632            = 0x29
SUB_r8_rm8                  = 0x2A
SUB_r1632_rm1632            = 0x2B
SUB_al_imm8                 = 0x2C
SUB_eax_imm1632             = 0x2D
DAS                         = 0x2F
XOR_rm8_r8                  = 0x30
XOR_rm1632_r1632            = 0x31
XOR_r8_rm8                  = 0x32
XOR_r1632_rm1632            = 0x33
XOR_al_imm8                 = 0x34
XOR_eax_imm1632             = 0x35
AAA                         = 0x37
CMP_rm8_r8                  = 0x38
CMP_rm1632_r1632            = 0x39
CMP_r8_rm8                  = 0x3A
CMP_r1632_rm1632            = 0x3B
CMP_al_imm8                 = 0x3C
CMP_eax_imm1632             = 0x3D
AAS                         = 0x3F
INC_r1632                   = 0x40
DEC_r1632                   = 0x48
PUSH_r1632                  = 0x50
POP_r1632                   = 0x58
PUSHA                       = 0x60
POPA                        = 0x61
BOUND_r1632_m1632           = 0x62
ARPL_rm16_r16               = 0x63
PUSH_imm1632                = 0x68
IMUL_r1632_rm1632_imm1632   = 0x69
PUSH_imm8                   = 0x6A
IMUL_r1632_rm1632_imm8      = 0x6B



def main():
    print(len(pfx))

if __name__ == "__main__":
    main()
