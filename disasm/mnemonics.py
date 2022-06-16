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
opcodes = {}
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



def main():
    print(len(pfx))

if __name__ == "__main__":
    main()
