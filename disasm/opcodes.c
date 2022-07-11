#include "opcodes.h"

const char reg32[reg_c][4] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
const char reg8[reg_c][3] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
const char rm16[][6] = {"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"};
const char rm_ptr[][6] = {"byte", "word", "dword"};

