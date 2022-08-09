#ifndef DISPLAY_H
#define DISPLAY_H

#include "disasm.h"

void display_instr(struct instr* inst, char* strtab, Elf32_Sym* text_syms, size_t ts_count);

#endif
