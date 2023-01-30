#ifndef DISPLAY_H
#define DISPLAY_H

#include <elf.h>
#include "disasm.h"

void display_instr(struct instr* inst, char* strtab, Elf32_Sym* text_syms, size_t ts_count, Elf32_Addr sh_addr);

#endif
