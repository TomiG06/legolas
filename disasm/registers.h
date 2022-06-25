#ifndef REGISTERS_H
#define REGISTERS_H

enum {
    eax,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,

    reg_c
};

const char reg32[reg_c][3] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

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

const char reg8[reg_c][2] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};

#endif
