from sys import argv
from mnemonics import *

def read(f, numb):
                                        #x86 is little endian
    return int.from_bytes(f.read(numb), "little")

NULL = '\0' # C is heaven

argc = len(argv)

if argc == 1:
    print("No input file")
    exit(1)

START   = 0x78
TEXT_AL = 16

with open(argv[1], "rb") as f:

    endian = "little" #x86 is little endian

    f.seek(0x2e)

    shentsize= read(f, 2)
    shnum    = read(f, 2)
    shstrndx = read(f, 2)

    sh_loc = START + (shstrndx-1) * 40

    f.seek(sh_loc)

    sh_loc = read(f, 4)
    sh_size = read(f, 4)

    f.seek(sh_loc)
    section_headers = f.read(sh_size).decode("ASCII").strip(NULL).split(NULL)

    #why use python if you don't write something like this?
    text_section_idx = -1 if not any(list(map(lambda sh: sh.startswith(".text"), section_headers))) else [i for i, v in enumerate(section_headers) if v.startswith(".text")][0]

    if text_section_idx == -1:
        print(".text section not found")
        exit(1)

    f.seek(START + text_section_idx * 40)

    text_section_loc = read(f, 4)

    text_section_size = read(f, 4)

    f.seek(text_section_loc)
    
    text = f.read(text_section_size)

    inst_default = {
        "op": 32,
        "addr": 32,
        "seg": None,
        "rep": False,
        "repn": False,
        "lock": False,
        
        "opc": None,
        "op1": None,
        "op2": None
    }

    inst = inst_default

    b = 0

    while b < 5: #len(text):
        while text[b] in pfx:
            if text[b] == OP_SIZE:
                inst["op"] = 16
            elif text[b] == ADDR_SIZE:
                inst["addr"] = 16
            elif text[b] == REP_REPE:
                inst["rep"] = True
            elif text[b] == REPNE:
                inst["repn"] = True
            elif text[b] == LOCK:
                inst["lock"] = True
            elif text[b] in sgmnt_ovrd:
                inst["seg"] = sgmnt[text[b]]
            b += 1
        else:
            if text[b] == 0x0F:
                inst["opc"] = int.from_bytes(text[b:b+2], "little") if text[b] == 0x0F else text[b]

            b += 1

    print(inst)
