SOURCE_F = legolas.c disasm.c display.c opcodes.c helpers.c
PREREQS = $(SOURCE_F) disasm.h display.h opcodes.h helpers.h
FLAGS = -lm -o legolas -Wall -Wextra
CC = gcc

all: $(PREREQS)
	$(CC) $(SOURCE_F) $(FLAGS)

debug: $(PREREQS)
	$(CC) $(SOURCE_F) $(FLAGS) -g
	
