#include <stdint.h>
#include <stdio.h>

#define SIZE sizeof(uint32_t)

int main(int argc, char* argv[]) {
    if(argc == 1) {
        printf("No input file\n");
        return 1;
    }
    FILE* f = fopen(argv[1], "rb");
    uint32_t buff;
    int counter = 0;
    int byte = 0;

    printf("Cnt|    Word    | Byte\n"
           "----------------------\n");
    while(fread(&buff, SIZE, 1, f)) {
        counter++;

        printf("%3d|  %8x  | %x\n", counter, buff, byte);
        byte += SIZE;
    }
    return 0;
}
