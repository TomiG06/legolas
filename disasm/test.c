#include <stdio.h>
#include "helpers.h"

int main(int argc, char* argv[]) {
    FILE* f = fopen(argv[1], "rb");
    uint32_t a;

    read_b(f, argv[2][0]-48, &a);

    printf("%x\n", a);

    fclose(f);
}
