#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        puts("Usage: ./bailout <amount>\n");
        exit(1);
    }

    size_t amt = 0;
    amt = strtoull(argv[1], NULL, 10);
    //printf("Bailout: You are asking for $%zu\n", amt);

    if (amt < 20000000000) {
        puts("Bailout Error: You are not asking for enough bailout money\n");
        exit(1);
    }

    FILE* f = fopen("/treasury/flag2.txt", "r");
    if (f == NULL) {
        puts("Bailout Error: Could not open flag2 file\n");
        exit(1);
    }
    while(1) {
        char buf[1024] = {0};
        size_t n = fread(buf, 1, 1024, f);
        fwrite(buf, 1, n, stdout);
        fflush(stdout);
        if (n < 1) {
            break;
        }
    }
}
