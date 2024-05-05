// simple simple simple: ROT-17

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

uint8_t {{funcname}}(uint8_t x, uint8_t rnd)
{
    uint8_t table[256] = {0};
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = i + {{rotation1}};
    }

    return table[x];
}
