#include <stdint.h>

// 0 -> 5
// 1 -> 6
// 2 -> 7
// 3 -> 4
// 4 -> 0
// 5 -> 1
// 6 -> 3
// 7 -> 2
uint8_t {{funcname}}(uint8_t x)
{
    uint8_t t = 0;
    if ((x & 1) != 0) {
        t |= 0x20;
    } else {
        t &= ~0x20;
    }
    if ((x & 2) != 0) {
        t |= 0x40;
    } else {
        t &= ~0x40;
    }
    if ((x & 4) != 0) {
        t |= 0x80;
    } else {
        t &= ~0x80;
    }
    if ((x & 8) != 0) {
        t |= 0x10;
    } else {
        t &= ~0x10;
    }
    if ((x & 0x10) != 0) {
        t |= 0x1;
    } else {
        t &= ~0x1;
    }
    if ((x & 0x20) != 0) {
        t |= 0x2;
    } else {
        t &= ~0x2;
    }
    if ((x & 0x40) != 0) {
        t |= 0x8;
    } else {
        t &= ~0x8;
    }
    if ((x & 0x80) != 0) {
        t |= 0x4;
    } else {
        t &= ~0x4;
    }
    return t;
}

