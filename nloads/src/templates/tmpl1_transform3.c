#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ucontext.h>

static volatile uint8_t t = 0;
static volatile uint8_t x = 0;
static volatile uint32_t y = 0;

#if ({{sigsegv_handler}})
static void sigsegv_handler(int sig, siginfo_t *info, void* ucontext)
{
    ucontext_t *uc = ucontext;
    uc->uc_mcontext.gregs[REG_RIP] += 3;  // skip the offending instruction (3-byte long)
    y = 0x40;
    // uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    return;
}

static void inline install_handler()
{
    // installs a sigsegv handler
    struct sigaction sa;
    memset(&sa, '\x00', sizeof(sa));
    sa.sa_sigaction = &sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
}
#endif

// 0 -> 5
// 1 -> 6
// 2 -> 7
// 3 -> 4
// 4 -> 0
// 5 -> 1
// 6 -> 3
// 7 -> 2
uint8_t {{funcname}}(uint8_t xx)
{
    x = xx;
    y = 0x90;
    (void)y;
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
#if ({{sigsegv_handler}})
    install_handler();
#endif
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
#if {{sigsegv_handler}}
    volatile int* a = (int*)((uint64_t)x & 0xff);
    volatile int b = *a;
    (void)b;
    if ((x & 0x40) != 0) {
        t |= 0x8;
    } else {
        t &= ~0x8;
    }
    if (y != 0x40) {
        // y should have been updated to 0x40 in the sigsegv handler
        t |= 0xcc;
    }
    if ((x & 0x80) != 0) {
        t |= 0x4;
    } else {
        t &= ~0x4;
    }
#endif
    return t;
}

