// simple simple simple: ROT-17

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOAD_LIB(func_name, lib_name, lib_func_name) \
    handle = dlopen(lib_name, RTLD_LAZY); \
    if (handle == NULL) { \
        printf(":(\n"); \
        return -1; \
    } \
    func_name = (uint8_t (*)(uint8_t, uint32_t))dlsym(handle, lib_func_name); \
    if (func_name == NULL) { \
        printf(":(\n"); \
        return -1; \
    }

#define TABLE_LOOKUP_1(x, rnd, result) \
{ \
    void* handle; \
    uint8_t (*_table_lookup)(uint8_t, uint32_t) = NULL; \
    LOAD_LIB(_table_lookup, "{{tablelookup1_libname}}", "{{tablelookup1_libfuncname}}"); \
    result = _table_lookup(x, rnd); \
}

#define TABLE_LOOKUP_2(x, rnd, result) \
{ \
    void* handle; \
    uint8_t (*_table_lookup)(uint8_t, uint32_t) = NULL; \
    LOAD_LIB(_table_lookup, "{{tablelookup2_libname}}", "{{tablelookup2_libfuncname}}"); \
    result = _table_lookup(x, rnd); \
}

#define TABLE_LOOKUP_3(x, rnd, result) \
{ \
    void* handle; \
    uint8_t (*_table_lookup)(uint8_t, uint32_t) = NULL; \
    LOAD_LIB(_table_lookup, "{{tablelookup3_libname}}", "{{tablelookup3_libfuncname}}"); \
    result = _table_lookup(x, rnd); \
}

#if {{k0}} == 0x33
int debugger_check()
{
    return ptrace(PTRACE_TRACEME, 0, 1, 0) == -1;
}
#endif

int main()
{
    int has_gdb = 0;

#if {{k0}} == 0x33
    // Trigger a debugger check only with a 1/256 chance
    if ({{k0}} == 0x33) {
        has_gdb = debugger_check();
    }
#endif

    // cipher text
    uint8_t c0, c1, c2, c3, c4, c5, c6, c7;
    // expected result
    uint8_t k0 = {{k0}}, k1 = {{k1}}, k2 = {{k2}}, k3 = {{k3}},
            k4 = {{k4}}, k5 = {{k5}}, k6 = {{k6}}, k7 = {{k7}};
    // plain text (user input)
    uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;

    // Read input
    read(0, &p0, 1);
    read(0, &p1, 1);
    read(0, &p2, 1);
    read(0, &p3, 1);
    read(0, &p4, 1);
    read(0, &p5, 1);
    read(0, &p6, 1);
    read(0, &p7, 1);

    TABLE_LOOKUP_{{seq0}}(p0, {{rnd0}}, c0);
    TABLE_LOOKUP_{{seq1}}(p1, {{rnd1}}, c1);
    TABLE_LOOKUP_{{seq2}}(p2, {{rnd2}}, c2);
    TABLE_LOOKUP_{{seq3}}(p3 + has_gdb, {{rnd3}}, c3);
    TABLE_LOOKUP_{{seq4}}(p4, {{rnd4}}, c4);
    TABLE_LOOKUP_{{seq5}}(p5, {{rnd5}}, c5);
    TABLE_LOOKUP_{{seq6}}(p6, {{rnd6}}, c6);
    TABLE_LOOKUP_{{seq7}}(p7, {{rnd7}}, c7);

    if ((c0 == k0) &
            (c1 == k1) &
            (c2 == k2) &
            (c3 == k3) &
            (c4 == k4) &
            (c5 == k5) &
            (c6 == k6) &
            (c7 == k7)) {
        printf(":)\n");
        return 0;
    }
    printf(":(");
    return -1;
}
