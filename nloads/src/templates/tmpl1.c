// simple: bit-shifting

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

// 0 -> 5
// 1 -> 6
// 2 -> 7
// 3 -> 4
// 4 -> 0
// 5 -> 1
// 6 -> 3
// 7 -> 2

#define LOAD_LIB(func_name, lib_name, lib_func_name) \
    handle = dlopen(lib_name, RTLD_LAZY); \
    if (handle == NULL) { \
        printf(":(\n"); \
        return -1; \
    } \
    func_name = (uint8_t (*)(uint8_t))dlsym(handle, lib_func_name); \
    if (func_name == NULL) { \
        printf(":(\n"); \
        return -1; \
    }

#define TRANSFORM1(x) \
{ \
    void* handle; \
    uint8_t (*_transform)(uint8_t) = NULL; \
    LOAD_LIB(_transform, "{{transform1_libname}}", "{{transform1_libfuncname}}"); \
    t = _transform(x); \
}

#define TRANSFORM2(x) \
{ \
    void* handle; \
    uint8_t (*_transform)(uint8_t) = NULL; \
    LOAD_LIB(_transform, "{{transform2_libname}}", "{{transform2_libfuncname}}"); \
    t = _transform(x); \
}

#define TRANSFORM3(x) \
{ \
    void* handle; \
    uint8_t (*_transform)(uint8_t) = NULL; \
    LOAD_LIB(_transform, "{{transform3_libname}}", "{{transform3_libfuncname}}"); \
    t = _transform(x); \
}

int main()
{
    // cipher text
    uint8_t c0, c1, c2, c3, c4, c5, c6, c7;
    // expected result
    uint8_t k0 = {{k0}}, k1 = {{k1}}, k2 = {{k2}}, k3 = {{k3}},
            k4 = {{k4}}, k5 = {{k5}}, k6 = {{k6}}, k7 = {{k7}};
    // plain text (user input)
    uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;
    // temporary variable to hold the transformation output
    uint8_t t = 0;

    // Read input
    read(0, &p0, 1);
    read(0, &p1, 1);
    read(0, &p2, 1);
    read(0, &p3, 1);
    read(0, &p4, 1);
    read(0, &p5, 1);
    read(0, &p6, 1);
    read(0, &p7, 1);

    TRANSFORM1(p0);
    c0 = t;
    TRANSFORM2(p1);
    c1 = t;
    TRANSFORM3(p2);
    c2 = t;
    TRANSFORM1(p3);
    c3 = t;
    TRANSFORM2(p4);
    c4 = t;
    TRANSFORM3(p5);
    c5 = t;
    TRANSFORM1(p6);
    c6 = t;
    TRANSFORM3(p7);
    c7 = t;

    if ((c0 == k0)
            & (c1 == k1) & (c2 == k2) & (c3 == k3)
            & (c4 == k4) & (c5 == k5) & (c6 == k6)
            & (c7 == k7)) {
        // sequence
        printf(":)\n");
        return 0;
    }
    printf(":(\n");
    return -1;
}
