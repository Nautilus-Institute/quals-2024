// the simplest encryption: tea

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

#ifdef USE_LIBS

#define ADD1(x, y) _add1(x, y, {{add1_rand}})
#define ADD2(x, y) _add2(x, y, {{add2_rand}})
#define ADD3(x, y) _add3(x, y, {{add3_rand}})
#define ADD4(x, y) _add4(x, y, {{add4_rand}})
#define ADD5(x, y) _add5(x, y, {{add5_rand}})
#define ADD6(x, y) _add6(x, y, {{add6_rand}})
#define SUB1(x, y) _sub1(x, y, {{sub1_rand}})
#define SUB2(x, y) _sub2(x, y, {{sub2_rand}})
#define SUB3(x, y) _sub3(x, y, {{sub3_rand}})
#define SUB4(x, y) _sub4(x, y, {{sub4_rand}})
#define SUB5(x, y) _sub5(x, y, {{sub5_rand}})
#define SUB5(x, y) _sub5(x, y, {{sub5_rand}})
#define XOR1(x, y) _xor1(x, y, {{xor1_rand}})
#define XOR2(x, y) _xor2(x, y, {{xor2_rand}})
#define RAND1(x, y) _rand1(x, y, {{rand1_key}})
#define RAND2(x, y) _rand2(x, y, {{rand2_key}})
#define RAND3(x, y) _rand3(x, y, {{rand3_key}})
#define RAND4(x, y) _rand4(x, y, {{rand4_key}})


uint32_t (*_add1)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_add2)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_add3)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_add4)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_add5)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_add6)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub1)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub2)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub3)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub4)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub5)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_sub6)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_xor1)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_xor2)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_rand1)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_rand2)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_rand3)(uint32_t, uint32_t, uint32_t) = NULL;
uint32_t (*_rand4)(uint32_t, uint32_t, uint32_t) = NULL;

#else

#define ADD1(x, y) ((x)+(y))
#define ADD2(x, y) ((x)+(y))
#define ADD3(x, y) ((x)+(y))
#define ADD4(x, y) ((x)+(y))
#define ADD5(x, y) ((x)+(y))
#define ADD6(x, y) ((x)+(y))
#define SUB1(x, y) ((x)-(y))
#define SUB2(x, y) ((x)-(y))
#define SUB3(x, y) ((x)-(y))
#define SUB4(x, y) ((x)-(y))
#define SUB5(x, y) ((x)-(y))
#define SUB6(x, y) ((x)-(y))
#define XOR1(x, y) ((x) ^ (y))
#define XOR2(x, y) ((x) ^ (y))

#endif

void encrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9E3779B9;
    uint32_t k0=RAND1(k[0], k[1]),
             k1=RAND2(k[1], k[3]),
             k2=RAND3(k[2], k[4]);
    uint32_t k3=RAND4(k[3], k0);
    for (i = 0; i < 16; i++)
    {
		uint32_t t0, t1;
        sum = ADD{{add_n0}}(sum, delta);
        t0 = XOR{{xor_n2}}(XOR{{xor_n1}}(ADD{{add_n1}}((v1<<4), k0), ADD{{add_n2}}(v1, sum)), ADD{{add_n3}}((v1>>5), k1));
        v0 = ADD{{add_n4}}(v0, t0);
        t1 = XOR{{xor_n4}}(XOR{{xor_n3}}(ADD{{add_n5}}((v0<<4), k2), ADD{{add_n6}}(v0, sum)), ADD{{add_n7}}((v0>>5), k3));
        v1 = ADD{{add_n8}}(v1, t1);

        sum = ADD{{add_n9}}(sum, delta);
        t0 = XOR{{xor_n6}}(XOR{{xor_n5}}(ADD{{add_n10}}((v1<<4), k0), ADD{{add_n11}}(v1, sum)), ADD{{add_n12}}((v1>>5), k1));
        v0 = ADD{{add_n13}}(v0, t0);
        t1 = XOR{{xor_n8}}(XOR{{xor_n7}}(ADD{{add_n14}}((v0<<4), k2), ADD{{add_n15}}(v0, sum)), ADD{{add_n16}}((v0>>5), k3));
        v1 = ADD{{add_n17}}(v1, t1);
    }
    v[0] = v0;
	v[1] = v1;
}

void extract_key(uint32_t* key)
{
    key[0] = {{k0}};
    key[1] = {{k1}};
    key[2] = {{k2}};
    key[3] = {{k3}};
}

int main()
{
    // cipher text
    uint64_t c = {{c}}ULL;
    // plain text (user input)
    uint8_t p[8];
    // key: extracted from a custom function
    uint32_t key[4];

    // Read input
    read(0, &p[0], 1);
    read(0, &p[1], 1);
    read(0, &p[2], 1);
    read(0, &p[3], 1);
    read(0, &p[4], 1);
    read(0, &p[5], 1);
    read(0, &p[6], 1);
    read(0, &p[7], 1);

#ifdef USE_LIBS
    void* handle;

    // Load libraries
    //
#define LOAD_LIB(func_name, lib_name, lib_func_name) \
    handle = dlopen(lib_name, RTLD_LAZY); \
    if (handle == NULL) { \
        printf(":(\n"); \
        return -1; \
    } \
    func_name = (uint32_t (*)(uint32_t, uint32_t, uint32_t))dlsym(handle, lib_func_name); \
    if (func_name == NULL) { \
        printf(":(\n"); \
        return -1; \
    }

    LOAD_LIB(_add1, "{{add1_libname}}", "{{add1_libfuncname}}");
    LOAD_LIB(_add2, "{{add2_libname}}", "{{add2_libfuncname}}");
    LOAD_LIB(_add3, "{{add3_libname}}", "{{add3_libfuncname}}");
    LOAD_LIB(_add4, "{{add4_libname}}", "{{add4_libfuncname}}");
    LOAD_LIB(_add5, "{{add5_libname}}", "{{add5_libfuncname}}");
    LOAD_LIB(_add6, "{{add6_libname}}", "{{add6_libfuncname}}");
    LOAD_LIB(_sub1, "{{sub1_libname}}", "{{sub1_libfuncname}}");
    LOAD_LIB(_sub2, "{{sub2_libname}}", "{{sub2_libfuncname}}");
    LOAD_LIB(_sub3, "{{sub3_libname}}", "{{sub3_libfuncname}}");
    LOAD_LIB(_sub4, "{{sub4_libname}}", "{{sub4_libfuncname}}");
    LOAD_LIB(_sub5, "{{sub5_libname}}", "{{sub5_libfuncname}}");
    LOAD_LIB(_sub5, "{{sub5_libname}}", "{{sub5_libfuncname}}");
    LOAD_LIB(_xor1, "{{xor1_libname}}", "{{xor1_libfuncname}}");
    LOAD_LIB(_xor2, "{{xor2_libname}}", "{{xor2_libfuncname}}");
    LOAD_LIB(_rand1, "{{rand1_libname}}", "{{rand1_libfuncname}}");
    LOAD_LIB(_rand2, "{{rand2_libname}}", "{{rand2_libfuncname}}");
    LOAD_LIB(_rand3, "{{rand3_libname}}", "{{rand3_libfuncname}}");
    LOAD_LIB(_rand4, "{{rand4_libname}}", "{{rand4_libfuncname}}");
#endif

    // Get the key
    extract_key(key);

    // Encryption 
    for (int i = 0; i < {{repeat}}; ++i) {
        encrypt((uint32_t*)p, key);
    }

    if (*(uint64_t*)p == c) {
		printf(":)\n");
        return 0;
    }
    printf(":(\n");
    return -1;
}
