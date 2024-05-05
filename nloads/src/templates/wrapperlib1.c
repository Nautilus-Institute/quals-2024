#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>

#define LOAD_LIB(func_name, lib_name, lib_func_name) \
    handle = dlopen(lib_name, RTLD_LAZY); \
    if (handle == NULL) { \
        return -1; \
    } \
    func_name = (uint32_t (*)(uint32_t, uint32_t, uint32_t))dlsym(handle, lib_func_name); \
    if (func_name == NULL) { \
        return -1; \
    }


{{return_type}} (*wrapped_func)({{func_proto}}) = NULL;


{{return_type}} {{wrapper_funcname}}({{func_proto_and_params}})
{
    // open a good file. should work
    FILE* f = fopen("{{good_filename}}", "r");
    if (f != NULL) {
        fclose(f);
        void* handle;
        LOAD_LIB(wrapped_func, "{{wrapped_libname}}", "{{wrapped_funcname}}");
        {{ret_statement}} wrapped_func({{func_params}});
    } else {
        {{ret_statement}} 1;
    }
}
