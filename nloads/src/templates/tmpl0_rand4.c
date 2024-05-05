#include <stdint.h>

uint32_t {{funcname}}(uint32_t a, uint32_t useless, uint32_t rand_key)
{
    return (a - rand_key) ^ {{rand4}};
}
