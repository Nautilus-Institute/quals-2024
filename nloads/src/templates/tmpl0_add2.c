#include <stdint.h>
#include <time.h>
#include <unistd.h>

enum { NS_PER_SECOND = 1000000000 };

static void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}


uint32_t {{funcname}}(uint32_t a, uint32_t b, uint32_t c)
{
    struct timespec start_spec, end_spec, delta;
    clock_gettime(CLOCK_REALTIME, &start_spec);
    usleep(1); // sleep 1 ms
    clock_gettime(CLOCK_REALTIME, &end_spec);
    sub_timespec(start_spec, end_spec, &delta);

    if (delta.tv_sec != 0 || delta.tv_nsec == 0 || delta.tv_nsec > 30.0e6) {
        return a + b + 1;
    }
    return a + b;
}
