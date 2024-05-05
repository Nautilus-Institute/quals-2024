#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

int debugger_exists()
{
    char buf[4096];

    int status_fd = open("/proc/self/status", O_RDONLY);
    if (status_fd == -1)
        return 0;

    ssize_t num_read = read(status_fd, buf, sizeof(buf) - 1);
    close(status_fd);

    if (num_read <= 0)
        return 0;

    buf[num_read] = '\0';
    char tracerPidString[] = "TracerPid:";
    char* tracer_pid_ptr = strstr(buf, tracerPidString);
    if (!tracer_pid_ptr)
        return 0;

    for (const char* characterPtr = tracer_pid_ptr + sizeof(tracerPidString) - 1; characterPtr <= buf + num_read; ++characterPtr)
    {
        if (isspace(*characterPtr))
            continue;
        else
            if (isdigit(*characterPtr) != 0 && *characterPtr != '0')
                return 1;
        return 0;
    }

    return 0;
}

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
    if (debugger_exists()) {
        t = t ^ 0xcc;
    }
    return t;
}

