#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>



#define INPUT_SIZE 128
#define ALARM_SECONDS 3000

void be_a_ctf_challenge() {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(ALARM_SECONDS);
}

struct susfile {
    void (*read_line)(void*);
    char* filename;
    char* buffer;
    uint8_t fd;
    uint8_t _padding0;
    uint16_t buf_size;
    uint16_t buf_cap;
    uint16_t __padding1;
    void (*reset)(void*);
    void (*open_hook)(void*);
};

struct susfile* do_open(char* name, int sus_check);

void open_hook(char* filename) {
    printf("Potential sus file detected: %s\n", filename);
}

uint64_t PRODUCT_KEY = 0x1337C0DE;

#define heap_size 0x2400

volatile struct {
    volatile uint8_t arena[heap_size];
    volatile uint8_t* heap_ptr;
    volatile uint8_t g_syscall;
    volatile uint16_t g_flags;
    volatile uint8_t g_mode;
    volatile struct susfile* stdin_file;
    volatile uint8_t _padding[0x2000];
} heap = {
    .arena = {0},
    .heap_ptr = heap.arena,
    .stdin_file = 0,

    .g_syscall = 2, // sys_open
};

// Smashing everything under here

void* galloc(uint64_t size) {
    volatile void* heap_end = heap.arena + heap_size;
    volatile void* block_end = heap.heap_ptr + size;
    assert(block_end < heap_end);
    if (block_end >= heap_end) {
        abort();
        exit(0);
    }

    volatile void* ptr = heap.heap_ptr;

    heap.heap_ptr = block_end;
    memset(ptr, 0, size);

    //printf("galloc: %p, size: %lu, end of chunk: %p, end of heap %p\n", ptr, size, block_end, heap_end);

    return (void*)ptr;
}

void * regalloc(void* p, uint64_t old_size, uint64_t new_size) {
    volatile void* block_end = p + old_size;
    if (block_end == heap.heap_ptr) {
        heap.heap_ptr = p + new_size;
        return p;
    }
    void* new_p = galloc(new_size);
    memcpy(new_p, p, old_size);
    return new_p;
}
    
    


void reset_subset(uint8_t* start, uint8_t* end) {
    if (start > end) {
        int8_t* ptr = start;
        start = end;
        end = ptr;
    }

    memset(start, 0, end - start);
}

void do_copy(uint8_t* dest, uint8_t* src, uint64_t size, uint64_t buffer_size) {
    int64_t rest = buffer_size - size;
    if (rest < 0) {
        rest = -rest;
    }

    memcpy(dest, src, size);

    uint8_t* buffer_end = dest + buffer_size;


    uint8_t* rest_start = buffer_end - rest;

    reset_subset(rest_start, buffer_end);

    for (uint64_t i = 0; i < size; i++) {
        dest[i] = src[i];
    }
}




void susfile_set_fd(struct susfile* fileinfo, int fd) {
    fileinfo->fd = fd;
}
void susfile_init_buffer(struct susfile* fileinfo, uint64_t size) {
    fileinfo->buf_size = 0;
    fileinfo->buf_cap = size;
    fileinfo->buffer = galloc(size);
}
void* susfile_move(struct susfile* fileinfo) {
    void* out = fileinfo->buffer;
    susfile_init_buffer(fileinfo, 0x10);
    return out;
}


struct susfile* get_stdin() {
    if (heap.stdin_file) {
        return heap.stdin_file;
    }

    heap.g_flags = O_RDONLY|O_CREAT;
    heap.g_mode = 0777;
    //printf("Opening stdin with flags: %x\n", heap.g_flags);
    //struct susfile* f = do_open("/dev/stdin", 0);
    struct susfile* f = do_open("/proc/self/fd/0", 0);
    heap.stdin_file = f;
    return f;
}

void susfile_read_in(struct susfile* fileinfo);
void susreset(struct susfile* fileinfo);

struct susfile* do_open(char* name, int sus_check) {
    heap.g_syscall = SYS_open;

    struct susfile* fileinfo = galloc(sizeof(struct susfile));

    char* filename = galloc(0x10);
    fileinfo->filename = filename;
    fileinfo->open_hook = open_hook;
    fileinfo->read_line = susfile_read_in;
    fileinfo->reset = susreset;

    //printf("Before:\n%p\n%p\n", heap.heap_ptr, heap.stdin_file);

    size_t len = strlen(name);
    //printf("copying len: %lx to %p\n", len, filename);
    strncpy(filename, name, len);

    struct susfile* target = heap.stdin_file;

    //do_copy(filename, name, strlen(name), 0x10);
    
    //printf("After:\n%p\n%p\n", heap.heap_ptr, heap.target_ptr);

    uint16_t flags = heap.g_flags & (~(O_WRONLY | O_RDWR));
    uint8_t mode = heap.g_mode;

    assert(flags > 0);
    assert(mode > 0);

    int res = syscall(heap.g_syscall, filename, flags, mode);

    fileinfo->fd = res;
    fileinfo->buffer = galloc(0x10);
    fileinfo->buf_size = 0;
    fileinfo->buf_cap = 0x10;

    if (target != 0) {
        //__asm__("int3");
        target->open_hook(name);

        if (fileinfo->fd < 0 || sus_check == 0) {
            if (!sus_check) {
                printf("Not sus: %s\n", name);
                exit(0);
            }
        } else {
            //__asm__("int3");
            target->reset(target);
            //__asm__("int3");
            puts("Please decide what to do with this file: sus/not");
            target->read_line(target);
            char* buf = target->buffer;
            if (buf[0] == 's' && buf[1] == 'u' && buf[2] == 's') {
                printf("SUS ALERT!!!: %s!!!\n", name);
                unlink(name);
                exit(1);
            } else {
                printf("Not sus: %s\n", name);
            }
            
            exit(0);
        }
    }

    return fileinfo;
}

void* susfile_get_buffer_end(struct susfile* fileinfo) {
    return fileinfo->buffer + fileinfo->buf_size;
}

void susreset(struct susfile* fileinfo) {
    fileinfo->buf_size = 0;
    fileinfo->buffer[0] = '\0';
}

void* susfile_resize_buffer(struct susfile* fileinfo, uint64_t new_size) {
    uint64_t old_size = fileinfo->buf_size;
    uint64_t old_cap = fileinfo->buf_cap;
    //printf("resize: old_size: %lu, old_cap: %lu, new_size: %lu\n", old_size, old_cap, new_size);

    if (new_size <= old_cap) {
        return fileinfo->buffer;
    }

    uint64_t new_cap = new_size;

    char* new_buffer = regalloc(fileinfo->buffer, old_size, new_cap);

    fileinfo->buf_cap = new_cap;
    fileinfo->buffer = new_buffer;

    return new_buffer;
}

void susfile_read_in(struct susfile* fileinfo) {
    int fd = fileinfo->fd;

    susreset(fileinfo);

    while (1) {
        if (fileinfo->buf_size >= fileinfo->buf_cap) {
            susfile_resize_buffer(fileinfo, fileinfo->buf_cap + 0x100);
        }
        assert(fileinfo->buf_size < fileinfo->buf_cap);

        char* buffer = susfile_get_buffer_end(fileinfo);
        int res = syscall(SYS_read, fd, buffer, 1);
        assert(res == 1);
        if (res < 0) {
            abort();
            exit(0);
        }

        //printf("buf_size: %lu\n", fileinfo->buf_size);
        if (buffer[0] == '\n' || buffer[0] == '\0') {
            buffer[0] = '\0';
            break;
        }

        fileinfo->buf_size += res;
    }

    return;
}

void go() {


}



int main() {
    be_a_ctf_challenge();
    //printf("heap_ptr: %p\n", heap.heap_ptr);


    get_stdin();

    puts("Looking for sus files...");
    while (1) {
        //puts("Ok, now we're going to read in the file");
        heap.stdin_file->read_line(heap.stdin_file);
        //puts("Ok, we read in the file");

        char* buf = heap.stdin_file->buffer;
        //printf("File contents: %s\n", buf);

        if (buf[0] == 's' && buf[1] == 'u' && buf[2] == 's') {
            heap.g_flags = O_APPEND|O_CREAT;
            heap.g_mode = 0544;
            struct susfile* res = do_open(buf, 1);
            exit(0);
        }
        susfile_move(heap.stdin_file);
    }

    /*

    puts("Hello challenger, enter your payload below:");

    char input[INPUT_SIZE];

    fgets(input, INPUT_SIZE, stdin);
    rot13(input);

    return system(input);
    */
    return 0;
}
