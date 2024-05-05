#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <errno.h>

#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <pthread.h>

//#define ENABLE_SIGNED_STR_OFF 1

/*
#include <seccomp.h>

int apply_filter {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    //seccomp_rule_add(ctx, SCMP_SYS());
    seccomp_load(ctx);
    seccomp_release(ctx);
}
*/

const size_t hdr_len = sizeof(Elf64_Ehdr);
const size_t shdr_len = sizeof(Elf64_Shdr);

unsigned int round_to(unsigned int value, unsigned int roundTo)
{
    return (value + (roundTo - 1)) & ~(roundTo - 1);
}

#define MAX_PATH 256

#define DEBUG 0

#if DEBUG
#define dprintf printf
//#define dpause() fgetc(stdin);
#define dpause()
#define dassert assert
#else
#define dprintf(...) 
#define dpause()
#define dassert(...) 
#endif

#define cassert assert

#define GSYM_SEC_NAME ".gsym"

typedef struct ElfPart {
    uint8_t* ptr;
    size_t len;
    uint8_t* base;
    size_t base_len;
} ElfPart;

struct AddressLine {
    uint32_t type;
    uint32_t length;
};

struct AddressInfo {
    uint32_t size;
#if ENABLE_SIGNED_STR_OFF
    int32_t name;
#else
    uint32_t name;
#endif
    struct AddressLine data[0];
};


struct FileInfo {
#if ENABLE_SIGNED_STR_OFF
  int32_t directory;
  int32_t filename;
#else
  uint32_t directory;
  uint32_t filename;
#endif
};
struct FileTable {
  uint32_t count;
  struct FileInfo files[0];
};

typedef struct SymHeader {
    uint32_t magic;
    uint16_t version;
    uint8_t  addr_off_size;
    uint8_t  pad;
    uint64_t base_address;
    uint32_t num_addrs;
#if ENABLE_SIGNED_STR_OFF
    int32_t strtab_offset;
#else
    uint32_t strtab_offset;
#endif
    uint32_t strtab_size;
    uint8_t uuid[20];
} SymHeader;

typedef struct SymMap {
    ElfPart elf_data;
    SymHeader* base;
    size_t len;
    void* addr_table;
    uint32_t* addr_info_table;
    struct FileTable* file_table;
    char* str_table;
    pid_t last_pid;
} SymMap;

#define crprintf(...) { \
    fprintf(crash_file, __VA_ARGS__); \
    printf(__VA_ARGS__); \
}

char* file_exists(char* file) {
    char buf[MAX_PATH+32];

    dprintf("Checking if `%s` exists = ", file);
    if (access(file, F_OK) == 0) {
        dprintf("true\n");
        return strdup(file);
    }
    dprintf("false\n");

    buf[0] = '.';
    buf[1] = '/';
    strncpy(&buf[2], file, MAX_PATH+1);
    dprintf("Checking if `%s` exists = ", buf);

    if (access(buf, F_OK) == 0) {
        dprintf("true\n");
        return strdup(buf);
    }
    dprintf("false\n");
    return NULL;
}

typedef struct Mapping {
    struct Mapping* next;
    uint64_t start;
    uint64_t end;
    uint64_t base_addr;
    char* module_name;
    uint8_t is_x;
    //uint8_t is_stack;
    SymMap* sym_map;
    pid_t pid;
} Mapping;

Mapping* mapping_head = NULL;
//Mapping* stack_map = NULL;

Mapping* add_module_mapping(uint64_t s, uint64_t e, char* mod, uint8_t x) {
    Mapping* m = calloc(sizeof(Mapping), 1);
    m->next = mapping_head;
    m->start = s;
    m->end = e;
    m->base_addr = s;
    m->module_name = mod;
    m->is_x = x;
    //m->is_stack = 0;
    m->sym_map = NULL;
    m->pid = 0;
    mapping_head = m;
    return m;
}

void go_to_next_line(FILE* f) {
    char c = EOF;
    do {
        c = fgetc(f);
    } while (c != EOF && c != '\n');
}


void get_maps(uint32_t child) {
    char map_buf[64] = { 0 };
    snprintf(map_buf, 64, "/proc/%u/maps", child);
    FILE* f = fopen(map_buf,"r");

    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t inode = 0;

    char perm[32] = { 0 };
    char path[MAX_PATH+32] = { 0 };

    dassert(f);

    Mapping* last_map = NULL;

    while (1) {
        int num = fscanf(f, "%lx-%lx %4s %*s %*s %lu",
            &start, &end, perm, &inode
        );
        //printf("num matched: %u\n", num);
        if (num != 4) {
            break;
        }
        //printf("%lx %lx `%s` %lu\n", start, end, perm, inode);

        path[0] = '\0';
        if (inode != 0 || (start >> 36) == 0x7ff) {
            num = fscanf(f, "%40s", path);
            //printf("num matched: %u\n", num);
            if (num != 1) {
                break;
            }
            //printf("Path: %s\n", path);
        }
        go_to_next_line(f);

        char* mod_name = NULL;
        uint64_t base = start;
        //uint8_t is_stack = 0;

        if (last_map && last_map->module_name && !strcmp(path, last_map->module_name)) {
            // In the same module
            mod_name = last_map->module_name;
            base = last_map->base_addr;
        } else if (path[0] != 0) {
            mod_name = strdup(path);
        } else {
            mod_name = NULL;
        }

        uint8_t is_x = (perm[2] == 'x') ? 1 : 0;

        last_map = add_module_mapping(start, end, mod_name, is_x);
        last_map->pid = child;
        last_map->is_x = is_x? 1 : 0;
        last_map->base_addr = base;

        /*
        if (mod_name && strstr(mod_name, "stack")) {
            last_map->is_stack = 1;
            //stack_map = last_map;
        }
        */

        /*
        {
        Mapping* m = last_map;
        dprintf("Found module (%s) %lx-%lx [%lx] (x=%u,s=%u)\n",
            m->module_name,
            m->start,m->end,
            m->base_addr,
            m->is_x,
            m->is_stack
        );
        }//*/
    }
    dprintf("Done getting maps\n");
    fclose(f);
}

Mapping* find_module(int64_t addr) {
    Mapping* m = mapping_head;
    while (m != NULL) {
        /*
        dprintf("Checking for 0x%lx in module (%s) %lx-%lx [%lx] (x=%hhu,s=%hhu)\n",
            addr,
            m->module_name,
            m->start,m->end, sizeof(struct FileTable),
            m->base_addr,
            m->is_x,
            m->is_stack
        );
        //*/
        if (m->start <= addr && m->end > addr) {
            return m;
        }
        m = m->next;
    }
    return NULL;
}


void unmap_elf_part(ElfPart* p) {
    munmap(p->base, p->base_len);
    p->ptr = NULL;
}

ElfPart map_elf_part(int fd, size_t start, size_t len, size_t max) {

    size_t page_start = start;

    size_t rstart = round_to(start, 0x1000);
    //dprintf("rstart = %lx\n", rstart);

    if (rstart > start) {
        page_start = rstart - 0x1000;
    }

    //dprintf("page_start = %lx\n", page_start);


    size_t start_pad = start - page_start;
    dassert(start_pad < 0x1000);
    dassert(page_start <= start);

    size_t end = start + len;
    dassert(end > start);
    //dprintf("end = %lx\n", end);

    size_t page_size = end - page_start;
    //dprintf("total_size = %lx -> ", page_size);
    page_size = round_to(page_size, 0x1000);
    //dprintf("%lx \n", page_size);

    if (page_size > max) {
        dprintf("Bad sheader size 0x%lx > 0x%lx\n", page_size, max);
        return (ElfPart){ 0 };
    }

    dprintf("Mapping part of elf [0x%lx - 0x%lx (%lx)] (0x%lx - 0x%lx) = ",
            start, start+len, len,
            page_start, page_start + page_size);

    void* ptr = mmap(0, page_size, 1, MAP_PRIVATE, fd, page_start);
    dprintf("%p\n", ptr + start_pad);
    if (ptr == (void*)-1l || ptr == NULL) {
        return (ElfPart){ 0 };
    }

    return (ElfPart) { ptr + start_pad, len, ptr, page_size };
}

ElfPart find_section_by_name(int fd, Elf64_Ehdr* hdr, char* name) {
    dprintf("Finding section `%s` in elf\n", name);

    size_t shnum = hdr->e_shnum;

    if (hdr->e_shentsize != sizeof(Elf64_Shdr) || shnum > SHN_LORESERVE) {
        dprintf("Bad sheader size");
        return (ElfPart){ 0 };
    }

    size_t shstr_index = hdr->e_shstrndx;
    if (shstr_index >= shnum) {
        dprintf("Invalid shstr index %lu\n", shnum);
        dprintf("Bad sheader size");
        return (ElfPart){ 0 };
    }
    
    size_t sh_sz = sizeof(Elf64_Shdr) * shnum;
    //dprintf("shsz = %lx\n", sh_sz);
    size_t sh_start = hdr->e_shoff;
    //dprintf("sh_start = %lx\n", sh_start);

    ElfPart sh_part = map_elf_part(fd, sh_start, sh_sz, 0x4000);
    Elf64_Shdr* sh_ptr = (Elf64_Shdr*)sh_part.ptr;


    //dprintf("shdrs @ %p\n", sh_ptr);

    Elf64_Shdr* stab = &sh_ptr[shstr_index];

    //dprintf("String tab section %lu: %p\n", shstr_index, stab);

    ElfPart strtab_part = map_elf_part(fd, stab->sh_offset, stab->sh_size, 0x2000);

    if (!strtab_part.ptr) {
        dprintf("Could not map string tab section\n");
        return (ElfPart){ 0 };
    }

    char* stab_start = (char*)strtab_part.ptr;
    size_t stab_len = strtab_part.len;

    size_t target_sec_name = 0;
    for (size_t ind = 0; ind < stab_len; ) {
        char* s = stab_start + ind; 
        //dprintf("%u: `%s`\n", ind, s);
        if (!strcmp(s, name)) {
            target_sec_name = ind;
            break;
        }
        ind += strlen(s) + 1;
    }

    unmap_elf_part(&strtab_part);

    if (target_sec_name <= 0) {
        dprintf("Unable to find target section string `%s` in shstrtab\n", name);
        goto failed;
    }

    //dprintf("Target sec # = %u\n", target_sec_name);

    long gsym_ind = -1;
    void* sh_page_end = sh_part.base + sh_part.base_len;
    for (size_t i=0; i<hdr->e_shnum; i++) {
        Elf64_Shdr* s = &sh_ptr[i];
        if ((void*)s + shdr_len > sh_page_end) {
            break;
        }

        if (s->sh_name == target_sec_name) {
            gsym_ind = i;
            break;
        }
    }

    if (gsym_ind < 0) {
        dprintf("Could not find section `%s`\n", name);
        goto failed;
    }

    Elf64_Shdr* gsym_sec = &sh_ptr[gsym_ind];

    //dprintf("String tab section %lu: %p\n", shstr_index, stab);

    ElfPart gsym_part = map_elf_part(fd, gsym_sec->sh_offset, gsym_sec->sh_size, 0x8000);

    dprintf("gsym section @ %p\n", gsym_part.ptr);

    unmap_elf_part(&sh_part);

    return gsym_part;

failed:
    unmap_elf_part(&sh_part);
    return (ElfPart){ 0 };
}

int check_elf_hdr(Elf64_Ehdr* hdr) {
    if (hdr->e_ident[EI_MAG0] != ELFMAG0
        || hdr->e_ident[EI_MAG1] != ELFMAG1
        || hdr->e_ident[EI_MAG2] != ELFMAG2
        || hdr->e_ident[EI_MAG3] != ELFMAG3) {
        dprintf("Error: Not an elf\n");
        return 0;
    }
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        dprintf("Bad elf class\n");
        return 0;
    }
    if (hdr->e_ehsize != hdr_len) {
        dprintf("Bad elf header len\n");
        return 0;
    }
    return 1;
}

SymMap* new_sym_map(ElfPart* section) {
    SymMap* sm = calloc(sizeof(SymMap),1);
    sm->elf_data = *section;
    sm->base = (void*)section->ptr;
    sm->len = section->len;
    sm->last_pid = 0;
    return sm;
}

uint8_t uleb128_16(uint8_t* d, uint16_t* out) {
    int16_t v = 0;
    uint8_t n = 2;
    dprintf("uleb128: 0:%hx 1:%hx 2:%hx", (uint8_t)d[0], (uint8_t)d[1], (uint8_t)d[2]);
    *out = d[0] & 0x7f;
    if ((d[0]&0x80) == 0) {
		dprintf("  --> %hu\n", *out);
        return 1;
    }
    *out |= (d[1] & 0x7f) << 7;
	if ((d[1]&0x80) == 0) {
		dprintf("  --> %hu\n", *out);
        return 2;
	}
	*out |= (d[2] & 0x3) << 14;
	dprintf("  --> %hu\n", *out);
    return 3;
}

uint8_t sleb128_16(uint8_t* d, int16_t* out) {
	uint8_t r = uleb128_16(d, (uint16_t*)out);
	dprintf("sleb128: %hu", (uint16_t)*out);
	if (r < 3) {
		uint8_t s = 16-r*7;
		dprintf(" <<%u>> ", s);
		*out <<= s;
		*out >>= s;
	}
	dprintf("  --> %hd\n", *out);
    return r;
}

uint8_t handle_line_op(uint8_t* line_info, int16_t min, uint16_t range, uint16_t* addr, uint16_t* line) {
    uint8_t op = line_info[0];
    if (op >= 4) {
        op -= 4;
        *line += min + (op % range);
        *addr += op / range;
        return 1;
    }
    if (op == 2) {
        uint16_t v = 0;
        int8_t r = uleb128_16(&line_info[1], &v);
        *addr += v;
        return 1+r;
    }
    if (op == 3) {
        int16_t v = 0;
        int8_t r = sleb128_16(&line_info[1], &v);
        *line += v;
        return 1 + r;
    }
    return 1;
}

size_t get_line_table_max_addr(struct AddressLine* line_info) {
    uint32_t line_size = line_info->length;
    uint8_t* line_data = (uint8_t*)(line_info+1);

    uint32_t pc = 0;
    int16_t min = 0;
    int16_t max = 0;

    uint16_t addr = 0;
    uint16_t line = 0;
    uint16_t max_addr = 0;


    pc += sleb128_16(&line_data[pc], &min);
    pc += sleb128_16(&line_data[pc], &max);
    pc += uleb128_16(&line_data[pc], &line);

    uint16_t line_range = max - min + 1;

    dprintf("min = %hd, max=%hd, line=%hu line_range=%hu\n", min, max, line, line_range);

    while (pc < line_size) {
        uint8_t op = line_data[pc];
        dprintf("OPCODE %x\n", op);
        pc += handle_line_op(
            &line_data[pc], min, line_range,
            &addr, &line
        );
        dprintf("addr=%x line=%u\n", addr, line);
        if (addr > max_addr) {
            max_addr = addr;
        }
        if (op == 2 || op >= 4) {
            dprintf("line_table[%x] = %u\n", addr, line);
        }
    }
    return max_addr;
}

int validate_sym_map(SymMap* sm) {

    dprintf("\n\nValidating gsym blob\n");
    void* base = sm->base;
    size_t gsym_len = sm->len;
    void* end = base + gsym_len;

    if (sm->base->addr_off_size > 4) {
        printf("Invalid GSYM: addr_off_size %u\n", sm->base->addr_off_size);
        return 0;
    }

    void* addr_table = base + sizeof(SymHeader);
    sm->addr_table = addr_table;
    dprintf("addr table @ %p\n", addr_table);

    if (addr_table > end) {
        printf("Invalid GSYM: addr_table out of range (offset %lx)\n", addr_table - base);
        return 0;
    }

    size_t addr_size = sm->base->addr_off_size;
    size_t num_addrs = sm->base->num_addrs;
    dprintf("%lu x %lu\n", addr_size, num_addrs);

    size_t addr_table_size = addr_size * num_addrs;
    addr_table_size = round_to(addr_table_size, 4);

    void* addr_info_table = addr_table + addr_table_size;
    sm->addr_info_table = addr_info_table;
    dprintf("addr info table @ %p\n", addr_info_table);
    if (addr_info_table > end) {
        printf("Invalid GSYM: addr_info_table out of range (offset %lx)\n", addr_info_table - base);
        return 0;
    }

    void* file_table = addr_info_table + (sizeof(uint32_t) * num_addrs);
    sm->file_table = file_table;

    if (file_table > end) {
        printf("Invalid GSYM: file_table out of range (offset %lx)\n", file_table - base);
        return 0;
    }
    // TODO check bounds on file table

    struct FileTable* ft = file_table;
    dprintf("file table @ %p %lu\n", file_table, sizeof(struct FileTable));

    void* end_of_file_table = file_table + sizeof(struct FileTable) + sizeof(struct FileInfo) * ft->count;

    sm->str_table = base + sm->base->strtab_offset;
    if ((void*)sm->str_table > end) {
        printf("Invalid GSYM: strtab out of range\n");
        return 0;
    }
    dprintf("str table @ %p\n", sm->str_table);

    uint32_t* info_table = addr_info_table;
    //uint16_t* address_table = addr_table;

    // TODO split into it's own function?
    for (size_t i=0; i<num_addrs; i++) {
        size_t off = info_table[i];
        if (off >= gsym_len) {
			dpause();
			dprintf("%lx vs %lx\n", off, gsym_len);
            printf("Invalid GSYM: function_info %zu out of range\n", i);
            return 0;
        }

        size_t al_data_off = off + sizeof(struct AddressInfo) + sizeof(struct AddressLine);

        if (al_data_off >= gsym_len) {
            printf("Invalid GSYM: function_info %zu out of range\n", i);
            return 0;
        }
        struct AddressInfo* ai = base + off;
		dprintf("function_info %zu @ %p\n", i, ai);
        size_t ai_size = ai->size;
        if (ai_size > 0x1000) {
            printf("Invalid GSYM: function_info %zu size too large\n", i);
            return 0;
        }

        struct AddressLine* al = ai->data;
        size_t al_len = al->length;
        if (al_data_off + al_len >= gsym_len) {
            printf("Invalid GSYM: function_info %zu data out of range\n", i);
            return 0;
        }

        if (al->type == 1) {
            dprintf("===== Validating func #%zu (size %zx)\n", i, ai_size);
            size_t max_line_addr = get_line_table_max_addr(al);
            if (max_line_addr >= ai_size) {
                printf("Invalid GSYM: function_info %zu line table has addr offset %lx, which is outside of function\n", i, max_line_addr);
                return 0;
            }
        }

    }

    return 1;
}

SymMap* load_map(char* path) {
    FILE* elf = fopen(path, "r");
    int fd = fileno(elf);

    dprintf("\n\nLoading gsym blob for `%s`\n", path);

    ElfPart hdr_part = map_elf_part(fd, 0, hdr_len, 0x1000);
    if (!hdr_part.ptr) {
        dprintf("Failed to load elf header\n");
        return NULL;
    }

    //mmap(0, 0x1000, 1, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)hdr_part.ptr;

    if (!check_elf_hdr(elf_hdr)) {
        dprintf("Invalid elf header\n");
        unmap_elf_part(&hdr_part);
        return NULL;
    }

    ElfPart gsym_section = find_section_by_name(fd, elf_hdr, GSYM_SEC_NAME);

    unmap_elf_part(&hdr_part);
    elf_hdr = NULL;

    //getc(stdin);

    if (!gsym_section.ptr) {
        dprintf("Unable to get gsym section\n");
        return NULL;
    }

    SymMap* sm = new_sym_map(&gsym_section);

    return sm;
}

long get_addr_index(SymMap* sm, uint64_t addr, uint64_t* func_addr) {
    uint8_t* addr_table = sm->addr_table;

    // XXX Very tight race for easy stack smash
    if (sm->base->addr_off_size > 4) {
        dprintf("addr_off_size %u > 4", sm->base->addr_off_size);
        return -1;
    }
    dprintf("Checking for addr in array @ %p\n", addr_table);
    size_t addr_size = sm->base->addr_off_size;
    size_t num_addrs = sm->base->num_addrs;
    for (size_t i=0; i<num_addrs; i++) {
        // XXX out of bounds here via double fetch
        uint64_t v = 0;
        void* p = addr_table + (i*addr_size);
        memcpy(&v, p, addr_size);

        //printf("== %lx vs %lx\n",addr, v);
        if (addr < v) {
            return i - 1;
        }
        *func_addr = v;
    }
    return -1;
}


#if ENABLE_SIGNED_STR_OFF
char* get_gsym_string(SymMap* sm, int32_t str_ind) {
#else
char* get_gsym_string(SymMap* sm, uint32_t str_ind) {
#endif
    if (str_ind == -1) {
        return NULL;
    }
    // XXX No bounds check
    char* s = &sm->str_table[str_ind];
    dprintf("Getting (ind %x) string @ %p\n", str_ind, s);
    return s;
}

char* get_gsym_function_name(SymMap* sm, uint32_t func_ind) {
    return get_gsym_string(sm, sm->file_table->files[func_ind].filename);
}

// XXX No bounds check
struct AddressInfo* get_gsym_function_info(SymMap* sm, long ind) {
    void* base = sm->base;

    uint32_t info_off = sm->addr_info_table[ind];
    dprintf("Info offset 0x%x\n", info_off);

    struct AddressInfo* info_ptr = base + info_off;
    dprintf("info @ %p (l=0x%x,n=0x%x)\n", info_ptr, info_ptr->size, info_ptr->name);
    return info_ptr;
}

typedef struct SymbolInfo {
    uint64_t addr;
    char* func_name;
    uint64_t func_addr;
    uint32_t func_size;
    char* file;
    uint32_t line_num;
} SymbolInfo;



uint16_t find_addr_in_line_table(uint16_t* table, size_t off) {
    while(1) {
        uint16_t v = table[off];
        dprintf("flt %lx: %hu\n", off, v);
        if (v != 0)
            return v;
        if (off == 0)
            return 0;
        off --;
    };
}

void find_line_number(SymbolInfo* out, struct AddressLine* line_info, size_t addr_off) {
    uint16_t addr = 0;
    uint16_t line = 0;

    uint64_t func_addr = out->func_addr;

    uint16_t func_size = out->func_size;
    uint16_t line_table[func_size];
    memset(line_table, 0, func_size*sizeof(uint16_t));

    dprintf("Finding line number for off %lx (size %x)\n", addr_off, func_size);

    uint32_t line_size = line_info->length;
    uint8_t* line_data = (uint8_t*)(line_info+1);

    uint32_t pc = 0;
    int16_t min = 0;
    int16_t max = 0;
    pc += sleb128_16(&line_data[pc], &min);
    pc += sleb128_16(&line_data[pc], &max);
    pc += uleb128_16(&line_data[pc], &line);

    uint16_t line_range = max - min + 1;
    dprintf("min = %hd, max=%hd, line=%hu\n", min, max, line);
	dprintf("line_table @ %p\n", line_table);

    while (pc < line_size) {
        uint8_t op = line_data[pc];
        dprintf("OPCODE %x\n", op);
        pc += handle_line_op(&line_data[pc], min, line_range, &addr, &line);
        dprintf("addr=%x line=%u\n", addr, line);

        // "Push" a line to the table
        if (op == 2 || op >= 4) {
            dprintf("line_table[%x] (%lx) = %hx\n", addr, addr+func_addr, line);
            line_table[addr] = line;
        }
		dpause();
    }

    out->line_num = find_addr_in_line_table(line_table, addr_off);
    dprintf("Line num = %u\n", out->line_num);
}

// XXX No bounds check
int find_symbol_in_gsym_map(SymMap* sm, uint64_t addr, SymbolInfo* out) {
    void* base = sm->base;

    dprintf("base @ %p\n", base);

    uint64_t func_addr = 0;
    long addr_ind = get_addr_index(sm, addr, &func_addr);
    dprintf("0x%lx is at index %ld (%lx)\n", addr, addr_ind, func_addr);
    if (addr_ind < 0) {
        dprintf("Address 0x%lx is not in gsym\n", addr);
        return 0;
    }

    struct AddressInfo* func_info = get_gsym_function_info(sm, addr_ind);
    dprintf("function info @ %p\n", func_info);
    char* func_name = get_gsym_string(sm, func_info->name);
    dprintf("function info name `%s`\n", func_name);
	dprintf("function size = %x\n", func_info->size);

    out->addr = addr;
    out->func_name = func_name;
    out->func_addr = func_addr;
    out->func_size = func_info->size;
    out->file = NULL;
    out->line_num = 0;

    if (func_info->data[0].type == 1) {
        dprintf("Finding line number for 0x%lx inside func 0x%lx\n", addr, func_addr);
        find_line_number(out, func_info->data, addr - func_addr);

    }

    if (out->line_num != 0) {
        out->file = get_gsym_function_name(sm, 1);
    }

    return 1;
}

int get_symbol_in_mapping(Mapping* m, uint64_t addr, SymbolInfo* out) {
    if (!m || !m->module_name) {
        dprintf("Failed to find module for address 0x%lx", addr);
        return 0;
    }
    dprintf("-- Looking for 0x%lx in %s\n", addr, m->module_name);

    if (!m->sym_map) {
        char* path = file_exists(m->module_name);

        if (!path) {
            dprintf("-- Module `%s`, file does not exist for 0x%lx\n", m->module_name, addr);
            return 0;
        }
        m->module_name = path;
        SymMap* map = load_map(path);
        m->sym_map = map;
    }
    if (!m->sym_map) {
        dprintf("-- Failed to load gsym map for %s\n", m->module_name);
        return 0;
    }
    if (m->sym_map->last_pid != m->pid && !validate_sym_map(m->sym_map)) {
        m->sym_map = NULL;
        // TODO free symmap?
        printf("Failed to validate gsym map for %s, ignoring\n", m->module_name);
        return 0;
    }
    m->sym_map->last_pid = m->pid;

    size_t maddr = addr - m->base_addr;

    find_symbol_in_gsym_map(m->sym_map, maddr, out);
    return 1;
}

void print_trace_line(FILE* crash_file, size_t ind, Mapping* m, uint64_t addr) {
    SymbolInfo symbol = {0};

    int sym_found = get_symbol_in_mapping(m, addr, &symbol);
    if (!sym_found || !symbol.func_name) {
        if (m == NULL || m->module_name == NULL) {
            crprintf("#%zu 0x%016lx in ???\n", ind, addr);
            return;
        }
        uint32_t diff = addr - m->base_addr;
        crprintf("#%zu 0x%016lx at %s+0x%x\n",
            ind, addr, m->module_name, diff);
        return;
    }
    if (symbol.file != NULL) {
        crprintf("#%zu 0x%016lx at %s()+0x%lx in %s:%u\n", ind, addr,
            symbol.func_name, symbol.addr - symbol.func_addr,
            symbol.file, symbol.line_num
        );
        return;
    }
    crprintf("#%zu 0x%016lx at %s()+0x%lx\n", ind, addr,
            symbol.func_name, symbol.addr - symbol.func_addr);
}

#define offsetof(a, b) __builtin_offsetof(a,b)
#define reg_off(name) (offsetof(struct user, regs.name))


uint64_t read_child_u64(uint32_t child, uint64_t addr) {
    uint64_t data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
    return data;
}

void read_child_memory(uint32_t child, uint64_t* dest, void* addr, size_t len) {
    for (int i=0; i<len/8; i++) {
        dest[i] = read_child_u64(child, (uint64_t)addr + i*8);
    }
}


void walk_stack(FILE* crash_file, uint32_t child, uint64_t rip, uint64_t rsp, uint64_t rbp) {
    uint64_t sp = rsp;
    if (find_module(rbp)) {
        sp = rbp;
    }

    size_t bt_ind = 0;

    printf("==== Crash Stack Trace ====\n");

    Mapping* rip_m = find_module(rip);
    if (rip_m && rip_m->is_x) {
        print_trace_line(crash_file, bt_ind, rip_m, rip);
        fflush(crash_file);
        fflush(stdout);
    }

    uint64_t next_rbp = 0;
    uint64_t prev_word = 0;

    uint64_t last_code_ptr = 0;
    uint32_t repeat_stacks = 0;


    size_t stack_tries = 0;
    while(1) {
        /*
        if (bt_ind > 25)
            break;
            */
        /*
        if (stack_tries++ > 10)
            break;
            */
        errno = 0;
        uint64_t val = read_child_u64(child, sp);
        //dprintf("0x%lx: %lx\n", sp, val);
        if (errno != 0) {
            break;
        }
        if (val == 0)
            goto next_stack;

        if (val == last_code_ptr) {
            repeat_stacks++;
            bt_ind++;
        } else {

            Mapping* m = find_module(val);

            if (m && (val >= sp/* || m->is_stack*/)) {
                next_rbp = val;
                //dprintf(" - Next Frame = %lx\n", next_rbp);
                goto next_stack;
            }

            if (m == NULL || m->is_x == 0) {
                prev_word = val;
                goto next_stack;
            }

            if (repeat_stacks != 0) {
                crprintf("'- Repeats %u times\n", repeat_stacks);
                repeat_stacks = 0;
            }

            uint64_t diff = val - m->base_addr;
            dprintf(" - Addr 0x%lx is in module %s [%lx] -> %lx\n",
                val, m->module_name, m->base_addr, diff);
            //dprintf(" -- %lx\n", prev_word);
            bt_ind++;

            print_trace_line(crash_file, bt_ind, m, val);
            fflush(crash_file);
            fflush(stdout);
            dpause();

            last_code_ptr = val;
            repeat_stacks = 0;
        }

        if (next_rbp != 0) {
            prev_word = 0;
            sp = next_rbp;
            next_rbp = 0;
            continue;
        }

        if (prev_word == 1) {
            break;
        }

next_stack:
        sp += 8;
    }
}

uint64_t get_child_reg(uint32_t child, size_t reg) {
    greg_t* regs = (void*)ptrace(PTRACE_PEEKUSER, child, reg_off(r9), NULL);
    if (regs == NULL || regs == (void*)-1) 
        return 0;
    return read_child_u64(child, (uint64_t)(regs + reg));
    //*/
    //return ptrace(PTRACE_PEEKUSER, child, reg, NULL);
}

typedef struct CrashMessage {
    uint32_t command;
    uint32_t pid;
} CrashMessage;

FILE* open_crash_file(uint32_t pid, char* mode) {
    char buf[MAX_PATH+32] = {0};
    char buf2[MAX_PATH+32] = {0};
    snprintf(buf, MAX_PATH, "/proc/%u/exe", pid);
    readlink(buf, buf2, MAX_PATH);

    char* bn = basename(buf2);

    snprintf(buf, MAX_PATH, "/tmp/%s.crash.txt", bn);
    dprintf("Creating crashfile `%s`\n", buf);
    FILE* f= fopen(buf, mode);
    assert(f);
    return f;
}

void write_abort_string(FILE* crash_file, uint32_t child, uint64_t addr, uint32_t len) {
    dassert(crash_file);
    if (len > 0x2000)
        len = 0x2000;
    char* abt_string = calloc(len,1);
    size_t data_len = round_to(len, 8);

    read_child_memory(child, (void*)abt_string, (void*)addr, data_len);
    dprintf("Read abort string `%s`\n", abt_string);
    fwrite(abt_string, len, 1, crash_file);
    fwrite(abt_string, len, 1, stdout);
    fwrite("\n", 1, 1, crash_file);
    fwrite("\n", 1, 1, stdout);
    fflush(crash_file);
    fflush(stdout);
}

void handle_crash(CrashMessage cm) {
    FILE* crash_file = NULL;

    uint32_t child = cm.pid;

    dprintf("Attaching to %u\n", child);
    uint64_t res = ptrace(PTRACE_ATTACH, child, NULL, NULL);
    dprintf("Attach result = %lx\n", res);
    ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_EXITKILL, NULL);
    wait(NULL);

    dprintf("Child has exited or crashed\n");
    
    dpause();

    uint64_t _r9 = ptrace(PTRACE_PEEKUSER, child, reg_off(r9), NULL);
    dprintf("r9 = %lx\n", _r9);
    if (_r9 == 0 || _r9 == -1) {
        dprintf("Failed to get stack pointer\n");
        return;
    }

    uint64_t _rip = get_child_reg(child, REG_RIP);//reg_off(rip));
    dprintf("Child rip = %lx\n", _rip);
    uint64_t _rsp = get_child_reg(child, REG_RSP);//reg_off(rsp));
    dprintf("Child rsp = %lx\n", _rsp);
    uint64_t _rbp = get_child_reg(child, REG_RBP);//reg_off(rbp));
    dprintf("Child rbp = %lx\n", _rbp);
    if (_rsp == 0 || _rsp == -1) {
        dprintf("Failed to get stack pointer\n");
        return;
    }


    crash_file = open_crash_file(child, "w+");
    if (cm.command == SIGABRT) {
        uint64_t _rdi = get_child_reg(child, REG_RDI);//reg_off(rbp));
        dprintf("Child rdi = %lx\n", _rdi);
        uint64_t _rsi = get_child_reg(child, REG_RSI);//reg_off(rbp));
        dprintf("Child rsi = %lx\n", _rsi);

        write_abort_string(crash_file, child, _rdi, _rsi);


    }

    get_maps(child);

    walk_stack(crash_file, child, _rip, _rsp, _rbp);
    fflush(crash_file);
    fflush(stdout);
    fclose(crash_file);
    kill(child, SIGKILL);


    dpause();


}


void message_handler(int message_fd) {

    while (1) {
        CrashMessage msg = { 0 };

        dprintf("Waiting for message...\n");
        int n = read(message_fd, &msg, sizeof(msg));
        if (n == 0) {
            dprintf("No more message\n");
            break;
        }
        dprintf("Got message pid=%u command=%u...\n", msg.pid, msg.command);

        uint64_t val = *(uint64_t*)(&msg);

        handle_crash(msg);
        break;
        /*
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, (void *(*)(void *))handle_crash, (void*)val);
        */
    }
}


void start_child(char* path, int* ipc) {
    pid_t child = fork();
    if (child == 0) {
        open_crash_file(getpid(), "w+");
        //unshare(CLONE_NEWUSER);
        //ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(path, path, NULL);
        abort();
    }
    dprintf("Child %d running...\n", child);
    /*
    uint64_t _r8 = ptrace(PTRACE_PEEKUSER, child, reg_off(r9), NULL);
    dprintf("Child reg @ %lx\n", _r8);
    if (_r8 == 0 || _r8 == -1) {
        dprintf("Failed to get stack pointer\n");
        return;
    }
    */

}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /*
    uint8_t* v = mmap(0x414140000, 0x1000, 7, MAP_FIXED|MAP_ANON|MAP_PRIVATE, -1,0);
    v[0] = 'A';
    v[1] = 'B';
    v[2] = 'C';
    */

    if (argc < 2) {
        puts("./airbag /abs/path/to/bin");
        return -1;

        //argv[1] = "/opt/dotcom_market";
    }

    chdir("/tmp/");

    int fd[2];
    pipe(fd);
    //printf("Got %u %u\n", fd[0], fd[1]);

    start_child(argv[1], fd);
#if DEBUG
#else
	close(0);
#endif

    message_handler(fd[0]);

    /*
    int fds[2];
    pipe(fds);
    printf("Got %u\n", fds[0]);
    char* ff = mmap(0, 0x1000, 7, MAP_SHARED, fds[0], 0);
    printf("%p\n", ff);

    ff[0] = 'D';


    getc(stdin);



    return 0;

    char* np = canonicalize_file_name("/foobar/../etc/passwd");
    printf("np = %s\n", np);



    //hello();
    //printf("Hello world %u\n", argc);
    int fd = memfd_create("foobar/../childa", 0);
    printf("fd = %u\n", fd);
    write(fd, "AAAAAAAAAAAAAAAAAAA", 10);
    void* f = mmap(0, 0x1000, 7, MAP_PRIVATE, fd, 0);
    printf("%p\n", f);

    int fd2 = open("/dev/pts/1",0);
    printf("fd %u\n", fd2);
    void* f2 = mmap(0, 0x1000, 7, MAP_PRIVATE, fd2, 0);
    printf("2 %p\n", f2);
    //char buf[1000] = {0};
    //
    get_address_symbol(getpid(), f);

    getc(stdin);

    write(fd, "CCCCCCCCCCCCC", 10);

    getc(stdin);
    
    //realpath("/memfd:foobar/../etc/passwd", buf);
    //printf("%s\n", buf);
    */
}


