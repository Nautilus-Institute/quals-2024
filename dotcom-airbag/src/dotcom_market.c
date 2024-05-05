#define __USE_GNU
#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
//#include <linux/seccomp.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <fenv.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include "seccomp-bpf.h"

typedef struct CrashMessage {
    uint32_t command;
    uint32_t pid;
} CrashMessage;

char* find_abort_string(uint64_t rsp){
    char format[32] = {0};
    uint64_t* p = rsp;

    for (int i = 0; i < 500; i++) {
        //printf("Checking %p %s\n", p, p);
        if (*p == *(uint64_t*)("(): Assertion")) {
            //printf("====== Found assertion: %s\n", p);
            strcpy(format, p);
            char* r = strdup(format);
            // move p into rsi
            asm volatile("mov %0, %%rsi;\n\t"
                    :
                    : "r"(p)
                    :);
            // move format into rdi
            asm volatile("mov %0, %%rdi;\n\t"
                    :
                    : "r"(format+32)
                    :);
            return r;
            break;
        }
        p++;
    }
    return NULL;
}

int isNaN(double d) {
    return isnan(d);
}

volatile char DO_FIND_ABORT_STRING = 1;

void crash_handler(int sn, siginfo_t* si, void* ctx) {
    char buf[128] = {0};
    puts("DOTCOM Bubble detected, market crash imminent... reporting to shareholders and necessary regulatory authorities...");
    //printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! IN CRASH HANDLER %u\n", sn);
    ucontext_t* uctx= (ucontext_t *)ctx;
    //printf("~~~~~~~~~~~~~~~~~Signal %d\n", sn);
    //printf("~~~~~~~~~~~~~uctx @ %p\n", uctx);
    //printf("~~~~~~~~~~~uctx->uc_mcontext @ %p\n", uctx->uc_mcontext);



    uint64_t rip = uctx->uc_mcontext.gregs[REG_RIP];
    //printf("rip @ %p\n", rip);
    //printf("rip @ %p\n", rip);
    uint64_t rsp = uctx->uc_mcontext.gregs[REG_RSP];
    //printf("rsp @ %p\n", rsp);
    void* regs = uctx->uc_mcontext.gregs;
    //printf("reg @ %p\n", regs);


    CrashMessage msg = {
        sn,
        getpid()
    };
    //puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ After getpid");

    char* abort_s = NULL;
    if (DO_FIND_ABORT_STRING)  {
        abort_s = find_abort_string(rsp);
    }
    DO_FIND_ABORT_STRING = 0;
    if (abort_s != NULL || sn == SIGABRT) {
        if (abort_s == NULL) {
            asm volatile("mov %%r14, %0;\n\t"
                    : "=r"(abort_s)
                    :
                    :);
        }
        /*
        char* abort_s = NULL;
        */
        //printf("Storing abort message `%s` in RDI and RSI\n", abort_s);
        uctx->uc_mcontext.gregs[REG_RDI] = abort_s;
        uctx->uc_mcontext.gregs[REG_RSI] = strlen(abort_s);
    }

    //puts("~~~~~~~~~~~~~~~~~~~~~~~About to write to pipe (fd 4)");
    asm volatile("mov %0, %%r9;\n\t"
            :
            : "r"(regs)
            :);

    // Send crash notifiaction
    write(4, &msg, sizeof(msg));
    //while(1){}
    sleep(100000000000000000);
    sleep(100000000000000000);
    sleep(100000000000000000);
    sleep(100000000000000000);
    asm volatile("int3");
    asm volatile("hlt");
}

size_t get_ulong() {
    char buf[505] = {0};
    fgets(buf, 500, stdin);
    if (strlen(buf) == 0) {
        fgets(buf, 500, stdin);
    }
    if (buf[0] == '\n') {
        fgets(buf, 500, stdin);
    }

    return strtoul(buf, NULL, 10);
}

void install_crash_handler(int i) {
  struct sigaction action;
  action.sa_sigaction = &crash_handler;
  action.sa_flags = SA_SIGINFO;
  sigaction(i,&action,NULL);
}

void crash() {
    char* a = 0;
    *a = 0;
}

int set_permissions() {

    struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
		ALLOW_SYSCALL(sigreturn),
#endif
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(msync),
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(memfd_create),
        ALLOW_SYSCALL(mremap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(readv),
        ALLOW_SYSCALL(writev),
        ALLOW_SYSCALL(pipe),
        ALLOW_SYSCALL(select),
        ALLOW_SYSCALL(dup),
        ALLOW_SYSCALL(dup2),
        ALLOW_SYSCALL(nanosleep),
        ALLOW_SYSCALL(alarm),
        ALLOW_SYSCALL(getpid),
        ALLOW_SYSCALL(gettid),
        ALLOW_SYSCALL(sendfile),
        ALLOW_SYSCALL(fork),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(mkdir),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(clock_nanosleep),
        ALLOW_SYSCALL(mkdirat),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(newfstatat),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(getrandom),
        ALLOW_SYSCALL(tgkill),
		KILL_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;
    failed:
    if (errno == EINVAL)
        fprintf(stderr, "SECCOMP_FILTER is not available.\n");
    exit(0);
    abort();
    return 1;
    /*
    //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);


    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);

    seccomp_load(ctx);
    seccomp_release(ctx);
    */
}

typedef struct market_model {
    double supply;
    double demand;
    double income;
    double employment;
    double confidence;
    double computed_rate;
    char notes[];
} market_model;

volatile double intercept = 0.00;
volatile double supply_coefficient = -0.05;
volatile double demand_coefficient = 0.1;
volatile double income_coefficient = 0.02;
volatile double employment_coefficient = 0.03;
volatile double confidence_coefficient = 0.04;

double run_model(market_model* m) {
    double growth_rate = intercept + supply_coefficient * m->supply + demand_coefficient * m->demand + income_coefficient * m->income + employment_coefficient * m->employment + confidence_coefficient * m->confidence;
    return growth_rate;
}


const size_t max_models = 32;

market_model* model_list[max_models];

market_model* load_model(char* blob, size_t length) {
    double values[5] = { 0.0 };
    size_t ind = 0;

    char* end = blob + length;
    char* p = blob;
    while (p < end) {
        //printf("Checking -> `%s`\n", p);
        uint64_t val = strtoul(p, &p, 10);
        //printf("P is now -> `%s`\n", p);
        if (*p != '|') {
            puts("Error! Invalid model format, expected values separated by `|`");
        }
        assert(*p == '|');
        p++;

        values[ind++] = *(double*)&val;
        if (ind >= 5) {
            break;
        }
    }
    // NOTE
    size_t note_len = end - p;

    market_model* m = (market_model*)malloc(sizeof(market_model) + note_len + 1);
    char has_any = 0;
    if (!isNaN(values[0])) {
        has_any = 1;
        m->supply = values[0];
    }
    if (!isNaN(values[1])) {
        has_any = 1;
        m->demand = values[1];
    }
    if (!isNaN(values[2])) {
        has_any = 1;
        m->income = values[2] * 64.0;
    }
    if (!isNaN(values[3])) {
        has_any = 1;
        m->employment = values[3] * 64.0;
    }
    if (!isNaN(values[4])) {
        has_any = 1;
        m->confidence = values[4] * 64.0;
    }
    if (!has_any) {
        puts("Error! Invalid model format, all values are NAN");
        abort();
    }

    memcpy(m->notes, p, note_len);
    m->notes[note_len] = 0;
    //printf("notes: `%s`\n", m->notes);


    for (size_t i = 0; i < max_models; i++) {
        if (!model_list[i]) {
            model_list[i] = m;
            printf("Loaded model #%02lu... \033[30;40m@%p\033[0m\n", i, m);
            break;
        }
    }
    return m;
}

market_model* import_model() {
    printf("[ IMPORT MARKET MODEL ]\n");
    printf("Paste model export text below:\n");
    printf(",-------------------------------------\n");
    printf("| ");
    fflush(stdout);

    char length_buf[100] = {0};
    for (int32_t i=0; i<32; i++) {
        length_buf[i] = getchar();

        if (length_buf[i] == '\n') {
            i--;
            continue;
        }

        if (length_buf[i] == '|') {
            length_buf[i] = 0;
            break;
        }
    }

    size_t length = strtoul(length_buf, NULL, 10);
    assert(length <= 0x500 && length > 10);

    char blob[length];
    size_t off = 0;
    while(off < length) {
        size_t r = fread(blob + off, 1, length, stdin);
        off += r;
    }
    printf("`-------------------------------------\n");

    return load_model(blob, length);
}


char* GRAPH_CHARS = "@+O-X0*#";

void draw_title() {
    puts("  __  __            _        _     ____            _           _   _                "); 
    puts(" |  \\/  | __ _ _ __| | _____| |_  |  _ \\ _ __ ___ (_) ___  ___| |_(_) ___  _ __  ___ ");
    puts(" | |\\/| |/ _` | '__| |/ / _ \\ __| | |_) | '__/ _ \\| |/ _ \\/ __| __| |/ _ \\| '_ \\/ __|");
    puts(" | |  | | (_| | |  |   <  __/ |_  |  __/| | | (_) | |  __/ (__| |_| | (_) | | | \\__ \\");
    puts(" |_|  |_|\\__,_|_|  |_|\\_\\___|\\__| |_|   |_|  \\___// |\\___|\\___|\\__|_|\\___/|_| |_|___/");
    puts("                                                |__/                                 ");

}

void draw_graph(market_model** models, char* desc) {
    const size_t x_min = 0;
    const size_t x_max = 100;
    const graph_lines = 50;
    double y_min = 0;
    double y_max = 0;

    draw_title();

    printf("\n\n%s\n", desc);

    printf("\n\n,-----------------------------------------,\n");
    printf("| LEGEND                                  |\n");



    for (size_t i=0; i<max_models; i++) {
        market_model* m = models[i];
        if (!m) {
            continue;
        }
        double r = run_model(m);
        m->computed_rate = r;
        double mr = r * ((double)x_max);
        if (mr < y_min) {
            y_min = mr;
        }
        if (mr > y_max) {
            y_max = mr;
        }

        char gc = GRAPH_CHARS[i % strlen(GRAPH_CHARS)];
        printf("| %c  <->  Model #%02u                       |\n",gc, i+1);
        
        printf("|         r = %.20e  |\n", m->computed_rate);
    }
    printf("|                                         |\n");
    printf("`-----------------------------------------'\n\n\n");


    double y_range = y_max - y_min;
    // find per line step
    double y_step = y_range / graph_lines;

    printf("y=%e\n", y_max);
    // draw each line
    for (size_t l_i = graph_lines; l_i > 0; l_i--) {
        printf("| ");
        double l = l_i;
        double y_end = y_min + y_step * (l + .01);
        double y_start = y_end - y_step*1.02;
        //printf("Looking for range %e to %e\n", y_start, y_end);

        for (size_t x_i = x_min; x_i < x_max; x_i++) {
            double x = x_i;
            char found = 0;

            for (size_t m_i = 0; m_i < max_models; m_i++) {
                market_model* m = models[m_i];
                if (!m) {
                    continue;
                }
                double r = m->computed_rate;
                double y = r * x;
                //printf("  %u -> %e\n", x_i, y);
                // Check if that is in the current line
                if (y >= y_start && y < y_end) {
                    // Draw a point
                    printf("%c", GRAPH_CHARS[m_i % strlen(GRAPH_CHARS)]);
                    found = 1;
                    break;
                }
            }
            if (found) {
                continue;
            }
            printf(" ");
        }
        if (l_i == 1) {
            printf(" | x=%u\n", x_max);
        } else {
            printf(" |\n");
        }
    }
    printf("y=%e\n", y_min);
}

void trash_model() {
    puts("Select model to TRASH:");
    for (size_t i=0; i<max_models; i++) {
        market_model* m = model_list[i];
        if (!m) {
            continue;
        }
        printf("  %02u) Model #%02u\n", i+1, i);
    }
    printf("   0) Cancel\n");
    printf("> ");
    fflush(stdout);

    size_t r = get_ulong();
    if (r == 0) {
        return;
    }
    if (r > max_models) {
        puts("Invalid model number");
        return;
    }
    market_model* m = model_list[r-1];
    if (!m) {
        puts("Invalid model number");
        return;
    }

    printf("Trashing model\n");
    free(m);
    model_list[r-1] = NULL;
}

size_t select_models(market_model** selected) {
    puts("Select new model to compare:");
    printf("   0) Import New Model\n");
    for (size_t i=0; i<max_models; i++) {
        market_model* m = model_list[i];
        if (!m) {
            continue;
        }
        printf("  % 2u) Model #%02u\n", i+1, i+1, m);
    }
    printf("  66) Trash Existing Model\n");
    printf("> ");
    fflush(stdout);

    size_t r = get_ulong();
    if (r == 0) {
        import_model();
        return select_models(selected);
    }
    if (r == 66) {
        trash_model();
        return select_models(selected);
    }

    if (r > max_models) {
        puts("Invalid model number");
        return select_models(selected);
    }
    market_model* mm = model_list[r-1];
    if (!mm) {
        puts("Invalid model number");
        return select_models(selected);
    }

    selected[r-1] = mm;

    return 1;
}


void compare_models(char* desc) {
    market_model* selected[max_models] = {0};
    size_t selected_count = 0;

    while (1) {
        if (selected_count == 0) {
            puts("No models selected, press enter to go to model selection");
        }
        selected_count += select_models(selected);
        if (selected_count == 0) {
            continue;
        }
        draw_graph(selected, desc);

        while (1) {
            puts("Options:\n 1) Add new models to graph\n 2) Exit\n");
            printf("> ");
            fflush(stdout);
            size_t r = get_ulong();
            if (r == 1) {
                break;
            }
            if (r == 2 || r == 0) {
                exit(0);
            }
        }
    }
}




void create_new_graph() {
    char description[220] = {0};
    draw_title();
    printf("\n\nInitializing DOTCOM market graph....\n");
    printf("\n Enter graph description:\n");
    printf(",-------------------------------------\n");
    printf("| ");
    fflush(stdout);
    fgets(description, 200, stdin);
    printf("`-------------------------------------\n");

    compare_models(description);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    feenableexcept(FE_DIVBYZERO | FE_OVERFLOW | FE_INVALID);

    install_crash_handler(SIGSEGV);
    install_crash_handler(SIGABRT);
    install_crash_handler(SIGTRAP);
    install_crash_handler(SIGFPE);
    install_crash_handler(SIGILL);
    install_crash_handler(SIGBUS);
    install_crash_handler(SIGINT);

    open("/flag1.txt", O_RDONLY, 0);

    set_permissions();

    //wtf();
    create_new_graph();
    exit(0);

    /*

    puts("Enter a number:");
    size_t i = get_ulong();
    //size_t i = 1;
    i = 100/i;
    assert(i != 1 );
    if (i == 10) {
        char* v = NULL;
        *v = 0;
    }

    void* foo = mmap(0, 0x1000, 7, MAP_PRIVATE|MAP_ANON, -1, 0);
    puts("Enter shellcode:");
    int n = read(0, foo, 0x1000);
    //printf("Read %u bytes\n", n);
    //close(fd);
    void(*fp)(void) = (void (*)(void))foo;
    fp();
    exit(0);
    */
}

