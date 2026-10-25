/*
 * trprobe - standalone POSIX-CPU-timer / exec cleanup-order measurement.
 *
 * Non-destructive by construction: it only creates and deletes ITS OWN process
 * timers and attempts an exec that is expected to fail. It never writes kernel
 * memory, never loads a module, never touches a partition.
 *
 * Build (static, so it runs on Android bionic without glibc):
 *   gcc -O2 -static -pthread -o trprobe trprobe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <pthread.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/utsname.h>

#ifndef HWCAP2_MTE
#define HWCAP2_MTE (1UL << 18)
#endif

#define N_TIMERS 4
#define MAX_ROUNDS 32

struct rec {
    int strategy;
    int armed;
    int exec_errno;
    int del_ok;
    int del_einval;
    int del_other;
    int listed;
    int signaled;
    int sig;
    long ms;
};

static volatile int g_stop;

static void *spin(void *arg)
{
    (void)arg;
    while (!g_stop) {
        sched_yield();
    }
    return NULL;
}

static int count_timers(void)
{
    char buf[8192];
    ssize_t n;
    int fd = open("/proc/self/timers", O_RDONLY);
    int count = 0;
    char *p;

    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    for (p = buf; *p != '\0'; p++) {
        if (*p == '\n' && p[1] != '\0' && p[1] != ' ') {
            count++;
        }
    }
    return count;
}

static void child(int strategy, int wfd)
{
    struct rec res;
    timer_t timers[N_TIMERS];
    struct sigevent sev;
    struct itimerspec its;
    struct timespec ts, te;
    int i, err = 0;

    memset(&res, 0, sizeof(res));
    res.strategy = strategy;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1000000L;
    its.it_interval.tv_nsec = 1000000L;

    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &timers[i]) != 0) {
            break;
        }
        if (timer_settime(timers[i], 0, &its, NULL) != 0) {
            break;
        }
        res.armed++;
    }

    if (strategy == 1) {
        /* Fails in the executable lookup, before begin_new_exec(). */
        char *argv[] = { (char *)"/system/bin/__tr_missing_binary__", NULL };
        execve(argv[0], argv, NULL);
        err = errno;
    } else if (strategy == 3) {
        /* Control for strategy 2: identical construction without the pending
         * signal. If this one execs successfully (prints EXEC_SUCCEEDED), then a
         * death inside execve for strategy 2 is caused by the pending signal,
         * i.e. de_thread() aborted. */
        pthread_t sib[16];
        int n = 0;

        for (i = 0; i < 16; i++) {
            if (pthread_create(&sib[i], NULL, spin, NULL) != 0) {
                break;
            }
            n++;
        }
        if (n > 0) {
            char *argv[] = { (char *)"/system/bin/sh", (char *)"-c",
                             (char *)"echo EXEC_SUCCEEDED_STRATEGY3", NULL };
            execve(argv[0], argv, NULL);
            err = errno;
            g_stop = 1;
            for (i = 0; i < n; i++) {
                pthread_join(sib[i], NULL);
            }
        } else {
            err = -1000;
        }
    } else if (strategy == 2) {
        /* A sibling thread plus a blocked pending signal makes de_thread()
         * return -ERESTARTNOINTR after the exec check block has run. The mask
         * must be installed before pthread_create, otherwise the sibling takes
         * the process-directed signal and the default action kills us. */
        sigset_t blocked;
        pthread_t siblings[16];
        int spawned = 0;

        sigemptyset(&blocked);
        sigaddset(&blocked, SIGUSR1);
        sigprocmask(SIG_BLOCK, &blocked, NULL);
        for (i = 0; i < 16; i++) {
            if (pthread_create(&siblings[i], NULL, spin, NULL) != 0) {
                break;
            }
            spawned++;
        }
        if (spawned > 0) {
            raise(SIGUSR1);
            {
                /* If the exec succeeds the process is replaced, so make the new
                 * image announce itself: seeing EXEC_SUCCEEDED proves de_thread
                 * did not abort and the measurement is not applicable. */
                char *argv[] = { (char *)"/system/bin/sh", (char *)"-c",
                                 (char *)"echo EXEC_SUCCEEDED", NULL };
                execve(argv[0], argv, NULL);
                err = errno;
            }
            g_stop = 1;
            for (i = 0; i < spawned; i++) {
                pthread_join(siblings[i], NULL);
            }
        } else {
            err = -1000;
        }
    }

    res.exec_errno = err;
    res.listed = count_timers();
    for (i = 0; i < res.armed; i++) {
        if (timer_delete(timers[i]) == 0) {
            res.del_ok++;
        } else if (errno == EINVAL) {
            res.del_einval++;
        } else {
            res.del_other++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &te);
    res.ms = (te.tv_sec - ts.tv_sec) * 1000L + (te.tv_nsec - ts.tv_nsec) / 1000000L;
    if (wfd >= 0) {
        ssize_t ignored = write(wfd, &res, sizeof(res));
        (void)ignored;
    }
    _exit(0);
}

static int run_one(int strategy, struct rec *out)
{
    int fds[2];
    pid_t pid;
    int status = 0;
    ssize_t got = -1;

    if (pipe(fds) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        child(strategy, fds[1]);
        _exit(0);
    }
    close(fds[1]);
    memset(out, 0, sizeof(*out));
    out->strategy = strategy;
    {
        fd_set set;
        struct timeval tv;

        FD_ZERO(&set);
        FD_SET(fds[0], &set);
        tv.tv_sec = 8;
        tv.tv_usec = 0;
        if (select(fds[0] + 1, &set, NULL, NULL, &tv) > 0) {
            got = read(fds[0], out, sizeof(*out));
        }
    }
    close(fds[0]);
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        out->signaled = 1;
        out->sig = WTERMSIG(status);
    }
    if (got != (ssize_t)sizeof(*out)) {
        /* No report: the child either exec'd successfully or was killed. */
        out->exec_errno = -4000;
        out->strategy = strategy;
    }
    return 0;
}

static void print_cmdline_facts(void)
{
    char buf[4096];
    int fd = open("/proc/cmdline", O_RDONLY);
    ssize_t n;
    const char *keys[] = { "kasan=off", "kasan=on", "kfence", "arm64.nomops", NULL };
    int i;

    if (fd < 0) {
        printf("cmdline: unreadable (%s)\n", strerror(errno));
        return;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        printf("cmdline: empty\n");
        return;
    }
    buf[n] = '\0';
    printf("cmdline facts: ");
    for (i = 0; keys[i] != NULL; i++) {
        if (strstr(buf, keys[i]) != NULL) {
            printf("[%s] ", keys[i]);
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    struct utsname u;
    int rounds = 8, r, i;
    struct rec acc[4];
    int signaled[4] = { 0, 0, 0, 0 };
    int last_errno[4] = { 0, 0, 0, 0 };
    const char *names[4] = { "control", "exec-missing", "exec+thread+pending-signal",
                             "exec+threads(no signal)" };

    if (argc > 1) {
        rounds = atoi(argv[1]);
    }
    if (rounds < 1) rounds = 1;
    if (rounds > MAX_ROUNDS) rounds = MAX_ROUNDS;

    memset(acc, 0, sizeof(acc));
    if (uname(&u) == 0) {
        printf("kernel: %s %s\n", u.sysname, u.release);
    }
    printf("uid=%d euid=%d pid=%d\n", (int)getuid(), (int)geteuid(), (int)getpid());
    printf("hwcap2 MTE: %s\n", (getauxval(AT_HWCAP2) & HWCAP2_MTE) ? "yes" : "no");
    print_cmdline_facts();
    printf("rounds: %d\n\n", rounds);

    for (r = 0; r < rounds; r++) {
        for (i = 0; i < 4; i++) {
            struct rec one;

            run_one(i, &one);
            acc[i].strategy = i;
            acc[i].armed += one.armed;
            acc[i].del_ok += one.del_ok;
            acc[i].del_einval += one.del_einval;
            acc[i].del_other += one.del_other;
            acc[i].listed = one.listed;
            acc[i].ms += one.ms;
            last_errno[i] = one.exec_errno;
            if (one.signaled) {
                signaled[i] = one.sig;
            }
        }
    }

    printf("%-32s %6s %6s %6s %6s %6s %6s\n",
           "strategy", "armed", "delOK", "EINVAL", "other", "list", "errno");
    for (i = 0; i < 4; i++) {
        printf("%-32s %6d %6d %6d %6d %6d %6d%s\n", names[i], acc[i].armed,
               acc[i].del_ok, acc[i].del_einval, acc[i].del_other, acc[i].listed,
               last_errno[i],
               signaled[i] ? " (killed by signal)" : "");
        if (signaled[i]) {
            printf("    last child died from signal %d\n", signaled[i]);
        }
    }

    printf("\nconclusion: ");
    if (acc[2].armed == 0) {
        printf("INCONCLUSIVE (strategy 2 could not arm any timer; errno=%d)\n",
               last_errno[2]);
    } else if (acc[2].del_einval > 0) {
        printf("PRE_FIX_ORDER (kernel removed the timers before the failed exec "
               "returned: %d of %d deletions reported EINVAL)\n",
               acc[2].del_einval, acc[2].armed);
    } else if (acc[2].del_ok >= acc[2].armed) {
        printf("POST_FIX_ORDER (all %d timers survived the failed exec)\n", acc[2].armed);
    } else {
        printf("INCONCLUSIVE (mixed: kept %d, cleared %d)\n",
               acc[2].del_ok, acc[2].del_einval);
    }
    return 0;
}
