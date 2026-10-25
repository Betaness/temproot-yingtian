/*
 * queuetest - is a SIGEV_SIGNAL CLOCK_THREAD_CPUTIME_ID timer actually queued?
 *
 * Evidence gathered:
 *   - does the signal fire (expiry processed)?
 *   - does /proc/self/timers list the timer (it is in the timer list)?
 *   - does a SIGEV_NONE timer behave differently?
 * Entirely inside our own process; no kernel state is modified.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

static volatile int g_fired;

static void on_sig(int s) { (void)s; g_fired++; }

static int count_proc_timers(void)
{
    char buf[8192];
    int fd = open("/proc/self/timers", O_RDONLY);
    ssize_t n;
    int count = 0;
    char *p;

    if (fd < 0) return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    for (p = buf; *p; p++) if (*p == '\n' && p[1] && p[1] != ' ') count++;
    return count;
}

static void burn_ms(int ms)
{
    struct timespec a, b;
    volatile unsigned long x = 0;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (;;) {
        int i;
        for (i = 0; i < 20000; i++) x += i;
        clock_gettime(CLOCK_MONOTONIC, &b);
        if ((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 >= ms) break;
    }
    (void)x;
}

static int run_case(const char *tag, int notify)
{
    timer_t t[4];
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;
    int i, armed = 0, before, after;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGRTMIN, &sa, NULL);
    g_fired = 0;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = notify;
    sev.sigev_signo = SIGRTMIN;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1000000L;    /* 1 ms of thread CPU time */
    its.it_interval.tv_nsec = 1000000L;

    before = count_proc_timers();
    for (i = 0; i < 4; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t[i]) != 0) break;
        if (timer_settime(t[i], 0, &its, NULL) != 0) break;
        armed++;
    }
    after = count_proc_timers();
    burn_ms(12);                        /* push the thread clock past expiry */
    printf("%-12s armed=%d  proc_timers %d->%d  signals_fired=%d\n",
           tag, armed, before, after, g_fired);
    for (i = 0; i < armed; i++) timer_delete(t[i]);
    return armed;
}

int main(void)
{
    printf("uid=%d\n", (int)getuid());
    run_case("SIGEV_SIGNAL", SIGEV_SIGNAL);
    run_case("SIGEV_NONE", SIGEV_NONE);
    return 0;
}
