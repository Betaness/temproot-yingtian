/* timers2 - arm POSIX CPU timers the way the published trigger requires:
 * SIGEV_SIGNAL (SIGRTMIN), NOT SIGEV_NONE: posix_cpu_timer_set skips
 * timerqueue_add when it_sigev_notify == SIGEV_NONE, so the node never queues. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

static void noop(int s) { (void)s; }

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 8;
    int i, ok = 0;
    timer_t t[64];
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = noop;
    sigaction(SIGRTMIN, &sa, NULL);

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_int = 0x41;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 500000L;
    its.it_interval.tv_nsec = 500000L;

    if (n > 64) n = 64;
    for (i = 0; i < n; i++) {
        t[i] = (timer_t)0;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t[i]) != 0) {
            printf("timer_create[%d] failed: %s\n", i, strerror(errno));
            break;
        }
        if (timer_settime(t[i], 0, &its, NULL) != 0) {
            printf("timer_settime[%d] failed: %s\n", i, strerror(errno));
            break;
        }
        ok++;
    }
    printf("armed %d timers with SIGEV_SIGNAL(SIGRTMIN)\n", ok);

    /* burn thread CPU so the thread clock advances and the timers fire */
    {
        volatile unsigned long x = 0;
        for (i = 0; i < 2000000; i++) x += i;
        (void)x;
    }
    usleep(150000);

    for (i = 0; i < ok; i++) timer_delete(t[i]);
    printf("deleted %d timers\n", ok);
    return ok > 0 ? 0 : 1;
}
