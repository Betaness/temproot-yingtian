/*
 * slideprobe - recover the kernel text address of a blocked call site.
 *
 * sched_blocked_reason stores `void *caller` at offset 16 of its payload
 * (event id 109). The text form prints it with %pS (symbol only); the raw
 * ring-buffer record keeps the real pointer. Read-only: it enables one
 * existing tracepoint, blocks once, and reads the per-cpu raw stream.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define KVA 0xffff000000000000ULL

static int write_str(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, val, strlen(val));
    close(fd);
    return n > 0 ? 0 : -1;
}

static int g_pipe[2];

static void *blocker(void *arg)
{
    char c;
    (void)arg;
    /* blocks in pipe_read -> sched_blocked_reason with caller in the kernel */
    if (read(g_pipe[0], &c, 1) < 0) { /* interrupted: fine */ }
    return NULL;
}

int main(void)
{
    int fds[16], nfds = 0, i;
    unsigned char buf[1 << 16];
    unsigned char *all = malloc(1 << 22);
    size_t total = 0;
    pthread_t th;

    if (!all) return 1;

    printf("event id for sched_blocked_reason: ");
    {
        char p[128], b[16] = {0};
        int fd;
        snprintf(p, sizeof(p), T "/events/sched/sched_blocked_reason/id");
        fd = open(p, O_RDONLY);
        if (fd >= 0) { ssize_t n = read(fd, b, sizeof(b) - 1); close(fd); if (n > 0) printf("%s", b); }
        else printf("(unreadable)");
        printf("\n");
    }

    write_str(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
    if (write_str(T "/events/sched/sched_blocked_reason/enable", "1\n") != 0) {
        printf("enable failed: %s\n", strerror(errno));
        return 2;
    }
    printf("sched_blocked_reason enabled\n");
    write_str(T "/tracing_on", "1\n");

    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        fds[nfds] = open(p, O_RDONLY | O_NONBLOCK);
        if (fds[nfds] < 0) break;
        nfds++;
    }
    printf("opened %d raw pipes\n", nfds);

    if (pipe(g_pipe) != 0) return 2;
    for (i = 0; i < 8; i++) {
        pthread_create(&th, NULL, blocker, NULL);
        pthread_detach(th);
    }

    {
        int rounds;
        for (rounds = 0; rounds < 80; rounds++) {
            struct pollfd pfd[16];
            for (i = 0; i < nfds; i++) { pfd[i].fd = fds[i]; pfd[i].events = POLLIN; }
            if (poll(pfd, nfds, 40) <= 0) continue;
            for (i = 0; i < nfds; i++) {
                if (pfd[i].revents & POLLIN) {
                    ssize_t n = read(fds[i], buf, sizeof(buf));
                    if (n > 0 && total + (size_t)n < (1u << 22)) {
                        memcpy(all + total, buf, (size_t)n);
                        total += (size_t)n;
                    }
                }
            }
        }
    }

    write_str(T "/tracing_on", "0\n");
    for (i = 0; i < nfds; i++) close(fds[i]);
    printf("captured %zu raw bytes\n", total);

    /* Print kernel-text-range 8-byte values, 4-byte aligned scan. */
    {
        size_t o;
        int shown = 0;
        for (o = 0; o + 8 <= total && shown < 10; o += 4) {
            uint64_t v;
            memcpy(&v, all + o, 8);
            if (v >= 0xffffff8000000000ULL && v < 0xfffffffec0000000ULL) {
                printf("  cand off=%-6zu 0x%016llx\n", o, (unsigned long long)v);
                shown++;
            }
        }
        if (!shown) printf("  no kernel-text addresses in the stream\n");
    }
    return 0;
}
