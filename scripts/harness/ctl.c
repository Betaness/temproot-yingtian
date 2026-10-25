/* ctl - control: does a SIGEV_THREAD_ID timer signal actually land in the
 * target thread's private pending queue on this kernel? Leader stays ALIVE. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#ifndef SIGEV_THREAD_ID
#define SIGEV_THREAD_ID 4
#endif
static pid_t g_leader; static int g_sig;
static int kt_create(pid_t tid,int tag){struct sigevent s;int id=-1;memset(&s,0,sizeof(s));
 s.sigev_notify=SIGEV_SIGNAL|SIGEV_THREAD_ID;s.sigev_signo=g_sig;s.sigev_value.sival_int=tag;s._sigev_un._tid=(int)tid;
 if(syscall(SYS_timer_create,CLOCK_MONOTONIC,&s,&id))return -1;return id;}
static int kt_arm(int id,int64_t ns){struct itimerspec it;memset(&it,0,sizeof(it));
 it.it_value.tv_sec=ns/1000000000LL;it.it_value.tv_nsec=ns%1000000000LL;return syscall(SYS_timer_settime,id,TIMER_ABSTIME,&it,NULL);}
static void *w(void *u){ int made=0; (void)u; usleep(20000);
 for(int i=0;i<20000;i++){int id=kt_create(g_leader,0x28000000|(i&0xffffff)); if(id<0)break; if(kt_arm(id,1))break; made++;}
 dprintf(2,"[worker] made=%d\n",made);
 write(1,&made,sizeof(made));
 for(;;)pause(); }
struct pa{uint64_t off;uint32_t flags;int32_t nr;};
int main(void){
 g_sig=SIGRTMIN+2; sigset_t b; sigemptyset(&b); sigaddset(&b,g_sig); sigprocmask(SIG_BLOCK,&b,NULL);
 pid_t c=fork(); int st=0;
 if(c==0){ pthread_t th; g_leader=(pid_t)syscall(SYS_gettid);
   if(pthread_create(&th,NULL,w,NULL))_exit(3); for(;;)pause(); }
 usleep(400000);
 int si=0,tag=0;
 if(ptrace(PTRACE_ATTACH,c,0,0)==0){ waitpid(c,&st,0);
   for(int off=0;off<4096;off++){ struct pa a={(uint64_t)off,0,1}; siginfo_t i2; memset(&i2,0,sizeof(i2));
     if(syscall(SYS_ptrace,PTRACE_PEEKSIGINFO,c,&a,&i2)!=1)break;
     if(i2.si_code==SI_TIMER){si++; if(((unsigned)i2.si_value.sival_int>>24)==0x28)tag++;} }
   ptrace(PTRACE_DETACH,c,0,0);
   printf("control(live leader): SI_TIMER=%d tagged=%d\n",si,tag);
 } else printf("attach failed errno=%d\n",errno);
 kill(c,SIGKILL); waitpid(c,&st,0); return 0; }
