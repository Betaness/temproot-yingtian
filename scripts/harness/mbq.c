#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>
int main(void){
    long r=syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
    printf("supported mask = 0x%lx\n", r);
    for(int b=0;b<16;b++) if(r&(1L<<b)) printf("  bit %d\n", b);
    errno=0; long q=syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,0,0);
    printf("register rseq-reg r=%ld errno=%d\n",q,errno);
    errno=0; q=syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,0,0);
    printf("register priv-exp r=%ld errno=%d\n",q,errno);
    return 0;
}
