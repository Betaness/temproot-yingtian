/* touchmem - force anonymous page faults so rss_stat fires */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ size_t n=4u<<20; char *p=malloc(n); if(!p) return 1; memset(p,0x5a,n); printf("touched %zu bytes, sum=%d\n", n, p[0]+p[n-1]); free(p); return 0; }
