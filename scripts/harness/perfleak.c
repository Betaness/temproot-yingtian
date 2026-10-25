/*
 * perfleak - does perf_event_open leak kernel instruction pointers here?
 * Read-only: samples the CPU clock, looks for addresses in the kernel range.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <stdint.h>

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                     int group, unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group, flags);
}

static void ring_scan(void *base, size_t page, const char *tag)
{
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    unsigned char *data = (unsigned char *)base + page;
    size_t data_size = page * 8;
    uint64_t head = meta->data_head;
    uint64_t tail = meta->data_tail;
    int found = 0;

    __sync_synchronize();
    while (tail < head) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (tail % data_size));
        if (h->size < sizeof(*h) || h->size > data_size) {
            break;
        }
        if (h->type == PERF_RECORD_SAMPLE) {
            uint64_t ip = *(uint64_t *)((unsigned char *)h + sizeof(*h));
            if (ip >= 0xffff000000000000ULL) {
                printf("  [%s] LEAK: kernel IP = 0x%llx\n", tag, (unsigned long long)ip);
                found = 1;
            }
        }
        tail += h->size;
    }
    meta->data_tail = head;
    if (!found) {
        printf("  [%s] no kernel-range IP in this window\n", tag);
    }
}

static int try_type(const char *tag, uint32_t type, uint64_t config)
{
    struct perf_event_attr attr;
    int fd;
    void *base;
    long page = sysconf(_SC_PAGESIZE);
    char busy[1 << 20];

    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.sample_period = 1000;
    attr.sample_type = PERF_SAMPLE_IP;
    attr.disabled = 1;
    attr.exclude_kernel = 0;   /* we WANT kernel IPs */
    attr.exclude_hv = 1;
    attr.wakeup_events = 1;

    fd = perf_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("  [%s] perf_event_open denied: %s (errno=%d)\n", tag, strerror(errno), errno);
        return -1;
    }
    base = mmap(NULL, page * 9, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("  [%s] mmap failed: %s\n", tag, strerror(errno));
        close(fd);
        return -1;
    }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    memset(busy, 1, sizeof(busy));         /* burn some CPU so samples land */
    usleep(120000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    ring_scan(base, (size_t)page, tag);
    munmap(base, page * 9);
    close(fd);
    return 0;
}

int main(void)
{
    printf("uid=%d perf_event_paranoid test\n", (int)getuid());
    try_type("sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
    try_type("sw-task-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK);
    try_type("hw-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    try_type("sw-context-switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
    return 0;
}
