#include "tr_leak.h"

#include <ctype.h>

/* arm64 kernel virtual addresses live in the top canonical range. */
#define TR_KVA_LOW 0xffff000000000000ULL

static int sysctl_int(const char *path, int fallback)
{
    char buf[32];

    if (tr_read_line(path, buf, sizeof(buf)) <= 0) {
        return fallback;
    }
    return atoi(buf);
}

/* Scan a text blob for tokens that look like kernel pointers. */
static int scan_candidates(const char *blob, char *sample, size_t sample_cap)
{
    const char *p = blob;
    int found = 0;

    sample[0] = '\0';
    while (p != NULL && *p != '\0') {
        const char *tok = p;
        size_t len = 0;

        while (*tok != '\0' && !isxdigit((unsigned char)*tok)) {
            tok++;
        }
        if (*tok == '\0') {
            break;
        }
        while (isxdigit((unsigned char)tok[len])) {
            len++;
        }
        if (len >= 12 && len <= 16) {
            /* Parse with strtoull on a bounded copy. */
            char tmp[20];
            uint64_t value = 0;

            if (len < sizeof(tmp)) {
                memcpy(tmp, tok, len);
                tmp[len] = '\0';
                value = strtoull(tmp, NULL, 16);
                if (value >= TR_KVA_LOW) {
                    found++;
                    if (sample[0] == '\0') {
                        snprintf(sample, sample_cap, "0x%llx",
                                 (unsigned long long)value);
                    }
                }
            }
        }
        p = tok + len;
        while (*p != '\0' && !isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
    }
    return found;
}

static void probe_file(tr_leak *leak, const char *name, const char *path, size_t limit)
{
    tr_leak_item *it;
    char *buf;
    int fd;
    ssize_t n;

    if (leak->items >= TR_LEAK_MAX_ITEMS) {
        return;
    }
    it = &leak->item[leak->items++];
    memset(it, 0, sizeof(*it));
    snprintf(it->name, sizeof(it->name), "%s", name);

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        it->readable = 0;
        snprintf(it->sample, sizeof(it->sample), "denied: %s", strerror(errno));
        return;
    }
    buf = (char *)malloc(limit + 1);
    if (buf == NULL) {
        close(fd);
        it->readable = -1;
        snprintf(it->sample, sizeof(it->sample), "out of memory");
        return;
    }
    n = read(fd, buf, limit);
    close(fd);
    if (n < 0) {
        free(buf);
        it->readable = -1;
        snprintf(it->sample, sizeof(it->sample), "read error: %s", strerror(errno));
        return;
    }
    buf[n] = '\0';
    it->readable = 1;
    it->masked = strstr(buf, "0000000000000000") != NULL;
    it->candidates = scan_candidates(buf, it->sample, sizeof(it->sample));
    if (it->candidates == 0) {
        snprintf(it->sample, sizeof(it->sample), "%s",
                 it->masked ? "values zeroed (kptr_restrict)" : "no kernel-range token");
    }
    if (it->candidates > 0) {
        leak->any_leak = 1;
    }
    free(buf);
}

static void probe_access(tr_leak *leak, const char *name, const char *path, int dir)
{
    tr_leak_item *it;

    if (leak->items >= TR_LEAK_MAX_ITEMS) {
        return;
    }
    it = &leak->item[leak->items++];
    memset(it, 0, sizeof(*it));
    snprintf(it->name, sizeof(it->name), "%s", name);
    if (access(path, R_OK | (dir ? X_OK : 0)) == 0) {
        it->readable = 1;
        snprintf(it->sample, sizeof(it->sample), "accessible");
    } else {
        it->readable = 0;
        snprintf(it->sample, sizeof(it->sample), "denied: %s", strerror(errno));
    }
}

int tr_leak_probe(tr_leak *leak)
{
    memset(leak, 0, sizeof(*leak));
    leak->kptr_restrict = sysctl_int("/proc/sys/kernel/kptr_restrict", -1);
    leak->dmesg_restrict = sysctl_int("/proc/sys/kernel/dmesg_restrict", -1);
    leak->perf_event_paranoid = sysctl_int("/proc/sys/kernel/perf_event_paranoid", -1);

    probe_file(leak, "/proc/kallsyms", "/proc/kallsyms", 32768);
    probe_file(leak, "/proc/modules", "/proc/modules", 16384);
    probe_file(leak, "/proc/net/unix", "/proc/net/unix", 16384);
    probe_file(leak, "/proc/net/tcp", "/proc/net/tcp", 16384);
    probe_file(leak, "/proc/net/packet", "/proc/net/packet", 8192);
    probe_file(leak, "/proc/net/netlink", "/proc/net/netlink", 8192);
    probe_file(leak, "/proc/net/protocols", "/proc/net/protocols", 8192);
    probe_file(leak, "/proc/self/stack", "/proc/self/stack", 4096);
    probe_file(leak, "/proc/1/stack", "/proc/1/stack", 4096);
    probe_file(leak, "/proc/slabinfo", "/proc/slabinfo", 8192);
    probe_file(leak, "/proc/vmallocinfo", "/proc/vmallocinfo", 8192);
    probe_file(leak, "/proc/iomem", "/proc/iomem", 8192);
    probe_file(leak, "/sys/kernel/btf/vmlinux", "/sys/kernel/btf/vmlinux", 64);
    probe_file(leak, "/proc/kmsg", "/proc/kmsg", 4096);
    probe_access(leak, "/sys/kernel/debug", "/sys/kernel/debug", 1);
    probe_access(leak, "/sys/fs/pstore", "/sys/fs/pstore", 1);
    probe_access(leak, "/dev/kmsg", "/dev/kmsg", 0);

    if (leak->any_leak) {
        snprintf(leak->summary, sizeof(leak->summary),
                 "发现可读的内核地址：泄漏面存在，primitive 阶段有解");
    } else if (leak->kptr_restrict >= 2) {
        snprintf(leak->summary, sizeof(leak->summary),
                 "全部内核地址被 kptr_restrict=%d 归零，且 debugfs/pstore 不可达："
                 "本机没有现成的泄漏面", leak->kptr_restrict);
    } else {
        snprintf(leak->summary, sizeof(leak->summary),
                 "没有接口吐出内核地址（kptr_restrict=%d, dmesg_restrict=%d）："
                 "需要一个新的泄漏原语", leak->kptr_restrict, leak->dmesg_restrict);
    }
    tr_logf(TR_LOG_INFO, "leak: %d 个接口，any_leak=%d", leak->items, leak->any_leak);
    return TR_OK;
}

void tr_leak_json(const tr_leak *leak, tr_buf *out)
{
    int i;

    tr_buf_add(out, "{");
    tr_buf_addf(out, "\"kptr_restrict\":%d,", leak->kptr_restrict);
    tr_buf_addf(out, "\"dmesg_restrict\":%d,", leak->dmesg_restrict);
    tr_buf_addf(out, "\"perf_event_paranoid\":%d,", leak->perf_event_paranoid);
    tr_buf_addf(out, "\"any_leak\":%s,", leak->any_leak ? "true" : "false");
    tr_buf_add(out, "\"summary\":"); tr_buf_add_json_string(out, leak->summary);
    tr_buf_add(out, ",\"items\":[");
    for (i = 0; i < leak->items; i++) {
        const tr_leak_item *it = &leak->item[i];
        if (i > 0) {
            tr_buf_add(out, ",");
        }
        tr_buf_add(out, "{\"name\":"); tr_buf_add_json_string(out, it->name);
        tr_buf_addf(out, ",\"readable\":%d,\"masked\":%s,\"candidates\":%d,\"sample\":",
                    it->readable, it->masked ? "true" : "false", it->candidates);
        tr_buf_add_json_string(out, it->sample);
        tr_buf_add(out, "}");
    }
    tr_buf_add(out, "]}");
}

void tr_leak_text(const tr_leak *leak, tr_buf *out)
{
    int i;

    tr_buf_addf(out, "kptr_restrict=%d  dmesg_restrict=%d  perf_event_paranoid=%d\n\n",
                leak->kptr_restrict, leak->dmesg_restrict, leak->perf_event_paranoid);
    for (i = 0; i < leak->items; i++) {
        const tr_leak_item *it = &leak->item[i];
        tr_buf_addf(out, "%-24s %-8s %s\n", it->name,
                    it->readable == 1 ? "可读" : it->readable == 0 ? "拒绝" : "错误",
                    it->sample);
    }
    tr_buf_addf(out, "\n结论：%s\n", leak->summary);
}
