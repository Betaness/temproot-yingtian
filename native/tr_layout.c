#include "tr_layout.h"

/* Every field the execution stages consume. Nothing else is assumed. */
static const struct {
    const char *object;
    const char *member;
} g_required[] = {
    {"task_struct", "pid"},
    {"task_struct", "tgid"},
    {"task_struct", "comm"},
    {"task_struct", "tasks"},
    {"task_struct", "cred"},
    {"task_struct", "real_cred"},
    {"task_struct", "signal"},
    {"task_struct", "mm"},
    {"task_struct", "files"},
    {"cred", "uid"},
    {"cred", "gid"},
    {"cred", "euid"},
    {"cred", "egid"},
    {"cred", "suid"},
    {"cred", "sgid"},
    {"cred", "fsuid"},
    {"cred", "fsgid"},
    {"cred", "cap_inheritable"},
    {"cred", "cap_permitted"},
    {"cred", "cap_effective"},
    {"cred", "cap_bset"},
    {"cred", "cap_ambient"},
    {"cred", "user_ns"},
    {"cred", "security"},
    {"signal_struct", "posix_timers"},
    {"signal_struct", "posix_cputimers"},
    {"pipe_buffer", "page"},
    {"pipe_buffer", "offset"},
    {"pipe_buffer", "len"},
    {"pipe_buffer", "ops"},
    {"pipe_buffer", "flags"},
    {"pipe_inode_info", "bufs"},
    {"pipe_inode_info", "head"},
    {"pipe_inode_info", "tail"},
    {"pipe_inode_info", "ring_size"},
    {"k_itimer", "it_clock"},
    {"k_itimer", "it_signal"},
    {"k_itimer", "it"},
};

static const int g_required_count = (int)(sizeof(g_required) / sizeof(g_required[0]));

/*
 * Offline layout for kernel 6.18.21-android17-5-g805aa6adea19-abogki565292102-4k,
 * produced by scripts/btf_dump.py from the BTF embedded in the stock boot image
 * (stock/kernel-0.btf, boot sha256
 * 1e3a1111aaf7e17f843dd541ef663a46b3b1891d25568f905cbcb364cc911ce4).
 *
 * Why this table exists: on this device /sys/kernel/btf/vmlinux is denied to
 * both untrusted_app and shell, so the runtime path yields nothing. The values
 * are evidence-derived, not guessed, and they are only used when the kernel
 * release string matches exactly.
 */
static const struct {
    const char *object;
    const char *member;
    uint32_t byte_off;
} g_offline[] = {
    {"task_struct", "pid", 0x718},
    {"task_struct", "tgid", 0x71c},
    {"task_struct", "comm", 0x918},
    {"task_struct", "tasks", 0x648},
    {"task_struct", "cred", 0x908},
    {"task_struct", "real_cred", 0x900},
    {"task_struct", "signal", 0x960},
    {"task_struct", "mm", 0x698},
    {"task_struct", "files", 0x948},
    {"cred", "uid", 0x008},
    {"cred", "gid", 0x00c},
    {"cred", "euid", 0x018},
    {"cred", "egid", 0x01c},
    {"cred", "suid", 0x010},
    {"cred", "sgid", 0x014},
    {"cred", "fsuid", 0x020},
    {"cred", "fsgid", 0x024},
    {"cred", "cap_inheritable", 0x030},
    {"cred", "cap_permitted", 0x038},
    {"cred", "cap_effective", 0x040},
    {"cred", "cap_bset", 0x048},
    {"cred", "cap_ambient", 0x050},
    {"cred", "user_ns", 0x090},
    {"cred", "security", 0x080},
    {"signal_struct", "posix_timers", 0x088},
    {"signal_struct", "posix_cputimers", 0x118},
    {"pipe_buffer", "page", 0x000},
    {"pipe_buffer", "offset", 0x008},
    {"pipe_buffer", "len", 0x00c},
    {"pipe_buffer", "ops", 0x010},
    {"pipe_buffer", "flags", 0x018},
    {"pipe_inode_info", "bufs", 0x0a8},
    {"pipe_inode_info", "head", 0x058},
    {"pipe_inode_info", "tail", 0x05c},
    {"pipe_inode_info", "ring_size", 0x064},
    {"k_itimer", "it_clock", 0x024},
    {"k_itimer", "it_signal", 0x030},
    {"k_itimer", "it", 0x0e0},
};

static const int g_offline_count = (int)(sizeof(g_offline) / sizeof(g_offline[0]));

#define TR_OFFLINE_KERNEL "6.18.21-android17-5-g805aa6adea19-abogki565292102-4k"

static void layout_from_offline(tr_layout *lay, const char *kernel_release)
{
    int i, j;

    lay->offline_used = 1;
    lay->btf_ok = 0;
    lay->count = 0;
    lay->missing_count = 0;
    for (i = 0; i < g_required_count && i < TR_LAYOUT_MAX_FIELDS; i++) {
        tr_layout_field *f = &lay->fields[i];
        f->object = g_required[i].object;
        f->member = g_required[i].member;
        f->found = 0;
        f->byte_off = 0;
        f->type_id = -1;
        lay->count++;
        for (j = 0; j < g_offline_count; j++) {
            if (strcmp(g_offline[j].object, f->object) == 0 &&
                strcmp(g_offline[j].member, f->member) == 0) {
                f->found = 1;
                f->byte_off = g_offline[j].byte_off;
                break;
            }
        }
        if (!f->found) {
            lay->missing_count++;
        }
    }
    snprintf(lay->missing, sizeof(lay->missing),
             "运行时 BTF 不可读；已改用离线 BTF 表（内核 %s）",
             kernel_release != NULL ? kernel_release : "?");
    lay->complete = lay->missing_count == 0;
    tr_logf(TR_LOG_WARN, "layout: 使用离线 BTF 表（%d/%d 字段）",
            lay->count - lay->missing_count, lay->count);
}

int tr_layout_build(tr_layout *lay, const char *btf_path, const char *kernel_release)
{
    tr_btf *btf;
    int i;
    size_t missing_len = 0;

    memset(lay, 0, sizeof(*lay));
    btf = tr_btf_open(btf_path);
    if (btf == NULL) {
        if (kernel_release != NULL && strcmp(kernel_release, TR_OFFLINE_KERNEL) == 0) {
            layout_from_offline(lay, kernel_release);
            return lay->complete ? TR_OK : TR_ECOMPAT;
        }
        tr_logf(TR_LOG_WARN, "layout: BTF 不可读（%s），且内核 %s 没有离线基线",
                btf_path, kernel_release != NULL ? kernel_release : "?");
        snprintf(lay->missing, sizeof(lay->missing),
                 "BTF 不可读且无该内核的离线基线：%s", btf_path);
        lay->missing_count = g_required_count;
        return TR_EUNSUPPORTED;
    }
    lay->btf_ok = 1;
    lay->btf_type_count = tr_btf_type_count(btf);

    for (i = 0; i < g_required_count && i < TR_LAYOUT_MAX_FIELDS; i++) {
        tr_layout_field *f = &lay->fields[i];
        int type_id = -1;
        uint32_t bit_off = 0;

        f->object = g_required[i].object;
        f->member = g_required[i].member;
        f->found = 0;
        f->type_id = -1;
        lay->count++;

        if (tr_btf_find(btf, f->object, &type_id) != 1) {
            tr_logf(TR_LOG_DEBUG, "layout: 缺少类型 %s", f->object);
        } else if (tr_btf_offset(btf, type_id, f->member, &bit_off) == 0) {
            f->found = 1;
            f->byte_off = bit_off / 8;
            f->type_id = type_id;
        }
        if (!f->found) {
            lay->missing_count++;
            if (missing_len + 64 < sizeof(lay->missing)) {
                missing_len += (size_t)snprintf(lay->missing + missing_len,
                                                sizeof(lay->missing) - missing_len,
                                                "%s.%s ", f->object, f->member);
            }
        }
    }
    lay->complete = lay->missing_count == 0;
    tr_btf_close(btf);
    tr_logf(TR_LOG_INFO, "layout: %d 个字段，缺失 %d 个", lay->count, lay->missing_count);
    return lay->complete ? TR_OK : TR_ECOMPAT;
}

int tr_layout_get(const tr_layout *lay, const char *object, const char *member,
                  uint32_t *byte_off)
{
    int i;

    for (i = 0; i < lay->count; i++) {
        if (strcmp(lay->fields[i].object, object) == 0 &&
            strcmp(lay->fields[i].member, member) == 0) {
            if (!lay->fields[i].found) {
                return -1;
            }
            *byte_off = lay->fields[i].byte_off;
            return 0;
        }
    }
    return -1;
}

void tr_layout_json(const tr_layout *lay, tr_buf *out)
{
    int i;

    tr_buf_add(out, "{");
    tr_buf_addf(out, "\"btf_ok\":%s,", lay->btf_ok ? "true" : "false");
    tr_buf_addf(out, "\"btf_type_count\":%d,", lay->btf_type_count);
    tr_buf_addf(out, "\"complete\":%s,", lay->complete ? "true" : "false");
    tr_buf_addf(out, "\"offline_used\":%s,", lay->offline_used ? "true" : "false");
    tr_buf_addf(out, "\"missing_count\":%d,", lay->missing_count);
    tr_buf_add(out, "\"missing\":"); tr_buf_add_json_string(out, lay->missing);
    tr_buf_add(out, ",\"fields\":[");
    for (i = 0; i < lay->count; i++) {
        if (i > 0) {
            tr_buf_add(out, ",");
        }
        tr_buf_add(out, "{\"object\":"); tr_buf_add_json_string(out, lay->fields[i].object);
        tr_buf_add(out, ",\"member\":"); tr_buf_add_json_string(out, lay->fields[i].member);
        tr_buf_addf(out, ",\"found\":%s,\"byte_offset\":%u}",
                    lay->fields[i].found ? "true" : "false", lay->fields[i].byte_off);
    }
    tr_buf_add(out, "]}");
}

void tr_layout_text(const tr_layout *lay, tr_buf *out)
{
    int i;

    if (!lay->btf_ok && !lay->offline_used) {
        tr_buf_add(out, "本机 BTF 不可读，且没有该内核的离线基线（不做任何偏移猜测）。\n");
        return;
    }
    if (lay->offline_used) {
        tr_buf_add(out, "运行时 BTF 被 SELinux 拒绝；以下偏移来自离线 BTF 表"
                        "（同一内核镜像，按内核 release 精确匹配）。\n");
    } else {
        tr_buf_addf(out, "BTF 类型总数 %d，需要字段 %d，缺失 %d。\n",
                    lay->btf_type_count, lay->count, lay->missing_count);
    }
    for (i = 0; i < lay->count; i++) {
        const tr_layout_field *f = &lay->fields[i];
        if (f->found) {
            tr_buf_addf(out, "  %-16s %-16s +0x%03x (%u)\n", f->object, f->member,
                        f->byte_off, f->byte_off);
        } else {
            tr_buf_addf(out, "  %-16s %-16s 缺失\n", f->object, f->member);
        }
    }
}
