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

int tr_layout_build(tr_layout *lay, const char *btf_path)
{
    tr_btf *btf;
    int i;
    size_t missing_len = 0;

    memset(lay, 0, sizeof(*lay));
    btf = tr_btf_open(btf_path);
    if (btf == NULL) {
        tr_logf(TR_LOG_WARN, "layout: BTF 不可读（%s），无法在运行时解析布局", btf_path);
        snprintf(lay->missing, sizeof(lay->missing), "BTF 不可读：%s", btf_path);
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

    if (!lay->btf_ok) {
        tr_buf_add(out, "本机 BTF 不可读，无法给出运行时布局（不做任何偏移猜测）。\n");
        return;
    }
    tr_buf_addf(out, "BTF 类型总数 %d，需要字段 %d，缺失 %d。\n",
                lay->btf_type_count, lay->count, lay->missing_count);
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
