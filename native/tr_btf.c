#include "tr_btf.h"

struct btf_hdr_wire {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
} __attribute__((packed));

struct btf_type_wire {
    uint32_t name_off;
    uint32_t info;
    uint32_t size_or_type;
} __attribute__((packed));

struct btf_member_wire {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
} __attribute__((packed));

struct btf_array_wire {
    uint32_t type;
    uint32_t index_type;
    uint32_t nelems;
} __attribute__((packed));

struct tr_btf {
    unsigned char *raw;
    size_t raw_len;
    const char *str;
    size_t str_len;
    const unsigned char *types;
    size_t types_len;
    int count;
    const struct btf_type_wire **index; /* index[1..count] */
};

static uint32_t kind_of(const struct btf_type_wire *t)
{
    return (t->info >> 24) & 0x1f;
}

static uint32_t vlen_of(const struct btf_type_wire *t)
{
    return t->info & 0xffff;
}

static uint32_t kind_flag_of(const struct btf_type_wire *t)
{
    return (t->info >> 31) & 0x1;
}

/* Size in bytes of the extra data that follows a btf_type record. */
static size_t extra_size(const struct btf_type_wire *t)
{
    switch (kind_of(t)) {
    case BTF_KIND_INT: return 4;
    case BTF_KIND_ARRAY: return sizeof(struct btf_array_wire);
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION: return (size_t)vlen_of(t) * sizeof(struct btf_member_wire);
    case BTF_KIND_ENUM: return (size_t)vlen_of(t) * 8u;
    case BTF_KIND_ENUM64: return (size_t)vlen_of(t) * 12u;
    case BTF_KIND_FUNC_PROTO: return (size_t)vlen_of(t) * 8u;
    case BTF_KIND_VAR: return 4;
    case BTF_KIND_DATASEC: return (size_t)vlen_of(t) * 12u;
    case BTF_KIND_DECL_TAG: return 4;
    default: return 0;
    }
}

tr_btf *tr_btf_open(const char *path)
{
    tr_btf *btf;
    const struct btf_hdr_wire *hdr;
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    const unsigned char *cursor, *end;
    int i;

    if (tr_read_file_alloc(path, &raw, &raw_len) != 0) {
        return NULL;
    }
    if (raw_len < sizeof(struct btf_hdr_wire)) {
        free(raw);
        return NULL;
    }
    hdr = (const struct btf_hdr_wire *)raw;
    if (hdr->magic != TR_BTF_MAGIC) {
        tr_logf(TR_LOG_WARN, "btf: bad magic 0x%04x", hdr->magic);
        free(raw);
        return NULL;
    }
    btf = (tr_btf *)calloc(1, sizeof(*btf));
    if (btf == NULL) {
        free(raw);
        return NULL;
    }
    btf->raw = raw;
    btf->raw_len = raw_len;
    btf->str = (const char *)(raw + hdr->hdr_len + hdr->str_off);
    btf->str_len = hdr->str_len;
    btf->types = raw + hdr->hdr_len + hdr->type_off;
    btf->types_len = hdr->type_len;

    /* First pass: count and index records. */
    cursor = btf->types;
    end = btf->types + btf->types_len;
    btf->count = 0;
    while (cursor + sizeof(struct btf_type_wire) <= end) {
        const struct btf_type_wire *t = (const struct btf_type_wire *)cursor;
        size_t step = sizeof(struct btf_type_wire) + extra_size(t);
        if (cursor + step > end) {
            break;
        }
        btf->count++;
        cursor += step;
    }
    btf->index = (const struct btf_type_wire **)calloc((size_t)btf->count + 2, sizeof(void *));
    if (btf->index == NULL) {
        tr_btf_close(btf);
        return NULL;
    }
    cursor = btf->types;
    for (i = 0; i < btf->count; i++) {
        const struct btf_type_wire *t = (const struct btf_type_wire *)cursor;
        btf->index[i + 1] = t;
        cursor += sizeof(struct btf_type_wire) + extra_size(t);
    }
    tr_logf(TR_LOG_INFO, "btf: %d types, strings %zu bytes", btf->count, btf->str_len);
    return btf;
}

void tr_btf_close(tr_btf *btf)
{
    if (btf == NULL) {
        return;
    }
    free((void *)btf->index);
    free(btf->raw);
    free(btf);
}

int tr_btf_type_count(const tr_btf *btf)
{
    return btf != NULL ? btf->count : 0;
}

static const struct btf_type_wire *get_type(const tr_btf *btf, int type_id)
{
    if (btf == NULL || type_id <= 0 || type_id > btf->count) {
        return NULL;
    }
    return btf->index[type_id];
}

const char *tr_btf_name(const tr_btf *btf, int type_id)
{
    const struct btf_type_wire *t = get_type(btf, type_id);

    if (t == NULL || t->name_off >= btf->str_len) {
        return "";
    }
    return btf->str + t->name_off;
}

int tr_btf_kind(const tr_btf *btf, int type_id)
{
    const struct btf_type_wire *t = get_type(btf, type_id);

    return t == NULL ? -1 : (int)kind_of(t);
}

uint32_t tr_btf_size(const tr_btf *btf, int type_id)
{
    const struct btf_type_wire *t = get_type(btf, type_id);

    return t == NULL ? 0 : t->size_or_type;
}

int tr_btf_vlen(const tr_btf *btf, int type_id)
{
    const struct btf_type_wire *t = get_type(btf, type_id);

    return t == NULL ? -1 : (int)vlen_of(t);
}

static int is_modifier(uint32_t kind)
{
    return kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_CONST
        || kind == BTF_KIND_VOLATILE || kind == BTF_KIND_RESTRICT
        || kind == BTF_KIND_TYPE_TAG || kind == BTF_KIND_DECL_TAG;
}

int tr_btf_resolve(const tr_btf *btf, int type_id)
{
    int guard = 0;

    while (guard++ < 32) {
        const struct btf_type_wire *t = get_type(btf, type_id);
        if (t == NULL) {
            return -1;
        }
        if (!is_modifier(kind_of(t))) {
            return type_id;
        }
        type_id = (int)t->size_or_type;
    }
    return -1;
}

int tr_btf_pointee(const tr_btf *btf, int type_id)
{
    int resolved = tr_btf_resolve(btf, type_id);
    const struct btf_type_wire *t;

    if (resolved < 0) {
        return -1;
    }
    t = get_type(btf, resolved);
    if (t == NULL || kind_of(t) != BTF_KIND_PTR) {
        return -1;
    }
    return tr_btf_resolve(btf, (int)t->size_or_type);
}

int tr_btf_find(tr_btf *btf, const char *name, int *type_id)
{
    int i;

    if (btf == NULL || name == NULL) {
        return -1;
    }
    for (i = 1; i <= btf->count; i++) {
        const struct btf_type_wire *t = btf->index[i];
        uint32_t kind = kind_of(t);
        if (t->name_off == 0 || t->name_off >= btf->str_len) {
            continue;
        }
        if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION
            && kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_ENUM) {
            continue;
        }
        if (strcmp(btf->str + t->name_off, name) == 0) {
            if (type_id != NULL) {
                *type_id = i;
            }
            return 1;
        }
    }
    return 0;
}

static int offset_in_record(const tr_btf *btf, const struct btf_type_wire *t,
                            const char *member, uint32_t base, uint32_t *out)
{
    const unsigned char *extra = (const unsigned char *)(t + 1);
    uint32_t vlen = vlen_of(t);
    uint32_t kflag = kind_flag_of(t);
    uint32_t i;

    for (i = 0; i < vlen; i++) {
        const struct btf_member_wire *m =
            (const struct btf_member_wire *)(extra + (size_t)i * sizeof(*m));
        const char *mname = (m->name_off < btf->str_len) ? btf->str + m->name_off : "";
        uint32_t bit_off = kflag ? (m->offset & 0x00ffffffu) : m->offset;

        if (mname[0] != '\0' && strcmp(mname, member) == 0) {
            *out = base + bit_off;
            return 0;
        }
        if (mname[0] == '\0') {
            /* Anonymous struct/union: descend. */
            int inner = tr_btf_resolve(btf, (int)m->type);
            const struct btf_type_wire *it;
            if (inner < 0) {
                continue;
            }
            it = get_type(btf, inner);
            if (it == NULL) {
                continue;
            }
            if (kind_of(it) == BTF_KIND_STRUCT || kind_of(it) == BTF_KIND_UNION) {
                if (offset_in_record(btf, it, member, base + bit_off, out) == 0) {
                    return 0;
                }
            }
        }
    }
    return -1;
}

int tr_btf_offset(tr_btf *btf, int type_id, const char *member, uint32_t *bit_off)
{
    int resolved = tr_btf_resolve(btf, type_id);
    const struct btf_type_wire *t;

    if (resolved < 0) {
        return -1;
    }
    t = get_type(btf, resolved);
    if (t == NULL) {
        return -1;
    }
    if (kind_of(t) != BTF_KIND_STRUCT && kind_of(t) != BTF_KIND_UNION) {
        return -1;
    }
    return offset_in_record(btf, t, member, 0, bit_off);
}

int tr_btf_member_type(tr_btf *btf, int type_id, const char *member, int *member_type)
{
    int resolved = tr_btf_resolve(btf, type_id);
    const struct btf_type_wire *t;
    const unsigned char *extra;
    uint32_t i, vlen;

    if (resolved < 0) {
        return -1;
    }
    t = get_type(btf, resolved);
    if (t == NULL || (kind_of(t) != BTF_KIND_STRUCT && kind_of(t) != BTF_KIND_UNION)) {
        return -1;
    }
    extra = (const unsigned char *)(t + 1);
    vlen = vlen_of(t);
    for (i = 0; i < vlen; i++) {
        const struct btf_member_wire *m =
            (const struct btf_member_wire *)(extra + (size_t)i * sizeof(*m));
        const char *mname = (m->name_off < btf->str_len) ? btf->str + m->name_off : "";
        if (strcmp(mname, member) == 0) {
            if (member_type != NULL) {
                *member_type = (int)m->type;
            }
            return 0;
        }
    }
    return -1;
}

void tr_btf_dump(tr_btf *btf, const char *name, tr_buf *out)
{
    int type_id = -1;
    const struct btf_type_wire *t;
    const unsigned char *extra;
    uint32_t i, vlen, kflag;
    int kind;

    if (tr_btf_find(btf, name, &type_id) != 1) {
        tr_buf_addf(out, "struct %s: 未在 BTF 中找到\n", name);
        return;
    }
    kind = tr_btf_kind(btf, type_id);
    if (kind == BTF_KIND_TYPEDEF) {
        type_id = tr_btf_resolve(btf, type_id);
        kind = tr_btf_kind(btf, type_id);
    }
    if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION) {
        tr_buf_addf(out, "%s: 类型不是 struct/union（kind=%d）\n", name, kind);
        return;
    }
    t = get_type(btf, type_id);
    extra = (const unsigned char *)(t + 1);
    vlen = vlen_of(t);
    kflag = kind_flag_of(t);
    tr_buf_addf(out, "%s %s  size=%u\n", kind == BTF_KIND_UNION ? "union" : "struct",
                name, t->size_or_type);
    for (i = 0; i < vlen; i++) {
        const struct btf_member_wire *m =
            (const struct btf_member_wire *)(extra + (size_t)i * sizeof(*m));
        const char *mname = (m->name_off < btf->str_len) ? btf->str + m->name_off : "";
        uint32_t bit_off = kflag ? (m->offset & 0x00ffffffu) : m->offset;
        tr_buf_addf(out, "  +0x%03x (bit %4u)  %-28s type=%u\n",
                    bit_off / 8, bit_off, mname[0] ? mname : "<anon>", m->type);
    }
}
