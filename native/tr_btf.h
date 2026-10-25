/*
 * tr_btf.h - minimal BTF reader for /sys/kernel/btf/vmlinux.
 *
 * Why this exists: the handoff document forbids guessing struct offsets for a
 * specific kernel build. BTF is shipped inside this kernel (CONFIG_DEBUG_INFO_BTF=y)
 * and exposed to unprivileged readers, so every layout the exploit needs is
 * derived at runtime from the running kernel's own type information. Nothing in
 * this project hardcodes task_struct/cred/pipe_buffer offsets.
 */
#ifndef TR_BTF_H
#define TR_BTF_H

#include "tr_common.h"

#define TR_BTF_MAGIC 0xeb9f

enum tr_btf_kind {
    BTF_KIND_UNKN = 0,
    BTF_KIND_INT = 1,
    BTF_KIND_PTR = 2,
    BTF_KIND_ARRAY = 3,
    BTF_KIND_STRUCT = 4,
    BTF_KIND_UNION = 5,
    BTF_KIND_ENUM = 6,
    BTF_KIND_FWD = 7,
    BTF_KIND_TYPEDEF = 8,
    BTF_KIND_VOLATILE = 9,
    BTF_KIND_CONST = 10,
    BTF_KIND_RESTRICT = 11,
    BTF_KIND_FUNC = 12,
    BTF_KIND_FUNC_PROTO = 13,
    BTF_KIND_VAR = 14,
    BTF_KIND_DATASEC = 15,
    BTF_KIND_FLOAT = 16,
    BTF_KIND_DECL_TAG = 17,
    BTF_KIND_TYPE_TAG = 18,
    BTF_KIND_ENUM64 = 19
};

typedef struct tr_btf tr_btf;

tr_btf *tr_btf_open(const char *path);
void tr_btf_close(tr_btf *btf);
int tr_btf_type_count(const tr_btf *btf);

/* 0 on success, negative on failure. Returns 1 when the type exists. */
int tr_btf_find(tr_btf *btf, const char *name, int *type_id);
int tr_btf_kind(const tr_btf *btf, int type_id);
const char *tr_btf_name(const tr_btf *btf, int type_id);
uint32_t tr_btf_size(const tr_btf *btf, int type_id);
int tr_btf_vlen(const tr_btf *btf, int type_id);

/* Follow TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG to the real type. */
int tr_btf_resolve(const tr_btf *btf, int type_id);
/* If type_id is a pointer, return the pointee type, else -1. */
int tr_btf_pointee(const tr_btf *btf, int type_id);

/* Bit offset of a struct/union member, searching nested anonymous members.
 * Returns 0 and sets *bit_off on success, -1 when the member is absent. */
int tr_btf_offset(tr_btf *btf, int type_id, const char *member, uint32_t *bit_off);
int tr_btf_member_type(tr_btf *btf, int type_id, const char *member, int *member_type);

/* Human readable dump of one struct, used by the in-app layout report. */
void tr_btf_dump(tr_btf *btf, const char *name, tr_buf *out);

#endif /* TR_BTF_H */
