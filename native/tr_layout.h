/*
 * tr_layout.h - struct layout resolution from BTF.
 *
 * The exploit path needs a fixed set of fields. Instead of hardcoding offsets
 * for one kernel build (forbidden by the handoff), every field is resolved from
 * the running kernel's BTF. If any field is missing the layout is marked
 * incomplete and the execution stages refuse to run.
 */
#ifndef TR_LAYOUT_H
#define TR_LAYOUT_H

#include "tr_common.h"
#include "tr_btf.h"

#define TR_LAYOUT_MAX_FIELDS 64

typedef struct {
    const char *object;
    const char *member;
    int found;
    uint32_t byte_off;
    int type_id;
} tr_layout_field;

typedef struct {
    int btf_ok;
    int offline_used;    /* 1 when the runtime BTF was unreadable and the
                          * offline table (same kernel image) was used instead */
    int complete;
    int btf_type_count;
    int count;
    int missing_count;
    tr_layout_field fields[TR_LAYOUT_MAX_FIELDS];
    char missing[512];
} tr_layout;

int tr_layout_build(tr_layout *lay, const char *btf_path, const char *kernel_release);
int tr_layout_get(const tr_layout *lay, const char *object, const char *member,
                  uint32_t *byte_off);
void tr_layout_json(const tr_layout *lay, tr_buf *out);
void tr_layout_text(const tr_layout *lay, tr_buf *out);

#endif /* TR_LAYOUT_H */
