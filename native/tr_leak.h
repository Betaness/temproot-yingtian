/*
 * tr_leak.h - kernel address disclosure surface enumeration.
 *
 * Stage 5 (arbitrary write) needs one kernel address: the vmemmap base, a
 * kernel text pointer or a task_struct pointer. Instead of guessing which
 * interface might still disclose one, this module tries every readable
 * interface on the running device and reports what each one actually returned.
 *
 * A negative result here is as valuable as a positive one: it defines whether
 * the exploitation stage is blocked by the platform or merely by missing code.
 */
#ifndef TR_LEAK_H
#define TR_LEAK_H

#include "tr_common.h"

#define TR_LEAK_MAX_ITEMS 18

typedef struct {
    char name[56];
    int readable;      /* 1 readable, 0 denied, -1 error */
    int masked;        /* 1 when values are present but zeroed (kptr_restrict) */
    int candidates;    /* plausible kernel addresses found */
    char sample[80];   /* first plausible address, or the reason it failed */
} tr_leak_item;

typedef struct {
    int kptr_restrict;
    int dmesg_restrict;
    int perf_event_paranoid;
    int items;
    int any_leak;
    char summary[288];
    tr_leak_item item[TR_LEAK_MAX_ITEMS];
} tr_leak;

/* Reads only. Never opens a write path. */
int tr_leak_probe(tr_leak *out);
void tr_leak_json(const tr_leak *leak, tr_buf *out);
void tr_leak_text(const tr_leak *leak, tr_buf *out);

#endif /* TR_LEAK_H */
