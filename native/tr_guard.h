/*
 * tr_guard.h - mitigation guard (fail closed).
 *
 * The guard decides whether any memory-corruption work may run at all. It is
 * evaluated before every dangerous call, never cached across reboots, and its
 * negative verdict is final: an unsupported or KASAN-instrumented kernel gets
 * read-only probing only.
 */
#ifndef TR_GUARD_H
#define TR_GUARD_H

#include "tr_common.h"
#include "tr_probe.h"
#include "tr_build_db.h"

#define TR_GUARD_MAX_REASONS 10

typedef struct {
    int verdict;               /* enum tr_build_verdict */
    int exploit_allowed;       /* 1 only when nothing blocks */
    int runtime_config_known;  /* /proc/config.gz parsed on this boot */
    int kasan_active;          /* best evidence-based estimate */
    int kfence_active;
    int panic_on_oops;
    int mte_hw;
    int identity_complete;
    char block_code[48];
    char reason[TR_GUARD_MAX_REASONS][192];
    int reason_count;
} tr_guard;

int tr_guard_evaluate(const tr_env *env, tr_guard *g);
void tr_guard_json(const tr_guard *g, tr_buf *out);

/* One-line operator summary in Chinese, used by the UI status card. */
const char *tr_guard_summary_zh(const tr_guard *g);

#endif /* TR_GUARD_H */
