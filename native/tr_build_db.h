/*
 * tr_build_db.h - offline-verified build table.
 *
 * Every row is backed by an artifact in the research workspace. The guard uses
 * this table when /proc/config.gz is not available on the device: absence of
 * runtime evidence must never be read as absence of mitigations.
 *
 * Verdict values:
 *   TR_BUILD_ALLOW      identity matches and the build has no KASAN/PANIC_ON_OOPS
 *   TR_BUILD_EXPERIMENT identity matches but exploitation is unproven
 *   TR_BUILD_BLOCK      identity matches a build where the primitive is blocked
 *   TR_BUILD_UNKNOWN    no row matches: stop, do not guess parameters
 */
#ifndef TR_BUILD_DB_H
#define TR_BUILD_DB_H

#include "tr_common.h"
#include "tr_probe.h"

enum tr_build_verdict {
    TR_BUILD_UNKNOWN = 0,
    TR_BUILD_ALLOW = 1,
    TR_BUILD_EXPERIMENT = 2,
    TR_BUILD_BLOCK = 3
};

typedef struct {
    const char *device;          /* ro.product.device */
    const char *kernel_release;  /* uname -r, exact */
    const char *fingerprint_prefix;
    int kasan;
    int panic_on_oops;
    int kfence;
    int init_on_alloc;
    int sysvipc;
    int user_ns;
    int static_usermodehelper;
    int mte;
    const char *evidence;        /* path inside the research workspace */
    const char *note_zh;         /* operator-facing reason */
} tr_build_row;

const tr_build_row *tr_build_lookup(const char *device, const char *kernel_release);
int tr_build_evaluate(const tr_build_row *row);
const char *tr_build_gate_json(const tr_env *env, tr_buf *out);

#endif /* TR_BUILD_DB_H */
