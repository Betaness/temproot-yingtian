/*
 * tr_verify.h - strict post-escalation verification.
 *
 * The handoff document forbids treating an exit code, a permissive SELinux
 * state or a UI message as proof of root. This module collects independent
 * evidence and only reports success when all of it agrees.
 */
#ifndef TR_VERIFY_H
#define TR_VERIFY_H

#include "tr_common.h"

typedef struct {
    int uid;
    int euid;
    int egid;
    char cap_eff[32];
    char cap_prm[32];
    char cap_bnd[32];
    char selinux[160];
    char seccomp[8];
    char no_new_privs[8];
    int selinux_enforce;        /* 1 enforcing, 0 permissive, -1 unknown */
    int privileged_open_ok;
    int privileged_open_errno;
    char privileged_path[128];
    int setuid_roundtrip_ok;
    int cap_sys_admin;
    int uid_is_root;
    int context_is_root_like;
    int verified;               /* 1 only when every criterion passed */
    char summary[512];
} tr_verify;

int tr_verify_run(tr_verify *v);
void tr_verify_json(const tr_verify *v, tr_buf *out);
const char *tr_verify_summary_zh(const tr_verify *v);

#endif /* TR_VERIFY_H */
