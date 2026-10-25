/*
 * tr_rootd.h - temporary root daemon and su client.
 *
 * Semantics (deliberately narrow):
 *   - lives only for the current boot, dies with its owner process or TTL
 *   - no persistence, no boot hooks, no partition writes
 *   - authorization is per connecting UID, verified with SO_PEERCRED, never
 *     with a value supplied by the caller
 *   - every command runs in a fresh session with its own pty
 *
 * This is the layer that DroidDesk talks to. It is independent from how the
 * root credentials were obtained.
 */
#ifndef TR_ROOTD_H
#define TR_ROOTD_H

#include "tr_common.h"

#define TR_ROOTD_SOCK_ABSTRACT "fujiang.temproot.su"
#define TR_SU_MAGIC 0x54525331u
#define TR_SU_VERSION 1
#define TR_SU_MAX_ARGC 32
#define TR_SU_MAX_ARG 4096
#define TR_ROOTD_DEFAULT_TTL_SEC 900

typedef struct {
    uint32_t magic;
    uint32_t version;
    int32_t uid;      /* advisory only, SO_PEERCRED is authoritative */
    int32_t pid;
    int32_t argc;
    int32_t reserved;
} tr_su_hdr;

typedef struct {
    int32_t status;   /* 0 = accepted, otherwise negative tr_status */
    int32_t child_pid;
    int32_t reserved[2];
} tr_su_reply;

/* Start the daemon in a detached child. Requires euid == 0.
 * ttl_sec <= 0 uses TR_ROOTD_DEFAULT_TTL_SEC. Returns the daemon pid or
 * a negative tr_status. */
int tr_rootd_start(const char *allow_file, int ttl_sec);

/* 1 = alive, 0 = not reachable. Cheap connect probe. */
int tr_rootd_ping(void);

/* Stop the daemon (idempotent). */
int tr_rootd_stop(void);

/* Run argv through the daemon. On success *pty_fd is a bidirectional fd that
 * behaves like the command's terminal and *child_pid is reported. The caller
 * must read the exit status with tr_su_wait(). */
int tr_su_spawn(char *const argv[], int *pty_fd, int *child_pid);

/* Read the exit status of a previously spawned command. */
int tr_su_wait(int *exit_code, int timeout_ms);

/* Convenience: run one command, print its output into out (bounded). */
int tr_su_capture(char *const argv[], tr_buf *out, int *exit_code, int timeout_ms);

/* Path helpers for the daemon state directory. */
int tr_rootd_state_dir(char *out, size_t cap);

#endif /* TR_ROOTD_H */
