/*
 * tr_timer_exec.h - CVE-2026-98260 reachability instrumentation.
 *
 * The upstream fix moves POSIX-CPU-timer cleanup to after a *successful*
 * de_thread() inside begin_new_exec(). The pre-fix order cleans up first, so a
 * later failure leaves the process running while the kernel has already dropped
 * its timer state.
 *
 * This module measures which order is present on the running kernel WITHOUT
 * corrupting memory:
 *   strategy 1  exec of a missing path       -> fails before begin_new_exec
 *   strategy 2  exec with a blocked, pending signal and a live sibling thread
 *                                             -> de_thread() fails with
 *                                                -ERESTARTNOINTR after the
 *                                                check block
 * After exec returns, each armed timer is deleted and the return value is
 * recorded. EINVAL means the kernel had already removed it (pre-fix order);
 * success means it survived (post-fix order). No freed object is ever
 * dereferenced, so the measurement is safe even on a KASAN + PANIC_ON_OOPS
 * kernel.
 */
#ifndef TR_TIMER_EXEC_H
#define TR_TIMER_EXEC_H

#include "tr_common.h"
#include "tr_guard.h"

#define TR_TIMER_STRATEGIES 3
#define TR_TIMERS_PER_CHILD 4

typedef struct {
    int strategy;
    int exec_errno;
    int timers_armed;
    int delete_ok;
    int delete_einval;
    int delete_other;
    int listed_after;
    int terminated_by_signal;
    int signal_number;
    long elapsed_ms;
} tr_timer_row;

typedef struct {
    tr_timer_row rows[TR_TIMER_STRATEGIES];
    int rounds;
    int completed_rounds;
    long elapsed_ms;
    char conclusion[32];   /* PRE_FIX_ORDER | POST_FIX_ORDER | INCONCLUSIVE */
    char detail[1024];
} tr_timer_probe;

/* Run the measurement. Safe to call on any kernel: it never writes kernel memory. */
int tr_timer_probe_run(tr_timer_probe *probe, int rounds);
void tr_timer_probe_json(const tr_timer_probe *probe, tr_buf *out);
const char *tr_timer_conclusion_zh(const char *conclusion);

/* Destructive stage. Refuses to do anything unless the guard allows it. */
int tr_timer_trigger_run(const tr_env *env, const tr_guard *guard, tr_buf *report);

#endif /* TR_TIMER_EXEC_H */
