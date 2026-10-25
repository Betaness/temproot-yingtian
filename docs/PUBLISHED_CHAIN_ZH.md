# 公开链条核对（2026-10-25）

用户提供了同款设备已成功临时 root 的截图（KernelSU LKM、越狱模式、SELinux 宽容）。
据此检索到公开资料，本文件记录**别人的方法**与**我在本机的复现位置**。

## 1. 公开来源

| 来源 | 内容 |
| --- | --- |
| [BRM-AN00 移植](https://github.com/sganggs/CVE-2026-98260-BRM-AN00) | 最完整的链：触发、占页、改 cred、写 selinux、late-load BakaSU |
| [nezha 移植](https://github.com/quyicheng03-boop/CVE-2026-98260-nezha-android) | 小米 17 Ultra，三阶段权限验证思路 |
| [smzdm 科普](https://post.smzdm.com/p/a5ro630l/) | GhostLock 工具链背景，明确提到小米平板 9 Pro Max 已支持 |
| 上游修复 | `acb03d388181` "exec: Cleanup POSIX timers right after de_thread"，进 6.18.54 |

## 2. 完整链条（来自 BRM 移植文档）

1. `begin_new_exec` 里非 leader 线程走 `+0x28c` 分支：`zap_other_threads` → `exchange_tids` → `release_task`，
   再回到 `+0x33c` 走 `unshare_files` / `set_mm_exe_file` / `exec_mmap`（`down_read_killable`）/ `exec_task_namespaces`。
2. **`exec_mmap` 期间被 SIGKILL**：任务在 `do_exit` → `exit_itimers` 里释放 `k_itimer`，
   而父进程 reap 时 `timerqueue_del` 还在操作那个已释放节点 → UAF。
3. **武装用的定时器必须是 `SIGEV_SIGNAL`**（`SIGEV_NONE` 时 `posix_cpu_timer_set` 跳过 `timerqueue_add`，节点根本不进队列）。
4. 释放出来的是一张 **order-1 页**；用 **8 KB 的 unix `SOCK_STREAM` 写入**占住它。
5. 占住后，回收路径把伪造的 `cred` 地址写进 `task + 0x908`；再两次写零修掉 uid/gid 与 suid/sgid。
6. `selinux_state - 7` 写零可清掉 enforcing 字节（BRM 上 `notif_lock` 在 `-8`）。
7. 最后 `ksud late-load --kmi android17-6.18` 起 KernelSU LKM（重启即消失 = 临时 root）。

## 3. 我在本机已验证的部分

| 项目 | 结果 |
| --- | --- |
| `posix_timers_cache` 几何 | `384 21 2` —— **与 BRM 完全相同** |
| `k_itimer` 大小 / `task->cred` | 0x180 / **0x908** —— 与 BRM 表格一致，且与我 BTF 独立算出的一致 |
| `SIGEV_SIGNAL` 定时器 | 可创建、可 armed、可删除（64 个） |
| `kprobe_events` 可写 | 是（0777），但事件 `enable` 被 SELinux 拒 |
| `events/kmem/rss_stat/enable`、`trigger` | **0666 可写** —— BRM 用的旁路在本机成立 |
| 触发旁路效果 | 成功打开 `kmem_cache_alloc`，文本 trace 抓到 253 条记录 |
| `per_cpu/cpuN/trace_pipe_raw` | **shell 可读**（1024 字节实测成功） |

## 4. 卡住的位置（精确）

想让 kmem trace 吐出 `do_timer_create` 的分配记录（BRM 用 `do_timer_create+0xb8` 的原始记录算 slide），
但在本机 **`timer_create` 的 384 字节分配没有出现在 trace 里**：

```
bytes_req=384 记录数: 0
call_site 里带 timer 的: 0
trace 里出现过的 cache: names_cache(161) skbuff_head_cache(37) ... 没有 posix_timers
```

同时 `posix_timers_cache` 在 `/proc/slabinfo` 里 `active_objs` 确实在变化，说明分配发生了、只是没被这个
tracepoint 记录下来。下一步需要确认：是事件的 per-event filter 问题、还是该 cache 走了不触发
`kmem_cache_alloc` 记录的路径（BRM 在他们机器上是能看到的）。

## 5. 我此前犯的两个错（已修正到代码里）

1. `trprobe` 用 `SIGEV_NONE` 装定时器 —— 节点从未进 timerqueue，测量测的是空气。
2. 触发构造用了「挂起信号 + 阻塞」而不是「exec_mmap 期间 SIGKILL」。

## 6. 复现脚本

`scripts/harness/`：`timers2.c`（SIGEV_SIGNAL 定时器）、`leakprobe.c`（原始 trace 抓取 + 指针扫描）、
`touchmem.c`（触发 rss_stat）、`perfleak.c`、`keysprobe.c`。
