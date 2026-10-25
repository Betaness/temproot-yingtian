# 触发机制：从参考实现里读出来的三件事（2026-10-26 03:41）

读了公开移植的 `plant/uaf_plant.c`（[BRM-AN00](https://github.com/sganggs/CVE-2026-98260-BRM-AN00)），
发现自己此前 1100 次试验全部打偏，原因是**三个构造细节全错**。

## 1. 杀手不靠延时，靠 tid 交换事件

参考实现里没有"延时 N 微秒再 kill"，而是一个 helper 线程**轮询**：

```c
while (!stop) {
    if (tgkill(tgid, old_exec_tid, 0) < 0 && errno == ESRCH) break;   /* 旧 tid 消失 */
}
tgkill(tgid, tgid, SIGKILL);                                          /* 立刻补一刀 */
```

为什么这个能精确命中：`execve` 走 `begin_new_exec()` → `de_thread()` → **`exchange_tids()`**，
它把 exec 线程的 tid 与线程组 leader 对调。旧 tid 在这一刻**从内核里消失**，
`tgkill(tid, 0)` 立刻返回 `ESRCH` —— 这就是"已经进入窗口"的硬信号。

## 2. 2048 个定时器里只有一个是真的

参考实现：

```c
for (i = 0; i < 2048; i++)
    timer_create(CLOCK_THREAD_CPUTIME_ID, i == 1024 ? &armed_ev : &plain, &many[i]);
```

- 第 **1024** 个用 `SIGEV_SIGNAL` + `SIGRTMIN`，`it_value = 3600s`（**永不触发，只入队**）
- 其余 2047 个是 `SIGEV_NONE`，作用只是**把 slab 灌满**，让受害对象落在一张"几乎全是自己的"页上

我之前把 2048 个全设成 `SIGEV_SIGNAL` 且 200µs 周期——既没灌满页、又让节点反复重排。

## 3. 还要主动制造 mmap_lock 争用

参考实现：`prepare_vmas()` 造 **50000 个 VMA**，再起 **3 个 helper 线程死循环
`mprotect(整个 VMA 区间)`**，把 `mmap_lock` 抢成瓶颈，然后 exec 线程才 `execve`。
exec 线程还要等到"某次 mprotect 正在进行中"才动手。

## 我的移植尝试（`scripts/harness/race.c`）

按上面三条写了 `race.c`：50000 VMA + 3 个 locker + tid-交换杀手 + 1 真 2047 假定时器。

**结果：挂住**。留下一个 `do_mprotect_pkey` 的 D 状态进程，load average 冲到 15.89，
20 秒后自行恢复（D 状态进程消失、load 回落、设备正常）。

结论：机制是对的，但 **50000 VMA + mprotect 死循环在这台机器上会把进程卡进 D 状态**，
需要削减规模（先试 5000 VMA / 1 个 locker）或换一种制造 mmap_lock 争用的方式。

## 下一轮的最小改动

1. VMA 数量从 50000 降到 **5000**，locker 从 3 个降到 **1 个**；
2. 加 `waitpid` 全超时，不允许任何一步无限等待；
3. 先用"只跑杀手、不跑喷流"的模式验证 **child 是否确实在 tid 交换后被 SIGKILL**；
   这一条能验证时，才接上喷流与 reap。
