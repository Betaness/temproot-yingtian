# plant 施工进度（2026-10-25 夜 → 26 日凌晨）

## 已完成并可复现

| 步骤 | 手段 | 证据 |
| --- | --- | --- |
| slide 测量 | `--preflight`，调用点表 + 投票 | `0x2459c00000`，43 票；复测 34 票 |
| 运行时地址表 | 离线 nm + slide | `selinux_state=0xffffffe4dc559630`、`selinux-7=…9629` |
| 定时器构造 | `--arm-test` | 32 个 `SIGEV_SIGNAL` 装/删成功 |
| 触发时序 | `--dry-exec` | fork + exec 线程 + SIGKILL，子进程 `status=0x9`，父进程成功 reap，设备无恙 |
| 伪造节点 | `--payload-preview` | 页内 `0xe0 + n*0x180` 共 21 槽，`parent=target-8`、`right=cred`、`left=0` |
| 页级检测 | `claimdetect` | `mm_page_free` / `mm_page_alloc` 的真实 PFN 可读（如 `pfn=0x241bb7 order=0`） |

## 更正：定时器确实入队（2026-10-26 实测）

上一版这里写的是"定时器没进队列"，**实测推翻了它**。`scripts/harness/queuetest.c`：

```
uid=2000
SIGEV_SIGNAL armed=4  proc_timers -1->-1  signals_fired=12
SIGEV_NONE   armed=4  proc_timers -1->-1  signals_fired=0
```

12 ms 烧 CPU、1 ms 周期 → 12 次信号，说明 `SIGEV_SIGNAL` 的
`CLOCK_THREAD_CPUTIME_ID` 定时器**确实入队、确实过期、确实投递**。
（`/proc/self/timers` 对普通进程不可读，所以 `proc_timers=-1`，这条观测手段作废。）

### 那前两次为什么没崩

合理的解释是：**reap 时那块内存还没被覆盖**。我是"先 SIGKILL、30 ms 后再喷流"，
而 init 的回收可能更早发生，`rb_erase` 拿到的仍是**已释放但内容完好**的节点，
指针自洽 → 走完不出事。

**结论：不是没入队，是我没进窗口。** 8 KiB 流的喷发必须与 SIGKILL **并发**，
而不是事后。

## 下一步（顺序固定）

1. ~~烧 CPU 让节点入队~~（已证明入队不需要额外操作；但烧 CPU 可让定时器真正过期，
   便于制造时序噪声）。
2. 把 8 KiB stream 的喷发改成**并发**：一个线程持续 send，另一个线程负责 SIGKILL，
   让喷发正好压在 `exit_itimers` 之后、`timerqueue_del` 之前。
4. 命中后用 `mm_page_alloc` 的 PFN 与 `mm_page_free` 的 PFN 求交集，确认占住。
5. 占住之后才谈 payload 落地与 `task+0x908` 的写。

## 安全边界

- 前两步（烧 CPU + 入队）本身不写内核内存。
- 真正的风险点在 reap：节点若已被释放且被我们的流占住、内容畸形，`rb_erase` 解引用会 oops → panic → 重启。
- 所有阶段都保持"僵尸不主动 reap"的默认行为，由 init 回收；若要主动推进，必须显式加参数。

## 并发喷流第一跑（2026-10-26 03:15）

```
=== concurrent spray ===
trigger: free=-1 alloc=-1
child=32561 exec_tid=0
kill(32561, SIGKILL)  (tid handoff not required)
sprayer: 8193 streams
order-1 frees=0 allocs=1
  no PFN intersection yet (window missed)
```

三个修正：

1. **不需要 tid**：`SIGKILL` 是进程级信号，`kill(child, SIGKILL)` 一样能打断
   `exec_mmap` 里的 `down_read_killable`。原来那条管道交接（`exec_tid`）直接删掉。
2. **order-1 free 是零**：`posix_timers_cache` 是 `21 对象/8 KiB 页`，
   只装 8 个定时器时整页不会被清空，所以内核根本不会释放那张页。
   BRM 用的是 **2048 个定时器**才逼出页释放（"A 2048-delete does"）。
3. `trigger: free=-1 alloc=-1`：`rss_stat/trigger` 是**追加写入**，同样的条目重复写会失败，
   说明之前已经设过；事件实际是开的（有 1 条 alloc 记录为证），但样本太少。

### 下一步

- 定时器数量提到 **2048**（受 `RLIMIT_...`/per-process 上限约束，可能需要多进程）。
- 喷流与 kill 的时序改成：先喷到一定量 → kill → 继续喷 → 停。
- 用 `order=1` 且 `mm_page_free` 的 PFN ∩ `mm_page_alloc` 的 PFN 判断是否占住。

## 2048 定时器 + order 分布实测（2026-10-26 03:18）

```
=== concurrent spray ===
child=991  timers_armed=2048
kill(991, SIGKILL)  (tid handoff not required)
sprayer: 8193 streams
order-1 frees=0 allocs=0
```

2048 个定时器**确实装上并随进程退出释放**了，但 trace 里没有任何 order-1 页事件。
换一个重负载验证事件本身没问题：

```
64 MiB 写入 + 删除期间：
  mm_page_free : 147 条，全部 order=0
  mm_page_alloc: 129 条，全部 order=0
```

**事件是好的，问题是 SLUB 不还页。**

`posix_timers_cache` 是 `order-1`（21 对象 / 8 KiB 页）。对象全部释放后，
SLUB 默认把空 slab 留在 `cpu_partial` / `partial` 列表，**不立刻还给 buddy**。
所以：没有 order-1 free → 没有被释放的页 → 喷流拿不到它。

想手动逼它还页也不行：

```
/sys/kernel/slab/posix_timers_cache/shrink      → Permission denied
objects / slabs / object_size                    → Permission denied
```

### 结论与下一步

这条链要成立，必须**先制造内存压力逼 SLUB 回收空 slab**。BRM 文档里正是这么做的：

> Holding 66 MiB of pipe pages, then deleting 2048 timers and spraying 3072 AIO rings,
> put leaked timer `pfn=0xb51c04` in ring 181

也就是顺序是：

1. **先占住大量 pipe 页**（约 66 MiB）→ 把内存压紧；
2. 再释放 2048 个定时器 → 空 slab 被回收、页真的还给 buddy；
3. 同时用 8 KiB unix stream（或 AIO ring）抢那张页；
4. 用 order-1 的 PFN 交集确认。

下一步就按这个顺序实现 `--pressure-spray`。
