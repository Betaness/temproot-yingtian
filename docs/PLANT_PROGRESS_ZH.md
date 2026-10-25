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

## 一个关键发现：定时器没进队列

前两次触发**没有 panic**，原因不是"运气好"，而是：

```
子进程主线程 pause() 不消耗 CPU
  → CLOCK_THREAD_CPUTIME 定时器永远到不了过期点
  → posix_cpu_timer_set 不会调 timerqueue_add
  → rbtree 里没有节点，reap 时无队列可走
```

BRM 文档说"武装的定时器必须是 `SIGEV_SIGNAL`"，实际是**两个条件**：

1. `it_sigev_notify == SIGEV_SIGNAL`（否则 `posix_cpu_timer_set` 直接跳过 `timerqueue_add`）；
2. **时钟必须真的走过过期点**（否则节点同样不进 rbtree）。

修正：exec 线程在 `execve` 之前先烧一小段线程 CPU，让定时器过期入队，然后再 exec、再被 SIGKILL。

## 下一步（顺序固定）

1. exec 线程 execve 前 `busy-loop` 约 1~5 ms，确认节点入队（可用 `kmem` trace 观察
   `posix_timers_cache` 的 384 字节分配，或观察定时器信号是否投递）。
2. 入队后再触发 exec + SIGKILL，让 `exit_itimers` 与 reap 的 `timerqueue_del` 形成窗口。
3. 同时把 8 KiB stream 的喷发压进这个窗口（当前是"先杀后喷"，顺序需要反过来或加并发）。
4. 命中后用 `mm_page_alloc` 的 PFN 与 `mm_page_free` 的 PFN 求交集，确认占住。
5. 占住之后才谈 payload 落地与 `task+0x908` 的写。

## 安全边界

- 前两步（烧 CPU + 入队）本身不写内核内存。
- 真正的风险点在 reap：节点若已被释放且被我们的流占住、内容畸形，`rb_erase` 解引用会 oops → panic → 重启。
- 所有阶段都保持"僵尸不主动 reap"的默认行为，由 init 回收；若要主动推进，必须显式加参数。
