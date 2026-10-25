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
