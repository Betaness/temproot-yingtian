# KASLR slide 提取：进展与卡点（2026-10-25 深夜）

## 已打通

| 步骤 | 结果 |
| --- | --- |
| `events/kmem/rss_stat/trigger`（0666）当旁路 | ✅ `enable_event:kmem:kmem_cache_alloc`、`enable_event:timer:timer_expire_entry` 均 rc=0 |
| 被旁路打开的事件是否真产出记录 | ✅ 文本 trace 抓到 `kmem_cache_alloc` 253 条、`timer_expire_entry` 33 条 |
| `per_cpu/cpu*/trace_pipe_raw` | ✅ shell 可读，单次可抓 40~50 万字节 |
| 原始流里能否读到内核指针 | ✅ 大量 vmalloc（`0xffffffe4d9…`）与线性映射（`0xffffff8X…`）地址 |

## 卡点：拿不到「内核 text」那一个指针

`sched_blocked_reason` 的 `caller`（offset 16）与 `timer_expire_entry` 的 `function`（offset 24）
本应是 text 地址，但抓到的值全部落在：

```
0xffffffe4d9dae6e8 / 0xffffffe4d9daea70 / 0xffffffe4d9dae314   ← vmalloc（内核栈）
0xffffff804d1e11e0 / 0xffffff8213ea3e10 / 0xffffff81bec02d00   ← 线性映射（slab 对象）
```

用离线 kernel.elf 的静态符号反推，没有一个能给出 **2 MB 对齐**的 slide：

| 静态符号 | 静态地址 |
| --- | --- |
| `_text` | `0xffffffc080000000` |
| `timerfd_tmrproc` | `0xffffffc080140f7c` |
| `hrtimer_wakeup` | `0xffffffc08014908c` |
| `delayed_work_timer_fn` | `0xffffffc08022577c` |
| `posix_timer_fn` | `0xffffffc0802401f4` |
| `mix_interrupt_randomness` | `0xffffffc0802b2270` |
| `selinux_state` | `0xffffffc082959630` |
| `__arm64_sys_getpid` | `0xffffffc08023d960` |
| `do_timer_create` | `0xffffffc0803a6f1c` |

结论：**我读到的不是 `function`/`caller` 字段本身**，而是同一记录里的其它指针（timer、栈、对象）。
原因在于 `trace_pipe_raw` 的流没有给出记录边界对齐，我按 `type_len` 朴素走位对不齐
（hexdump 里首 4 字节 `00 03 e8 5e` → type_len=0，明显是起始错位或 padding 头）。

## 下一步（明确）

1. 按 `struct ring_buffer_event` 的真实语义重写走位：`type_len==0` 时长度在**第 2 个 u32**；
   `type_len==31` 时长度在第 2 个 u32 且 payload 从 +8 开始；`1/2` 分别是 time_extend/time_stamp。
   当前实现按 `padding=len in next word` 处理，但用 `plen?:4` 兜底，容易连锁错位。
2. 或者绕开对齐问题：找**文本形式就打印原始地址**的事件（`%px`），例如 `kmem:mm_page_alloc` 的
   `pfn=0x…`（BRM 已确认能读到真 PFN）。
3. slide 一旦拿到，直接用离线符号表加偏移算出 `selinux_state`、`__arm64_sys_getpid`，
   接上 BRM 链的第 ⑤⑥⑦ 步。

## 现场状态

`tracing_on=0`，我加的 trigger 已移除，`kprobe_events` 里没有我留下的探针，
分区与引导链零写入。
