# 找到了：本机内核存在未修复的 LPE（2026-10-26）

设备：Xiaomi Pad 9 Pro Max / M367FC / yingtian
内核：`6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`
SPL：**2026-09-01**，构建：**2026-09-28**

## 方法

1. 先读设备 SPL，只考虑**晚于 2026-09-01** 披露的漏洞；
2. 命中「Infinity Core」——Hyunwoo Kim 于 **2026-10-16** 在 oss-security 披露的
   6 个内核核心子系统 LPE，**五个带公开 PoC**；
3. 对每个漏洞，取上游修复 commit，反汇编本机 `kernel.elf` 比对修复代码是否在位。

## 六个漏洞在本机的实测状态

| CVE | 子系统 | 修复 commit | 本机状态 | 判据 |
| --- | --- | --- | --- | --- |
| CVE-2026-98260 | Timer | `acb03d388181` | ❌ 已修复 | `begin_new_exec` 内含 `posix_cpu_timers_exit`+`exit_itimers`+`flush_itimer_signals` |
| **CVE-2026-98256** | **Signal** | `d2710c8d938a` | ✅ **未修复** | `release_task` 仍调 `flush_sigqueue`（0x…303784），`exit_signals` 内**没有**任何 `flush_*` 调用 |
| **CVE-2026-80775** | **Futex** | `bde023808364` | ✅ **未修复** | `futex_hash_allocate` 在 `pcpu_alloc` 之后是裸 `str x0,[x19,#0x140]`，**没有 cmpxchg** |
| CVE-2026-89754 | MM | `aedf2efd1897` | ⚠ 未定论 | 本机 pagewalk 已改用 maple tree（`mas_find`/`should_skip_vma`），与补丁形态差异过大，逐指令比对成本高 |
| CVE-2026-98385 | Scheduler | — | N/A | 仅影响 7.2 系列 |
| CVE-2026-97941 | SLAB | — | N/A | 仅影响 7.2 系列 |

## 证据一：CVE-2026-98256（Signal）未修复

修复语义（`d2710c8d938a` "signal: Prevent exec() race"）：
把 `task::pending` 的冲洗从 `release_task()` **提前到 `exit_signals()`**，
并在 `__send_signal_locked()` / `posixtimer_send_sigqueue()` 里用 `PF_EXITING` 挡住新入队。

本机反汇编：

```
release_task:
  ffffffc0801ff7e8:  bl 0xffffffc080303784 <flush_sigqueue>     ← 还在旧位置
  fffffc0801ff8d0:   bl 0xffffffc080303784 <flush_sigqueue>     ← 两次

exit_signals:                                                    ← 无任何 flush_* 调用
  ... _raw_spin_lock_irq / retarget_shared_pending / task_participate_group_stop ...
```

→ **旧顺序，未修复。**

## 证据二：CVE-2026-80775（Futex）未修复

修复语义（`bde023808364`）：`futex_hash_allocate()` 用 **cmpxchg** 发布
`mm->futex.phash.ref`，输的一方 `free_percpu()` 自己的计数器。

本机反汇编：

```
ffffffc0802b6c10:  cbnz x8, ...            ; mm->futex.phash.ref 已存在就跳过
ffffffc0802b6c28:  bl   pcpu_alloc_noprof
ffffffc0802b6c2c:  str  x0, [x19, #0x140]  ; ← 裸 store，直接发布，没有 cmpxchg
```

→ **无 cmpxchg，未修复。**

## 附带成果：k_itimer 的 arm64 布局（从 `posixtimer_deliver_signal` 反推）

Signal 链（PoC 第 4 阶段）需要伪造 `k_itimer`，本机实测布局：

| 字段 | 偏移 | 反汇编依据 |
| --- | --- | --- |
| `sigq`（嵌入的 `kernel_siginfo`） | **0x88** | `sub x19, x1, #0x88` |
| `it_lock` | 0x40 | `sub x21, x20, #0x48` |
| `it_status` | 0x44 | `ldur w8,[x20,#-0x44]; cmp #2` |
| `it_signal_seq` / `it_sigqueue_seq` | 0x60 / 0x64 | `ldp w8,w9,[x20,#-0x28]` |
| `it_interval` | 0x68 | `ldur x8,[x20,#-0x20]` |
| `kclock` | 0x38 | `ldur x8,[x20,#-0x50]` |
| `kclock->timer_rearm` | kclock+0x50 | `ldr x8,[x8,#0x50]; blr x8` |

**关键障碍**：`blr x8` 之前有 kCFI 校验

```
ldur  w16, [x8, #-4]        ; 取目标函数前的类型哈希
movk  w17, #0x33a3
movk  w17, #0x9ce4, lsl #16 ; 期望值 0x9ce433a3
cmp   w16, w17
b.eq  ok
brk   #0x8228               ; 不匹配 → 崩
```

→ 伪造的 `timer_rearm` 必须指向类型哈希为 `0x9ce433a3` 的地址，
不能像 x86 那样随便跳到 gadget。**这是 arm64 移植的核心难点。**

## 本机可用符号（静态地址，运行时需加 slide）

```
commit_creds              0xffffffc0802b667c
init_cred                 0xffffffc0826d2a50
posix_timer_fn            0xffffffc0802401f4
posixtimer_deliver_signal 0xffffffc0803a6d1c
dequeue_signal            0xffffffc0803a6a190
```

## 下一步（实际工程）

1. **优先 Signal 链**：触发器（非 leader 线程 exec）我们已有成熟框架；
   需要解决 kCFI 那一步——在 `kernel.elf` 里搜索 `*(u32*)(X-4) == 0x9ce433a3`
   且 X 处代码能完成 `commit_creds(init_cred)` 的地址。
2. 若 CFI 走不通：改用 UAF 阶段自带的原语（`list_del` 的任意写），
   绕开间接调用。
3. 备选 Futex 链：无 CFI 障碍，但 PoC 167 KB，堆喷策略要重做。

## 附件

`docs/infinitycore/` 下留档：
- `sig.c`（45 KB，Signal PoC 全文）
- `futex.c`（167 KB，Futex PoC 全文）
- `sig_readme.md`（Signal 链五阶段完整分析）
- `infinity.txt`（oss-security 原始披露，含全部引入/修复 commit）
