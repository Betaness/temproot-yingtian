# 两个半成品，还差一次合体（2026-10-26 03:50）

## 已经各自跑通的两半

### A 半：trigger 时序（`scripts/harness/race.c`）

按参考实现的机制重写后：

```
=== race (tid-swap driven kill, 50000 VMAs) ===
  round 0: child killed by signal 9 after ~89ms
  round 1: child killed by signal 9 after ~95ms
  ...
race done: signalled=6/6
```

关键三点（此前 1100 次全错就错在这）：

1. **杀手用 `tgkill(tgid, 旧exec_tid, 0) == ESRCH` 判定窗口**，不是盲猜延时；
2. **2048 个定时器里只有 1 个 `SIGEV_SIGNAL`**（第 1024 个，`it_value=3600s` 只入队不触发），
   其余 2047 个 `SIGEV_NONE` 只是灌满 slab；
3. **50000 个 VMA + `mprotect` 死循环线程**制造 `mmap_lock` 争用。

### B 半：页回收（`--pressure-spray`）

```
order-1 frees=91   order-1 allocs=8670
交集: 86            ← 91 张被释放的页里 86 张被 8 KiB 流拿走
```

## 差的那一步

现在 `race.c` 里喷流是在**僵尸已经死掉之后**才发的（`spray_and_diff` 里先 spray 再 waitpid），
而 B 半的经验是：喷流必须**正好压在 `exit_itimers` 之后、`timerqueue_del` 之前**。

race.c 目前的实测：`signalled=6/6`、`diffs=0`、`enforce=1`——
说明 trigger 打中了，但**喷流没在窗口里拿到那张页**，所以 `rb_erase` 走的是干净队列。

## 合体方案（下一轮唯一任务）

```
1. race.c 里把 spray 提到 wait_zombie 之前（与 killer 并发）
2. 用 mm_page_free / mm_page_alloc 的 PFN 交集确认"这一轮确实抢到了受害页"
3. 只在 PFN 命中的那一轮才 waitpid（reap）；没命中的轮次直接放弃、不留僵尸
4. 命中后读 /sys/fs/selinux/enforce：变 0 就是写原语成立
```

第 3 条很重要：**没抢到页就不该 reap**，否则等于白送给内核一次干净回收，
还会把僵尸堆起来（这也是之前几次留下 D 状态/僵尸的原因）。

## 现场

- `signalled=6/6`、`diffs=0`、`enforce=1`（Enforcing 未变）
- load 3.13（已回落）、无遗留进程、`verifiedbootstate=green`
- 全程零 panic、零分区写入
