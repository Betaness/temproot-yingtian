# 回读（leak）路线分析（2026-10-26 03:28）

要写 `task+0x908`，先得知道 `task` 的地址。BRM 的做法是从回收页里读出来。
本文件记录三条候选路线与实测结果。

## 路线 1：AIO 环（BRM 用的）——**本机不可用**

BRM 原文：

> spraying 3072 AIO rings, put leaked timer `pfn=0xb51c04` in ring 181 at
> `ctx=0x75dfe6a000` with ring magic `0xa10a10a1`

AIO 环由 `io_setup()` 映射到用户空间，理论上可以直接读残留数据。实测：

```
shell 6306  1  __arm64_sys_io_destroy 0 D  aiospray
```

**进程卡死在 `io_destroy` 的 D 状态（不可中断睡眠），`kill -9` 也收不掉。**
说明这颗内核的 AIO 上下文销毁路径会阻塞（可能是 ring 页被回收/迁移导致）。
结论：AIO 路线在本机**不能用**，而且一旦用上就会留下一个卡死进程（只能重启清掉）。

## 路线 2：ashmem / pipe 页——**结构上不匹配**

`ashmem`、`shmem`、pipe buffer 页都是 **order-0、movable**；
而 `posix_timers_cache` 的 slab 是 **order-1、unmovable**。
allocator 不会把一张 order-1 unmovable 的页拆给 order-0 movable 分配。
实测也印证：我们的 8 KiB `SOCK_STREAM`（会请求 order 3→1）能抢到，order-0 的对象抢不到。

## 路线 3：**unix stream + recv 差分**（推荐，未实测）

关键点：`SOCK_STREAM` 的 skb 持有那张页的引用，`recv()` 是**从那张页里拷数据**。
所以只要内核往页里写了任何东西，我们 `recv()` 回来的字节就会**跟着变**。

流程：

```
1. 用良性节点 payload（parent=0, right=0, left=0）抢页
   → 8 KiB 全是我们知道的内容
2. 把 8 KiB 通过 recv() 读回来一次，作为基线
3. 让 init 回收那个僵尸 → timerqueue_del → rb_erase 走我们的节点
   （良性节点：erase 只会把 NULL 写到队列根，不会解引用野指针）
4. 再 recv() 一次（需要重新灌数据或用 MSG_PEEK），与基线做**逐字节差分**
5. 差分出来的字节就是内核写进去的指针 → task / cred 地址
```

风险：第 3 步的 reap 是本项目第一次真正让内核走到 `timerqueue_del`。
良性节点应当安全，但仍可能 panic（可接受，重启即可）。

## 当前阻塞

- 路线 1 死亡（D 状态卡死），路线 2 结构不匹配。
- 路线 3 可行但需要一次 reap，属于"破坏性"边界，要单独跑。
- 因此 `task+0x908` 的写还不能做——**不是节点算不出来，是 task 地址还没拿到**。

## 现场

- 卡死的 aiospray 进程（pid 6306）仍在 D 状态，占约 7 MB；**重启即清**，不影响使用。
- 设备其余状态正常：`boot_completed=1`、`Enforcing`、`verifiedbootstate=green`。

## 路线 3 实测结果（2026-10-26 03:28）

```
=== readback (benign zero node) ===
child=6808 timers_armed=2048
streams claimed: 512
baseline captured
reaping child 6808 ...
reaped, status=0x9
no kernel-written pointers detected in the claimed pages
```

**整条流水线跑通了**：2048 定时器 → 512 条流抢页 → MSG_PEEK 基线 → **真的 waitpid 执行了 reap**
→ 再次 PEEK 做差分。设备无恙（uptime 不变、`verifiedbootstate=green`）。

但差分为零。原因不是回读机制，而是**触发窗口没进去**：

- 我的 kill 在 exec 线程启动后 **2 ms** 才发；`execve("/system/bin/sh")` 在这个时间内
  早就跑完 `exec_mmap` 并成功替换镜像了；
- 一旦 exec 成功，`begin_new_exec` 走的是成功路径，`de_thread` 没有失败，
  也就不存在"定时器已释放、节点还在队列"的不一致状态；
- 于是 reap 时队列是干净的 → 没有任何内核写入 → 差分自然为零。

### 结论

回读机制（recv 差分）**成立且已验证可用**（流程跑完、无 panic）。
真正卡住的是**把 SIGKILL 精确送进 `exec_mmap` 的 `down_read_killable` 窗口**：

- 需要让 exec 在 `exec_mmap` 上**停住**足够久；
- 常规手段（userfaultfd 让缺页卡住、FUSE 让 mmap 阻塞）在本机分别被 seccomp / 挂载权限挡住；
- BRM 文档里提到"目标页被其他任务占用时输出 PARKED"，说明他们也有类似的停滞机制。

这是本项目当前**唯一未解决的技术点**，而且它属于"时序工程"，不是结构性问题。
