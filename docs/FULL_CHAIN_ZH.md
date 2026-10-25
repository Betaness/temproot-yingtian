# 全链打通到最后一步（2026-10-26 04:45）

## 现在的流程（`scripts/harness/final.c`）

```
phase 1  子进程就绪：50000 VMA + 3 个 fork 型 locker + killer + exec 线程
phase 2  父进程开 kmem_cache_alloc trace，放行定时器武装
phase 3  1024 个定时器武装完成、exec tid 已知；
         父进程从 trace 里采出第 512 个 k_itimer 地址 → victim（精确到字节）
phase 4  放行 exec；同时喷流已经在跑（6000 × 8 KiB socket 记录）
         killer 在 tid 交换瞬间 SIGKILL
         等 trace 里出现 mm_page_free: victim_pfn  → 受害页真的被释放
         等 trace 里出现 mm_page_alloc: victim_pfn → 这一页现在归我们
reap     waitpid → release_task → 走 timerqueue_del
```

## 实测

```
round 0: allocations=1024 victim=0xffffff903577d380  pfn=0x103577c
         page_freed=1   sockets=6000  victim_page_owned=1
         REAPED (status=9)   enforce=1
round 1: 同上（victim_page_owned=1）
设备：uptime 2355s、Enforcing、green、无 panic
```

**我们第一次做到了：知道受害对象地址 → 确认它那一页被释放 → 确认那一页被我们抢到 → 在那张页上 reap。**

## 但毒指针依然没被写

payload 用的是 `0x4141414141414141`（必然非法），如果 `rb_erase` 走到我们的节点，
必然 panic。**没有 panic。**

结论：**队列里没有悬挂节点** —— `exit_itimers` 把定时器干净地摘掉了，
`release_task` 没有可走的东西。CVE-2026-98260 要求的那个不一致状态，
在当前这套 trigger 下没有产生。

## 剩下的可能性

1. kill 落点仍然不对：`exchange_tids` 在 `de_thread` 里，而 `exec_mmap` 在其后；
   fork 型 locker 虽然把 `mmap_write_lock` 握住了 27ms，但 exec 线程可能卡在别处。
2. 本机内核 `6.18.21` 与参考实现的目标版本（`6.18.30`）在 `begin_new_exec` 的
   清理顺序上可能已经不同（虽然修复 `acb03d388181` 号称在 6.18.54 才进）。
3. 参考实现的 `one_uaf` 里还有别的串联动作（`hold_aio_children`、`drain_pipes`、
   `drain_socks`），我只复刻了主流路径。

## 已经确定可复用的资产

| 组件 | 状态 |
| --- | --- |
| slide 测量（阻塞读版） | ✅ 62 票 |
| 受害地址采集（字节扫描） | ✅ 1024/1024 |
| 页释放/分配 PFN 验证 | ✅ |
| 触发（tid 交换杀手） | ✅ 稳定 |
| reap 不崩 | ✅ 数十次 |
| 全链编排（phase 握手） | ✅ |
