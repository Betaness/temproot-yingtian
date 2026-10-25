# 毒指针实验：决定性的否证（2026-10-26 04:15）

## 方法

把平铺节点里的目标地址换成一个**必然非法**的指针 `0x4141414141414141`：

```
node[0]=0  node[1]=0  node[2]=0x4141414141414141
```

如果 reap 时 `rb_erase` 真的走到这个节点，它会对 `node[2]` 执行
`rb_set_parent_color(child, parent, RB_BLACK)`，即**往 0x4141414141414141 写 8 字节**
→ 立刻 oops → panic → 重启。

## 结果

```
tiling phase=8, target=0x4141414141414141
    order-1 frees=18   allocs=4096  claimed=8
  round 0: zombie status=9  sockets=6000
    REAPED (claimed) -> checking enforce
    enforce=1
    order-1 frees=1886 allocs=4096  claimed=61
  round 1..3: 同上
join done: killed=4/4 claimed=4
设备: uptime 1076s, Enforcing, verifiedbootstate=green   ← 无 panic
```

## 结论

**reap 从来没有碰到我们伪造的节点。**

因此 `enforce` 一直是 1，不是"payload 写得不对"，而是**CVE-2026-98260 要求的那个不一致状态
没有被制造出来**——队列里没有悬挂节点可走。

这条结论的价值：它一次性否掉了"调 payload / 调节点偏移 / 调目标地址"这一整条方向，
把所有注意力集中回 **trigger 到底有没有把定时器节点留在队列里**。

## 下一步的三个验证方向

1. **定时器是否真的入队并被处理**：把 armed 定时器的 `it_value` 从 3600 s 改短（如 1 ms），
   看 SIGRTMIN 是否投递。投递 = 队列路径通；不投递 = 根本没进去。
2. **kill 是否落在 exec_mmap 里**（而不是 de_thread 之后、exec_mmap 之前）：
   记录 exec 线程进入 execve 到被杀的时间差，以及 `mmap_lock` 争用线程当时的 mprotect 状态。
3. **换个观察量**：既然毒指针能给出"是/否"的二值信号，可以用它来做**参数扫描**
   （定时器数量、VMA 数量、locker 数量、kill 时机），只要出现一次 panic 就说明参数进了窗口。
