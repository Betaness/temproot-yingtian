# 拿到受害对象的精确地址（2026-10-26 04:30）

## 缺的那一环

参考实现的 `one_uaf()` 里有一行我一直没看到：

```c
if (collect_nth(1024, &nptr, &victim)) { ... }
```

`collect_nth` 在子进程武装 2048 个定时器的**同时**开着 `kmem_cache_alloc` 的 trace，
把每一次 `k_itimer` 分配的对象地址按顺序收集下来，取第 1024 个 ——
**那正是 armed 定时器的对象地址**。

有了它，回收就不再是盲喷，而是针对**那一张页**。

## 本构建的实现（`scripts/harness/victim.c`）

```
call_site = 0xffffffd6401a726c      = do_timer_create + 0x350
```

采集要点（照参考实现，但补了他没写的细节）：

1. 用 **阻塞读 + 线程** 抓 `per_cpu/*/trace_pipe_raw`（本机 `poll()` 已失效）；
2. **按字节扫描**找 call_site（按 8 字节步进会漏掉一半记录——我第一版就漏了，只抓到 434/1024）；
3. 校验三件事：`call_site` 匹配、`+24 == 0x180`（k_itimer 大小）、`ptr` 是内核地址且 8 字节对齐。

## 实测结果

```
k_itimer allocations seen: 1024
chosen(#512)   = 0xffffff83b07cf380     ← 受害对象
node (+0xe0)   = 0xffffff83b07cf460     ← 伪造节点地址
page base      = 0xffffff83b07cf000
page offset    = 0x380
```

## 这一下解决了两件事

1. **不再盲喷**：知道页基址，就能用 `mm_page_alloc` 的 PFN 精确判断"这一页有没有被我们抢到"；
2. **节点位置确定**：`victim + 0xe0`，且 `0x380 + 0xe0 = 0x460` 印证了
   `0x380 ≡ 8 (mod 24)` 的相位结论（此前我推的相位 8 是对的）。

## 下一步

把 `collect_nth` 接进 `join.c`：

```
1. 子进程武装定时器 → 父进程 collect_nth 拿 victim
2. 放行 exec（phase 4）→ 触发 SIGKILL
3. 喷流，用 mm_page_alloc 的 PFN 与 victim 页 PFN 比对
   · 命中 → 这一页现在归我们，节点内容就是我们写的
   · 未命中 → 重试（参考实现就是 "page miss, retry"）
4. 命中后才 reap，然后读 enforce
```
