# 结论：CVE-2026-98260 在本机内核上已被修复（2026-10-26 05:00）

## 决定性证据

反汇编本机内核（`kernel.elf`，符号表 `nm.txt`）中的 `begin_new_exec`
（`0xffffffc0802cf910`）：

```
ffffffc0802cfca4:  bl  exec_task_namespaces          ← de_thread 之后的命名空间处理
ffffffc0802cfca8:  cbnz w0, <error path>
ffffffc0802cfcac:  ldr  x0, [x20, #0x968]
ffffffc0802cfcb0:  bl  _raw_spin_lock_irq
ffffffc0802cfcb4:  mov  x0, x20
ffffffc0802cfcb8:  bl  posix_cpu_timers_exit        ← ★ 修复代码
ffffffc0802cfcbc:  ldr  x0, [x20, #0x968]
ffffffc0802cfcc0:  bl  _raw_spin_unlock_irq
ffffffc0802cfcc4:  mov  x0, x20
ffffffc0802cfcc8:  bl  exit_itimers                 ← ★ 修复代码
ffffffc0802cfccc:  bl  flush_itimer_signals         ← ★ 修复代码
```

还原成 C 就是：

```c
spin_lock_irq(&tsk->sighand->siglock);
posix_cpu_timers_exit(tsk);
spin_unlock_irq(&tsk->sighand->siglock);
exit_itimers(tsk);
flush_itimer_signals();
```

这段代码的位置（`de_thread`/`exec_task_namespaces` 之后、`exec_mmap` 之前）
与调用集合，**正是上游修复 `acb03d388181`
（"exec: Cleanup POSIX timers right after de_thread"）的形态**。

## 这意味着什么

本机内核版本号是 `6.18.21`，而该修复号称在 `6.18.54` 才进入上游——
但 **厂商（小米/联发科）把这条安全补丁后向移植了**。Android 厂商对 CVE 做
backport 是常规操作，版本号停留在 6.18.21 不代表缺少这条修复。

**结论：CVE-2026-98260 在 `M367FC / yingtian / 6.18.21-android17` 上不可利用。**

## 这解释了此前所有实验现象

| 现象 | 解释 |
| --- | --- |
| 能稳定触发（tid 交换杀手 8/8） | 触发机制本身是对的 |
| 能确认受害页被释放、被我们抢到（`owned=1`） | 分配器层面的操作都成立 |
| **reap 永远不 panic、毒指针从不被写** | **因为根本没有悬挂节点**——定时器在 `exec_mmap` 之前就被干净清掉了 |
| `enforce` 永远是 1 | 写原语从未执行 |

不是 payload 不对、不是节点偏移不对、不是锁争用不对，是**漏洞本体不存在**。

## 对"临时 root"目标的影响

这条 CVE 路线到此为止。要继续做临时 root，需要换一个**在本机构建上确实未修复**的
内核漏洞，或者走非内核路线（厂商服务/调试接口/官方解锁通道）。

判断一个 CVE 是否值得投入的第一步，应当固定为：

```
反汇编目标内核 → 找到该漏洞关键函数 → 确认修复代码不存在
```

这一步只要几分钟，能省掉整条链的无效施工。这次我把它放在了最后，是本项目最大的方法错误。
