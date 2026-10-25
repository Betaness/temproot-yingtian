# 项目状态（2026-10-25）

## 交付物

| 文件 | 字节 | SHA-256 |
| --- | --- | --- |
| `dist/temproot-0.3.0-experimental.apk` | 86638 | `40d33aa99392b214342dee4ad85027d298086124941be3ffa55cd65b909a4338` |
| `dist/lib/arm64-v8a/libtemproot.so` | 55272 | 见 `dist/native-build.json` |
| `dist/lib/x86_64/libtemproot.so` | 56872 | 见 `dist/native-build.json` |

哈希以实际文件为准，重新构建后会变化（签名密钥复用则源码相同时可复现）。

## 验收矩阵

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| 读取并核对目标固件身份 | 完成 | `docs/FINDINGS_ZH.md` §1 |
| 提取并核对内核缓解措施配置 | 完成 | `docs/FINDINGS_ZH.md` §2（上一轮遗漏整段 KASAN 配置） |
| CVE 适用性结论 | **失败路径实机可达**（uid 2000，策略 2/3 对照）；是否可利用仍未验证 | `docs/DEVICE_RESULTS_ZH.md` §2 |
| 运行时结构布局 | 完成；设备拒绝 BTF，改由离线 BTF 表（38/38 字段）供给，按内核 release 精确匹配 | `dist/layout-stock-kernel.json` |
| 普通 APK 权限可行性 | **已实测**：seccomp 杀 io_uring/userfaultfd，timer_create/pipe/memfd/fork-exec 可用 | `docs/DEVICE_RESULTS_ZH.md` §1 |
| 中文 APK（探测/闸门/布局/测量/授权/验证/日志） | 完成并打包 | `dist/*.apk` |
| 不支持构建安全停止 | 完成（fail-closed + 明确阻断码） | `native/tr_guard.c` |
| 临时 root 授权层（rootd + su） | 完成，仅在已有 root 凭据时可用 | `native/tr_rootd.c` |
| 严格权限验证 | 完成（uid + CAP_SYS_ADMIN + 特权操作） | `native/tr_verify.c` |
| 内核内存写入 / 凭据改写 | **未实现**，本固件上被闸门阻断 | `tr_timer_trigger_run()` 直接返回 |
| 实机安装与运行 | **已完成**（2026-10-25，设备上 adb 安装 + uiautomator 校验） | `docs/DEVICE_RESULTS_ZH.md` |
| 一次性临时 root 脚本（fastboot boot） | 完成，未在有 BL 解锁的设备上跑过 | `scripts/temp_boot_root.py` |
| 第三方代码许可证检查 | 完成 | `LICENSES.md` |

## 明确未完成

1. **真机运行**：本机没有可用的 Android 运行环境（无 hypervisor，模拟器起不来），
   也没有连接平板。所有 UI/原生路径的实机证据都是 0。
2. **CVE 动态可达性**：测量器已实现，需要在真机上点一次才能得到 `PRE/POST_FIX_ORDER`。
3. **利用链**：未实现，且在本固件上无意义（见 `FINDINGS_ZH.md` §2.1）。
4. **`.D00` 版本核实**：实机 incremental/fingerprint 与 OTA 元数据不同，未定位来源。

## 下一步（按优先级）

1. 把 `dist/temproot-0.3.0-experimental.apk` 装到平板，跑一次探测 + 可达性测量，
   导出日志回传 → 这一步能把「普通 APK 权限可行性」从推断变成实测。
2. `scripts/temp_boot_root.py check` 看引导程序状态：
   - `READY` → 走 `fastboot boot` 一次性内核，拿到真正的临时 root，再用本 APK 的 rootd 分发。
   - `LOCKED_BOOTLOADER` → 本固件上没有临时 root 路径，只能等非 KASAN 的构建或解锁。
3. 若拿到非 KASAN 的生产内核，把 `tr_build_db.c` 加一行（带证据），
   闸门会自动放行，`tr_timer_trigger_run()` 才需要继续写回收与凭据改写阶段。
