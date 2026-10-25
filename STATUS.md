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
| CVE 适用性结论 | 完成，结论为**该构建上不可利用**（KASAN+MTE+PANIC_ON_OOPS） | 同上 |
| 运行时结构布局 | 完成，31/31 字段由 BTF 现读，零硬编码 | `dist/layout-stock-kernel.json` |
| 普通 APK 权限可行性 | 已实现真实系统调用探测，**未在真机运行** | `native/tr_probe.c` |
| 中文 APK（探测/闸门/布局/测量/授权/验证/日志） | 完成并打包 | `dist/*.apk` |
| 不支持构建安全停止 | 完成（fail-closed + 明确阻断码） | `native/tr_guard.c` |
| 临时 root 授权层（rootd + su） | 完成，仅在已有 root 凭据时可用 | `native/tr_rootd.c` |
| 严格权限验证 | 完成（uid + CAP_SYS_ADMIN + 特权操作） | `native/tr_verify.c` |
| 内核内存写入 / 凭据改写 | **未实现**，本固件上被闸门阻断 | `tr_timer_trigger_run()` 直接返回 |
| 实机安装与运行 | **未执行** | `VALIDATION.md` §3 |
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
