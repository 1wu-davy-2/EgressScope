# 更新日志

每个 `v*` 标签的 GitHub Release 会自动携带本文件中对应版本的说明。

## v0.3.2

- 关机 / 注销恢复修复：此前的钩子有两处实现错误——窗口类引用了 `ctypes.wintypes` 中不存在的 `HCURSOR`，窗口实际从未创建；即使创建，消息专用窗口也不属于顶层窗口且消息泵跑在另一个线程，收不到 Windows 的会话结束通知。GUI 构建因此无法执行关机恢复。
- 现在的实现：在独立消息线程上创建隐藏的顶层窗口并注册 `WM_QUERYENDSESSION` / `WM_ENDSESSION`；恢复前调用 `ShutdownBlockReasonCreate`，让 Windows 在写回代理期间显示等待原因，完成后立即释放。控制台构建同时修复 `SetConsoleCtrlHandler` 的缺失导入。
- 回归测试：新增隐藏窗口、顶层属性、`WM_QUERYENDSESSION` 与 `WM_ENDSESSION` 回调检查；Windows 上 `tests/recovery_test.py` 47 项全部通过。
- 发布流水线修复：`publish` job 增加仓库 checkout，才能读取标签对应的 `CHANGELOG.md` 提取版本说明；说明文件不可用时回退为通用提示，不再阻断 Release 创建。

**English**

- Shutdown/logoff restore fix: the previous hook had two implementation errors — the window class referenced `ctypes.wintypes.HCURSOR`, which does not exist, so the window was never created; and even if it had been, a message-only window is not top-level and its message pump ran on a different thread, so Windows never delivered the session-end notification. GUI builds therefore could not restore the proxy at shutdown.
- The guard now creates a hidden top-level window on its own message thread and handles `WM_QUERYENDSESSION` / `WM_ENDSESSION`; it calls `ShutdownBlockReasonCreate` while the proxy is being written back and releases the block immediately afterwards. The console handler now imports the types it uses.
- Regression coverage: hidden-window, top-level, `WM_QUERYENDSESSION` and `WM_ENDSESSION` callback checks; `tests/recovery_test.py` passes 47 checks on Windows.
- Release pipeline fix: the publish job now checks out the repository so it can read the tagged `CHANGELOG.md`; if the notes are unavailable it falls back to a generic line instead of blocking the release.

## v0.3.1

- 配置热更新修复：改为按文件内容摘要判断变更，在修改时间精度较低的文件系统上或快速连续编辑时也能可靠生效。
- 配置写入保护：外部编辑出现非法 JSON、文件暂时不可读或被删除时，保留当前设置并在控制台、Web 审计台标红提示，不再静默回退默认值。
- 回归测试：新增非法配置、删除配置与修改时间不变三类检查，`tests/recovery_test.py` 当前 43 项全部通过。

**English**

- Hot reload fix: edits are now detected by content digest, so they are still adopted on filesystems with coarse modification timestamps or during rapid consecutive edits.
- Config safety: malformed JSON, a temporarily unreadable file or a deleted file keeps the current settings and is surfaced in the desktop console and web console instead of silently resetting to defaults.
- Regression coverage: added malformed, deleted and unchanged-mtime config checks; `tests/recovery_test.py` now has 43 passing checks.

## v0.3.0

- 关机 / 注销优雅恢复：Windows 关机或注销时自动把系统代理恢复为启用前的设置（消息窗口与控制台双通道），与启动校正、看门狗、手动恢复共同组成四层断网保护。
- 默认开机自启：首次运行为当前用户注册 `Run` 键自启；可在控制台一键关闭，或运行 `EgressScope.exe --disable-autostart`。
- 断网保护默认注册：启用系统代理时默认勾选看门狗（登录时 + 每 2 分钟检查，代理停止后自动恢复原始代理），可取消。
- 配置热更新：控制台、Web 审计台或直接编辑配置文件都会在 2 秒内生效，无需重启程序；上游代理变更会自动重连本地代理并重新校准系统代理。
- 默认开启全部观察能力：流量采集、AI 端点识别、敏感数据规则与文件句柄抽样（Beta）默认开启；风险阻断与 Canary 诱饵文件仍需显式开启。
- 发布说明：每个打包 tag 的 Release 正文自动取自本文件对应版本章节。

**English**

- Graceful restore at shutdown and logoff: the system proxy is put back before the Windows session ends (message-only window plus console ctrl handler), forming a four-layer fail-safe together with startup reconciliation, the watchdog and manual restore.
- Logon autostart by default: the first run registers a per-user `Run` key entry; turn it off in the console or with `EgressScope.exe --disable-autostart`.
- Fail-safe watchdog on by default: the confirmation dialog for enabling the system proxy has it checked (logon plus every 2 minutes, restores the original proxy once ours stops); you can uncheck it.
- Live config reload: console toggles, web console toggles and direct edits to the config file are adopted within 2 seconds without a restart; an upstream proxy change reconnects the local proxy and re-reconciles the system proxy.
- Observation on by default: capture, AI endpoint detection, sensitive-data rules and file-handle sampling (Beta) start enabled; risk blocking and Canary decoy files still require an explicit opt-in.
- Release notes: the Release body of every packaged tag is taken from the matching section of this file.

## v0.2.0

- 断网保护：启动时校正过期的系统代理设置；可选的每用户计划任务看门狗在登录后自动恢复原始代理；新增 `--restore-proxy` / `--recover-proxy` 手动恢复命令。
- 官网重写为白底企业风格，支持中英切换，新增断网保护章节、六平台下载矩阵与 FAQ；`tests/site_check.py` 静态门禁进入 CI。
- 六平台原生构建（Windows x64/ARM64、Linux x64/ARM64、macOS x64/ARM64）与 SHA-256 校验文件。

## v0.1.1

- 补齐六平台发布矩阵；Windows ARM64 在 ARM runner 上原生构建并做打包验收。

## v0.1.0

- 首个可用闭环：嵌入式本地代理、本地 CA、TLS 内容还原、PID 归因、AI 端点与敏感数据规则、风险评分与阻断、AES-256-GCM 加密证据与 SHA-256 哈希链、桌面控制台与本机 Web 审计台。
