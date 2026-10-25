# 更新日志

每个 `v*` 标签的 GitHub Release 会自动携带本文件中对应版本的说明。

## Unreleased

- 许可协议：新增 PolyForm Noncommercial License 1.0.0。允许个人与非商业组织下载、使用、修改和非商业分发，禁止商业用途；分发需保留许可证与 `Required Notice`。严格来说这是 source-available，而不是 OSI 开源。安装器、安装目录与 GitHub Release 资产都会携带 LICENSE。
- License: adopted the PolyForm Noncommercial License 1.0.0. Individuals and noncommercial organizations may download, use, modify and redistribute it for noncommercial purposes; commercial use is prohibited. Redistribution must retain the license and the Required Notice. This is source-available, not OSI open source. The installer, installed files and GitHub release assets include the LICENSE.

## v0.4.0

- 安装包：新增 Windows x64 的 per-user 安装包 `EgressScope-Setup-v0.4.0.exe`。无需管理员权限，固定安装到 `%LOCALAPPDATA%\Programs\EgressScope`；可选桌面快捷方式（默认不勾选），开始菜单提供主程序与“恢复系统代理”（`--restore-proxy`）快捷方式。卸载时移除开机自启并恢复系统代理；静默安装/升级保留审计数据，交互式卸载会先询问是否删除 `%LOCALAPPDATA%\EgressScope`。Windows ARM64 不提供安装包，继续使用便携版。当前 EXE 与安装包默认未签名；只有仓库所有者配置 `WINDOWS_CERT_PFX_BASE64` / `WINDOWS_CERT_PASSWORD` 后，CI 的可选 signtool 步骤才会签名。
- 更新检查与安装：新增 GitHub Releases 更新检查，默认开启；启动 30 秒后检查，之后每 24 小时一次，结果缓存 6 小时，手动检查强制刷新。自动下载并安装仅支持 Windows x64，且要求发布中存在 `EgressScope-Setup-v<latest>.exe` 与 `.sha256` 或 `SHA256SUMS.txt`；只接受 HTTPS 与 GitHub 域名，必须通过 SHA-256 校验，失败即删除下载文件。安装以 `/SILENT /NORESTART /CLOSEAPPLICATIONS` 运行；应用先恢复系统代理并退出。Windows ARM64、Linux、macOS 可以检查，但只能手动下载。设置项 `update_check_enabled`、`--check-update`、状态 API 与控制台均可查看/控制。
- 集成自愈：启动时和每 10 分钟调用 `system.repair_integrations`，在程序被移动或覆盖升级后把当前用户 Run 键重新指向当前可执行文件，并在看门狗脚本/计划任务缺失时重新注册；不会覆盖其他程序的自启项。新增 `--repair-integrations` 手动修复命令；独立 `--restore-proxy` 不启动审计也能恢复系统代理。启动与端口变化时仍会把指向旧端口的系统代理改指当前监听端口。
- 可见性分级：每条流量标记 `full`（完整）、`partial`（部分）、`metadata`（仅元数据）、`blocked`（已阻断，界面显示“已拦截”）或 `error`（错误），并附中文原因。CONNECT 隧道与 TLS 握手失败（可能是证书固定、mTLS 或客户端拒绝本地 CA）只记录为仅元数据，不再伪装成完整记录；WebSocket 为部分（消息正文不持久化）；正文缺失/超限与请求正文不完整会降级。旧数据库的历史流量迁移为 `partial` 并标注“升级前的历史记录未做可见性分级”。仪表盘、API 与导出均包含等级/原因。
- 旁路与协议观测（Beta）：默认开启 `network_watch_enabled`，每 15 秒用 psutil 读取本机连接表，将公网直连 TCP 80/443/8080/8443 记为 `direct_tcp` 候选、UDP 443 记为 `quic` 候选、TCP/UDP 53 与 TCP 853 记为 `dns` 目标；Windows 解析缓存用于 IP→域名，DNS 查询内容从不记录。10 分钟去重、单次扫描/单日上限，并复用现有 PID 归因；覆盖页与状态卡展示计数/事件。此功能只做检测：不重定向、不拦截、不安装驱动、不解密 QUIC；直连/QUIC 只是候选而不是证明，暂停采集时同步暂停观测。WFP/WinDivert 透明重定向仍未实现。
- Windows 托盘：新增 pystray 0.19.5 + Pillow 12.3.0 的通知区域图标（仅 Windows）。关闭窗口会隐藏到托盘，首次隐藏显示气泡；菜单包含打开控制台、打开审计仪表盘、暂停/恢复审计、退出并恢复系统代理。暂停复用 `capture_enabled` 并暂停旁路观测；退出走正常关停流程。开机自启在托盘可用时隐藏启动；`--no-tray` 可禁用；依赖缺失或非 Windows 时保持原有“关闭即退出”行为。托盘在 Windows x64 上做过人工冒烟验证，未在 ARM64 Tk UI 验收，也不由打包 CI 的 UI 测试覆盖。
- 关机实验工具：新增 `tools/shutdown_lab.ps1`，提供 prepare/verify 两阶段、注册表快照/恢复与必须显式传入的 `-ConfirmReboot`。它是可选的一次性虚拟机实验工具，本版未在 CI 或真实虚拟机执行重启/关机/注销；关机钩子只有契约测试，不构成真实重启验证。
- 测试与 CI：新增 `tests/updater_test.py`（52 项）、`tests/visibility_test.py`（42 项）、`tests/netwatch_test.py`（69 项）、`tests/tray_test.py`（67 项，含 6 项需要 Pillow 的图标渲染检查）；`tests/smoke_test.py` 61 项、`tests/recovery_test.py` 78 项、`tests/upstream_test.py` 15 项。CI 运行上述套件与 `tests/site_check.py`（官网门禁另行同步）。

**English**

- Installer: added a per-user Windows x64 installer, `EgressScope-Setup-v0.4.0.exe`. It requires no administrator rights and installs to the fixed directory `%LOCALAPPDATA%\Programs\EgressScope`; the desktop shortcut is optional (unchecked by default), and Start-menu shortcuts cover the app and `--restore-proxy`. Uninstall removes autostart and restores the system proxy; silent install/upgrade keeps audit data, while interactive uninstall asks before deleting `%LOCALAPPDATA%\EgressScope`. Windows ARM64 has no installer and keeps using the portable EXE. The current EXE and installer are unsigned unless the repository owner configures `WINDOWS_CERT_PFX_BASE64` / `WINDOWS_CERT_PASSWORD`, which enables the optional signtool steps in CI.
- Update checking and install: added GitHub Releases update checks, enabled by default. A background check runs 30 seconds after startup and then every 24 hours, results are cached for 6 hours, and a manual check force-refreshes. Automatic download and install is Windows x64 only and requires `EgressScope-Setup-v<latest>.exe` plus either a `.sha256` asset or `SHA256SUMS.txt`; only HTTPS GitHub-owned hosts are accepted, a SHA-256 match is mandatory, and a failed download is deleted. The installer runs with `/SILENT /NORESTART /CLOSEAPPLICATIONS`; the app restores the system proxy and exits first. Windows ARM64, Linux and macOS can check but must download manually. The `update_check_enabled` setting, `--check-update`, the status API and the console expose this state.
- Self-healing integrations: `system.repair_integrations` runs at startup and every 10 minutes. After the app is moved or replaced by an upgrade it repoints the per-user Run key at the current executable and reinstalls the watchdog script/task when missing; foreign autostart values are never overwritten. Added `--repair-integrations` for a manual repair. Standalone `--restore-proxy` still works when the app is not running. Startup and port changes also repoint a system proxy that still references an old port.
- Visibility classification: every flow is labelled `full`, `partial`, `metadata`, `blocked` (shown as “已拦截” in the UI) or `error`, with a Chinese reason. CONNECT tunnel and TLS handshake failures (possibly certificate pinning, mTLS or a client rejecting the local CA) are recorded as metadata-only rows instead of fake full records; WebSocket is partial because messages are not persisted; missing/oversized bodies and incomplete request bodies downgrade the flow. Historical flows in old databases migrate to `partial` with an explicit “not classified before the upgrade” reason. The dashboard, API and exports expose the level and reason.
- Bypass and protocol observation (Beta): `network_watch_enabled` is on by default. Every 15 seconds psutil samples the local connection table and records public direct TCP 80/443/8080/8443 as `direct_tcp` candidates, UDP 443 as `quic` candidates, and TCP/UDP 53 plus TCP 853 as `dns` targets. The Windows resolver cache supplies IP-to-domain names; DNS query content is never recorded. Events are deduplicated for 10 minutes, capped per scan/day, attributed through the existing PID resolver, and shown on the coverage page and status cards. This is detection only: it never redirects or intercepts traffic, installs no driver and does not decrypt QUIC. Direct/QUIC events are candidates, not proof, and pausing capture also pauses observation. WFP/WinDivert transparent redirection is still not implemented.
- Windows tray: added a notification-area icon using pystray 0.19.5 and Pillow 12.3.0 (Windows only). Closing the window hides it to the tray and the first hide shows a balloon. The menu offers open console, open audit dashboard, pause/resume audit, and exit with system-proxy restore. Pause uses the same `capture_enabled` setting and also pauses bypass observation; exit follows the normal shutdown path. Autostart starts hidden when the tray is available; `--no-tray` disables it; without the dependencies or on non-Windows, closing keeps the previous exit behavior. The tray was manually smoke-tested on Windows x64, is not exercised on the ARM64 Tk UI, and is not covered by packaged CI UI tests.
- Shutdown lab: added `tools/shutdown_lab.ps1` with prepare/verify phases, registry snapshot/restore and an explicit opt-in `-ConfirmReboot`. It is an optional one-shot VM harness only; this release did not execute a real reboot, shutdown or logoff in CI or on a VM. The shutdown hook has contract tests, which are not a real-reboot validation.
- Tests and CI: added `tests/updater_test.py` (52), `tests/visibility_test.py` (42), `tests/netwatch_test.py` (69) and `tests/tray_test.py` (67, including 6 Pillow-dependent icon-rendering checks); `tests/smoke_test.py` is now 61, `tests/recovery_test.py` 78 and `tests/upstream_test.py` 15. CI runs these suites plus `tests/site_check.py` (the site gate is synced separately).

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
