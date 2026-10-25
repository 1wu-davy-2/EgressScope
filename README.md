<p align="center">
  <img src="web/assets/icon-192.png" width="88" height="88" alt="EgressScope project icon">
</p>

<h1 align="center">EgressScope</h1>

<p align="center">
  <strong>本机数据外发审计</strong> · Local Egress Audit for AI Agents &amp; Desktop Apps
</p>

<p align="center">
  AI 审计 · Agent 审计 · AI Agent 审计 · 智能体审计 · 数据外发审计 · 数据防泄漏（DLP）· AI DLP · LLM / 大模型安全 · 出站流量审计 · HTTPS 审计 · 进程归因 · 影子 AI
</p>

<p align="center">
  <a href="https://1wu-davy-2.github.io/EgressScope/">官网 / Product site</a> ·
  <a href="https://1wu-davy-2.github.io/EgressScope/tech.html">技术实现 / Technical notes</a> ·
  <a href="https://github.com/1wu-davy-2/EgressScope/releases/latest">Releases</a> ·
  <a href="https://github.com/1wu-davy-2/EgressScope">GitHub</a>
</p>

项目名：**EgressScope**（中文：**本机数据外发审计**；仓库：[1wu-davy-2/EgressScope](https://github.com/1wu-davy-2/EgressScope)）。英文检索词：`AI agent egress audit`、`agent audit`、`AI DLP`、`data exfiltration`、`DLP for AI agents`、`shadow AI`、`LLM security`、`process attribution`。

- 官网 / 产品介绍页：<https://1wu-davy-2.github.io/EgressScope/>
- 技术实现与安全边界：<https://1wu-davy-2.github.io/EgressScope/tech.html>
- 发布版本与 SHA-256 校验：<https://github.com/1wu-davy-2/EgressScope/releases/latest>
- 当前版本：**v0.4.0**。Windows x64 提供 per-user 安装包与便携版；Windows ARM64 使用便携版；Linux / macOS 以命令行和 Web 审计台为主。

EgressScope 是一个以 Windows 为主的本机审计工具。它在用户明确授权的前提下，通过本地 HTTP/HTTPS 转发代理、本地 CA、进程归因和内容策略，回答一个传统流量面板经常回答不了的问题：

> **是谁，在什么时候，把什么内容，发到了哪里？**

它面向 AI Agent、IDE 插件、脚本运行时，也适用于其他需要观察数据外发行为的桌面应用。所有证据默认保存在本机，不依赖云端服务。

> 仅用于你拥有或已获明确授权的设备。不要在日常使用、存有真实凭据的设备上分析疑似恶意软件；受信 CA 会扩大本机可被中间人解密的范围。未知样本请在隔离虚拟机或快照中处理。详见[安全边界](#安全边界与使用约束)。

---

## 目录

- [交付内容](#交付内容)
- [快速开始](#快速开始)
- [安装、更新与集成自愈](#安装更新与集成自愈)
- [平台与 GitHub Actions](#平台与-github-actions)
- [它解决什么问题](#它解决什么问题)
- [架构与取舍](#架构与取舍)
- [风险引擎](#风险引擎)
- [可见性分级与覆盖范围](#可见性分级与覆盖范围)
- [旁路与协议观测（Beta）](#旁路与协议观测beta)
- [Windows 托盘与后台运行](#windows-托盘与后台运行)
- [数据与隐私设计](#数据与隐私设计)
- [项目结构](#项目结构)
- [开发、测试与构建](#开发测试与构建)
- [安全边界与使用约束](#安全边界与使用约束)
- [路线图与已知限制](#路线图与已知限制)

---

## 交付内容

| 产物 | 位置 | 说明 |
| --- | --- | --- |
| Windows per-user 安装包 | `EgressScope-Setup-v0.4.0.exe` | **仅 Windows x64**；无需管理员权限；固定安装到 `%LOCALAPPDATA%\Programs\EgressScope`；当前发布构建未签名，详见下方说明 |
| Windows 便携版 | `dist\EgressScope.exe`（本地构建）/ `EgressScope-v0.4.0-windows-x64.exe`、`EgressScope-v0.4.0-windows-arm64.exe`（发布页） | 单文件 GUI 程序；Windows x64 支持自动更新，Windows ARM64 需手动更新 |
| Linux / macOS | `EgressScope-v0.4.0-linux-x64.tar.gz` 等 | 审计引擎 + 本机 Web 审计台；没有 Windows 系统代理接管与托盘 |
| 静态产品介绍页 | `web\intro.html` | 能力优先的官网首页；启动程序后同样可通过 `/intro` 访问 |
| 技术实现文档 | `web\tech.html` | 数据路径、进程归因、可见性、旁路观测、断网保护、安装更新、数据安全与验证状态；启动程序后可通过 `/tech` 访问 |
| 本机审计台 | 启动后 `http://127.0.0.1:8898/` | 流量、发现、文件触达、覆盖范围、可见性统计、旁路观测与策略设置 |
| 桌面控制窗口 + Windows 托盘 | 可执行文件启动后的主窗口 / 通知区域 | 安装/移除 CA、启用/恢复系统代理、暂停采集、导出证据；Windows 上关闭窗口默认隐藏到托盘 |
| 构建校验清单 | `dist\SHA256SUMS.txt` | 本地构建的可执行文件 SHA-256；发布页另有每个产物的 `.sha256` 与汇总 `SHA256SUMS.txt` |
| GitHub Actions | `.github/workflows/` | CI 冒烟与回归、六平台发布构建、可选 Windows 签名、介绍页 Pages 部署 |
| GitHub Release | [releases/latest](https://github.com/1wu-davy-2/EgressScope/releases/latest) | Windows x64 安装包与 x64 / arm64 便携版、Linux x64 / arm64、macOS x64 / arm64；每个 tag 的发布说明取自 `CHANGELOG.md` 对应小节 |
| 版本更新说明 | `CHANGELOG.md` | 按版本记录变更；打包 tag 时由发布工作流自动截取对应小节写入 Release 正文 |
| 研究/执行计划 | `PLAN.md` | 本项目的技术与产品调研底稿 |

审计台固定访问 `http://127.0.0.1:8898/`（端口可在设置中修改）。`18898` 只是自动化测试临时使用的端口，不是产品默认端口；临时测试进程关闭后访问会被拒绝。

首次启动会在 `%LOCALAPPDATA%\EgressScope` 下生成数据目录、数据库和审计 CA。**不会自动安装根证书，也不会自动修改系统代理**；两者都需要在桌面控制窗口中显式确认。采集、AI 端点识别、敏感数据规则、文件句柄抽样、更新检查与旁路观测（Beta）默认开启；风险阻断与 Canary 诱饵默认关闭。首次启动会写入当前用户的开机自启（`HKCU\...\CurrentVersion\Run` 的 `EgressScope` 值），可在控制台、审计台设置或 `--disable-autostart` 撤销。Windows 托盘可用时，开机自启会隐藏启动到通知区域。

> 当前发布的 Windows 可执行文件与安装包默认未做 Authenticode 代码签名，Windows SmartScreen 可能显示“未知发布者”。只有仓库所有者配置 `WINDOWS_CERT_PFX_BASE64` / `WINDOWS_CERT_PASSWORD` 后，CI 的可选 `signtool` 步骤才会签名。请先核对发布页或 `SHA256SUMS.txt` 中的 SHA-256，再决定是否运行；不要从来源不明的渠道获取本程序。SHA-256 只能确认下载内容与发布页一致，不等同于发布者身份验证。

---

## 快速开始

### 方式一：Windows per-user 安装包（推荐，Windows x64）

1. 从 [Releases](https://github.com/1wu-davy-2/EgressScope/releases/latest) 下载 `EgressScope-Setup-v0.4.0.exe`，并核对发布页的 SHA-256。安装包**仅支持 Windows x64**；Windows ARM64 请使用便携版。
2. 双击安装。安装程序不需要管理员权限，固定安装到 `%LOCALAPPDATA%\Programs\EgressScope`，不会询问安装目录；可勾选创建桌面快捷方式（默认不勾选），开始菜单会创建 **EgressScope** 与 **恢复系统代理**（`--restore-proxy`）两个快捷方式。
3. 启动后首次运行会写入当前用户的开机自启。Windows 托盘可用时，登录自启会隐藏到通知区域，而不是弹出主窗口。
4. 在控制窗口中点击 **打开审计控制台**，先熟悉界面与当前覆盖状态。
5. 如需审计 HTTPS 正文，点击 **安装本地 CA（当前用户）**，确认 Windows 安全警告中的证书名为 `EgressScope Local Audit CA`。
6. 二选一接入流量：
   - **系统代理**：点击 **启用系统代理**。只影响遵循 WinINet / 系统代理设置的应用；正常退出、关机与注销时都会恢复原设置。确认对话框默认勾选 **注册断网保护看门狗（推荐）**，详见[系统代理的失败模式与断网保护](#系统代理的失败模式与断网保护)。
   - **单 Agent 环境变量**：点击 **复制 Agent 环境变量**，在启动目标 Agent 的终端先运行生成的脚本。影响范围更小，适合先验证一个 Agent 或 IDE 插件。
7. 如果本机原本通过 Clash、v2rayN 等本地 HTTP 代理上网，EgressScope 启动时会自动识别 **当前生效的回环系统代理** 并串联它，避免接管后断网；也可以在“策略与设置 → 上行链路”手动指定。上游变更属于热更新范围：保存后代理会自动重连并重新校准系统代理，不需要重启程序。
8. 回到审计控制台，查看流量、风险、发现、可见性分级与覆盖范围。所有开关与阈值都是热更新，详见[配置热更新](#配置热更新)。
9. 更新：Windows x64 安装版可在“策略与设置 → 版本与更新”检查并自动安装更新；Windows ARM64、Linux、macOS 与希望保持便携的用户请手动下载替换。自动安装前应用会先恢复系统代理并退出，详见[更新检查与安装](#更新检查与安装)。
10. 结束审计：**关闭窗口不一定等于退出**。Windows 上托盘可用时，点击窗口关闭按钮只会隐藏到通知区域；要完全退出并恢复系统代理，右键托盘图标选择 **退出并恢复系统代理**，或使用托盘菜单的正常退出。使用 `--no-tray` 启动、托盘依赖缺失或在非 Windows 平台时，关闭按钮仍然是退出。
11. 完全退出会停止代理、恢复系统代理并移除断网保护任务（开机自启保持不变，可用 **关闭开机自启** 单独撤销）；仍不再需要 HTTPS 解密时，点击 **移除本地 CA**。如果程序崩溃、被强制结束或直接断电，下次登录时由启动校准、集成自愈与独立的断网保护任务恢复网络，见下一节。

### 方式二：Windows 便携版或源码运行

**便携版**：从 Releases 下载 `EgressScope-v0.4.0-windows-x64.exe` 或 `EgressScope-v0.4.0-windows-arm64.exe`，双击运行。便携版不写开始菜单、不安装到固定目录；开机自启、系统代理与 CA 行为与安装版相同。Windows ARM64 使用同一套桌面代码，但没有安装包，更新只能手动下载。

**源码运行**：需要 Windows 10/11 与 Python 3.12+。

```bat
cd ai-agent-audit
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe app.py
```

无桌面窗口运行（适合调试或服务器）：

```bat
.venv\Scripts\python.exe app.py --headless --home .\dev-home
```

可选参数：

```text
--headless           无桌面窗口运行，仅启动代理与 Web 审计台
--home PATH          覆盖数据目录
--proxy-port PORT    本地代理端口（默认 8899）
--web-port PORT      审计台端口（默认 8898）
--upstream-proxy URL 串联的上游 HTTP/HTTPS 代理，如 http://127.0.0.1:7890
--no-inherit-upstream 不自动继承当前回环系统代理
--upstream-ca PEM    额外的上游 CA（测试）
--insecure-upstream  关闭上游 TLS 校验（仅测试）
--no-fileguard       关闭打开句柄抽样
--open               启动后打开审计台
--restore-proxy      恢复 EgressScope 启用前的系统代理后退出（无需启动审计）
--recover-proxy      仅在本地代理端口已停止监听时恢复系统代理后退出
--recover-grace SEC  配合 --recover-proxy，等待本地代理启动的秒数
--enable-autostart   写入当前用户 Run 键的开机自启后退出（默认已开启）
--disable-autostart  移除本程序写入的开机自启后退出，不影响其他程序的自启项
--autostart          最小化启动（供 Run 键开机自启使用）
--no-tray            禁用 Windows 通知区域图标；关闭窗口恢复为退出程序
--repair-integrations 把当前用户开机自启与断网保护任务重新指向当前程序后退出
--check-update       检查 GitHub Releases 是否有新版本，输出 JSON 后退出（不安装）
--log-level LEVEL    DEBUG / INFO / WARNING / ERROR
--version            输出版本号后退出
```

`--repair-integrations` 输出 JSON，并在程序被移动、覆盖升级或任务丢失后修复当前用户的集成项。`--check-update` 只读取公开的 GitHub Releases 信息，不下载、不安装；自动安装仍受 Windows x64 与安装包校验条件限制。

### Agent 环境变量

控制台导出的脚本位于：

```text
%LOCALAPPDATA%\EgressScope\data\agent-env.cmd
```

它会设置：

```bat
set "HTTP_PROXY=http://127.0.0.1:8899"
set "HTTPS_PROXY=http://127.0.0.1:8899"
set "ALL_PROXY=http://127.0.0.1:8899"
set "NO_PROXY=localhost,127.0.0.1,::1"
set "NODE_EXTRA_CA_CERTS=%LOCALAPPDATA%\EgressScope\data\certs\mitmproxy-ca-cert.pem"
set "REQUESTS_CA_BUNDLE=%LOCALAPPDATA%\EgressScope\data\certs\mitmproxy-ca-cert.pem"
set "SSL_CERT_FILE=%LOCALAPPDATA%\EgressScope\data\certs\mitmproxy-ca-cert.pem"
```

> 这组变量只在当前终端窗口有效。IDE/Agent 如果由自身的桌面启动器拉起，需要在其启动配置中注入同样的变量，或改用系统代理接入。Linux / macOS 上生成的脚本是 `data/agent-env.sh`，用 `source` 加载。

### 系统代理的失败模式与断网保护

Windows 会把“当前用户的手动代理”持久保存在 WinINet 注册表设置中。EgressScope 在**正常退出、关机与注销**时都会恢复原值，但以下情况不会触发任何恢复代码：

- 直接断电、蓝屏或强制重启；
- 在任务管理器中结束进程；
- 程序崩溃、被安全软件终止，或更新过程被强制中断。

自动更新会先走正常退出并恢复代理，再替换文件；但强制结束进程、断电等仍然不会触发恢复代码。

此时注册表仍指向已停止的 `127.0.0.1:8899`，浏览器和部分桌面应用会表现为“没有网络”，和某些 VPN 异常退出后的现象一致。

EgressScope 提供四层处理，其中前三层不需要你手动执行任何命令：

1. **关机 / 注销时优雅恢复**：程序在独立消息线程上创建一个隐藏的**顶层窗口**（消息专用窗口不属于顶层窗口，收不到会话结束通知），注册 `WM_QUERYENDSESSION` / `WM_ENDSESSION`；控制台构建同时注册 `SetConsoleCtrlHandler` 处理 `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT`。你点击关机、重启或注销时，Windows 会先投递会话结束消息，程序在恢复期间调用 `ShutdownBlockReasonCreate` 让系统显示等待原因，把系统代理写回启用前的备份值并刷新 WinINet 后立即释放，因此下一次开机不会继承一个指向已停止端口的代理。
2. **启动校准**：代理成功启动后读取代理备份。如果系统代理仍指向上一实例的端口，自动改指当前监听端口；如果新代理启动失败，立即恢复原始系统代理，避免把机器留在断网状态。配合默认开启的开机自启，登录后这条链路会重新建立。
3. **独立断网保护看门狗（默认勾选）**：启用系统代理时的确认对话框默认勾选“注册断网保护看门狗（推荐）”，注册一个仅作用于当前用户的计划任务，不需要管理员权限：
   - `EgressScope Proxy Recovery`：登录时以及每 2 分钟检查一次。发现系统代理指向的回环端口已停止监听时，最多等待 30 秒；仍未恢复就写回启用前的 `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL`，刷新 WinINet，删除备份并停用自身。

   守护逻辑位于 `%LOCALAPPDATA%\EgressScope\data\proxy-guard.ps1`，日志位于 `data\logs\proxy-recovery.log`。它只读取注册表代理值与 `proxy-backup.json`，不读取流量内容。
4. **手动恢复**：
   - 控制窗口的 **恢复原始系统代理**（同时移除断网保护任务，开机自启保持不变）；
   - `EgressScope.exe --restore-proxy`；即使不启动审计台也能执行，安装版的开始菜单也提供 **恢复系统代理** 快捷方式；
   - Windows **设置 → 网络和 Internet → 代理**，关闭“使用代理服务器”；
   - 自动化场景可用 `EgressScope.exe --recover-proxy`，只在代理端口已停止监听时恢复。

**集成自愈：** 程序启动时及运行中每 10 分钟检查当前用户的 Run 键与断网保护任务。程序被移动、覆盖升级或计划任务被删除后，会自动把自启命令重新指向当前可执行文件，并在看门狗仍启用时重新注册任务；不会覆盖其他程序的自启项。也可以手动运行 `EgressScope.exe --repair-integrations`。自愈只修复当前用户集成，无法绕过任务计划程序被策略禁用、注册表权限不足或数据目录被清空等情况。

**开机自启：** 默认开启，写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 的 `EgressScope` 值，登录时以 `--autostart` 启动。Windows 托盘可用时自启会隐藏到通知区域；托盘不可用时仍以最小化窗口启动。可在控制窗口点击 **关闭开机自启**、在审计台“策略与设置”关闭，或运行 `EgressScope.exe --disable-autostart`。撤销时只删除命令与本程序完全一致的值，不会动其他程序的自启项。Linux / macOS 不写任何自启项。

**边界与注意事项：**

- 优雅恢复依赖系统把会话结束消息投递到本进程；直接断电、内核崩溃或强制结束进程时收不到，此时恢复发生在下一次登录后（启动校准 + 看门狗）。
- 守护任务与开机自启只在用户登录后运行、只覆盖当前登录用户；如果 Task Scheduler 被策略禁用、任务被删除、数据目录被手动清理，保护会失效，此时使用手动恢复或 `--repair-integrations`。
- 在备份文件存在期间，守护任务会把“已启用但已停止监听的回环系统代理”视为 EgressScope 的代理。如果你在启用期间改用另一个本地代理，并在备份仍存在时让它异常退出，守护任务可能恢复为 EgressScope 启用前的设置。
- 系统代理只影响遵循 WinINet / 系统代理的应用；服务、SYSTEM 会话、证书固定应用与忽略系统代理的程序本来就不在覆盖范围内。
- **关闭窗口不是安全停止。** Windows 托盘可用时，关闭主窗口只是隐藏，代理、CA 与断网保护仍然生效；需要停止审计并恢复网络时，必须从托盘选择 **退出并恢复系统代理**，或使用 `--no-tray` 后关闭窗口。托盘中的“暂停审计”只停止写入新证据并暂停旁路观测，不会移除 CA，也不会恢复系统代理。
- Linux / macOS 不提供系统代理接管与托盘，因此也不存在这类“全局断网”失败模式；Agent 环境变量方式同样把影响范围限制在单个终端或进程，是更保守的接入方式。
- 如果无法接受任何全局代理风险，请优先使用 **Agent 环境变量**，不要启用系统代理。

### 配置热更新

除端口与证书目录外，设置改动都不需要重启进程：

- **来源一：控制台与审计台**。桌面控制台按钮、审计台“策略与设置”的开关与滑块写入配置后立即作用于运行中的组件。
- **来源二：直接编辑配置文件**。`%LOCALAPPDATA%\EgressScope\data\config.json` 被外部修改后，运行中的进程按文件内容摘要检测变更并采纳；只有 `EDITABLE_KEYS` 中的键会被热更新，端口等字段被忽略（重启后生效）。
- **生效方式**：采集开关、阻断开关与阈值、正文保存、保留期（立即执行一次清理）、文件句柄守护启停与抽样间隔、Canary 诱饵创建 / 删除、上游代理与自动继承（自动重连代理并重新校准系统代理）、开机自启（写入或移除 Run 键）、更新检查开关、旁路观测开关。
- **暂停语义**：关闭 `capture_enabled` 会停止写入新的流量证据，并同时暂停旁路观测；代理进程仍在运行，CA 与系统代理不会被移除。
- **确认结果**：`GET /api/status` 与控制台状态卡返回 `config_reload`，包含完成时间、来源（`api` 或 `file`）与本次生效的键名，不需要靠猜。
- **需要重启的字段**：`listen_port`、`web_port`、证书目录、`insecure_upstream`、`upstream_ca`。

### 默认开启与需要显式确认的能力

| 能力 | 默认 | 说明 |
| --- | --- | --- |
| 流量采集、AI 端点识别、敏感数据规则 | 开启 | 装完即产生证据链记录 |
| 文件句柄抽样（Beta） | 开启 | 只记录路径与时间等元数据，不读取文件内容；可用 `--no-fileguard` 或设置关闭 |
| 旁路与协议观测（Beta） | 开启 | 只读取本机连接表与 Windows DNS 解析缓存，记录直连 / QUIC / DNS 候选；不重定向、不抓包、不解密 QUIC；`network_watch_enabled` 可关闭，暂停采集时同步暂停 |
| 更新检查 | 开启 | 每 24 小时检查一次 GitHub Releases，结果缓存 6 小时；`update_check_enabled` 可关闭后台检查；自动安装仅 Windows x64 |
| 开机自启（当前用户 Run 键） | 开启 | 控制台、设置或 `--disable-autostart` 可撤销；Windows 托盘可用时隐藏启动 |
| Windows 通知区域图标 | Windows GUI 默认启用 | 关闭窗口隐藏到托盘；`--no-tray` 禁用；pystray / Pillow 缺失或非 Windows 时关闭即退出 |
| 断网保护看门狗 | 启用系统代理时默认勾选 | 可在确认对话框取消勾选 |
| 关机 / 注销优雅恢复、启动校准、集成自愈 | 始终启用 | 无独立开关；自愈每 10 分钟检查当前用户集成 |
| 风险阻断（返回 403） | 关闭 | 会中断请求，需显式开启 |
| Canary 诱饵文件 | 关闭 | 会在 Documents 下写入含虚构凭据的文件，需显式开启 |
| 安装本地 CA、启用系统代理 | 关闭 | 改动系统信任与网络设置，需显式确认 |

---

## 安装、更新与集成自愈

### Windows per-user 安装包

`installer/EgressScope.iss` 定义了一个 Inno Setup 6.0+ 的 per-user 安装包，发布工作流只在 **Windows x64** 上构建并上传 `EgressScope-Setup-v0.4.0.exe`。

- **无需管理员权限**：`PrivilegesRequired=lowest`，只写当前用户目录与当前用户注册表项。
- **固定安装目录**：`%LOCALAPPDATA%\Programs\EgressScope`，安装向导不显示目录选择页，避免更新器找不到安装位置。Windows ARM64 没有对应安装包，只能使用便携版。
- **快捷方式**：开始菜单始终创建 **EgressScope** 与 **恢复系统代理**（`--restore-proxy`）；桌面快捷方式是可选任务，默认不勾选。
- **升级与卸载**：安装包只覆盖程序文件，不改动 `%LOCALAPPDATA%\EgressScope` 下的审计数据。卸载时自动移除开机自启并恢复系统代理；静默卸载保留审计数据，交互式卸载会询问是否删除 `%LOCALAPPDATA%\EgressScope`（数据库、配置、证书、日志与已导出的证据），默认选择保留。
- **签名状态**：当前发布构建未签名。仓库所有者配置 `WINDOWS_CERT_PFX_BASE64` 与可选的 `WINDOWS_CERT_PASSWORD` 后，发布工作流的可选步骤会用 `signtool` 分别签名 `dist\EgressScope.exe` 与安装包；未配置时不会签名。安装向导首页会显示 `installer/UNSIGNED-NOTE.txt` 中的未签名说明。

### 更新检查与安装

更新器位于 `ai_audit/updater.py`，只访问 GitHub Releases 的公开接口，不上传审计数据、主机名或本地标识。

- **自动检查**：默认开启。程序启动 30 秒后执行一次后台检查，之后每 24 小时一次；结果缓存 6 小时。控制台/审计台的“检查更新”是强制刷新，不受 6 小时缓存限制。`update_check_enabled` 可关闭后台检查，手动检查仍可使用。
- **自动安装条件**：只有 **Windows x64** 才会提供自动安装。发布中必须存在 `EgressScope-Setup-v<latest>.exe`，并且存在该文件的 `.sha256` 或 `SHA256SUMS.txt`；否则只提示新版本，由用户手动下载。
- **下载与校验**：安装包和校验文件都必须使用 HTTPS，主机必须是 GitHub 控制或 GitHub Releases 使用的域名。SHA-256 不匹配、下载失败或超过大小上限时，文件会被删除，绝不会启动。SHA-256 校验只证明文件与发布页一致，不替代代码签名与发布者身份验证。
- **安装流程**：校验通过后以 `/SILENT /NORESTART /CLOSEAPPLICATIONS` 启动安装包；应用先恢复系统代理并退出，让安装器替换固定目录中的文件。静默安装/升级不会删除审计数据。
- **平台边界**：Windows ARM64、Linux、macOS 可以检查新版本，但自动安装不可用，必须手动下载。Windows x64 便携版也可发起更新，但更新器下载的是 per-user 安装包，运行后会切换到固定安装目录；希望保持便携时请手动替换文件。
- **可见状态**：`GET /api/status` 的 `update` 字段、`/api/update`、`/api/update/check`、`/api/update/install`、桌面控制台的“版本与更新”卡片以及 `--check-update` 都会给出当前版本、最新版本、可用性与安装条件。`--check-update` 只输出 JSON，不下载或安装。

### 集成自愈

- **自动修复**：Windows 上启动时调用一次 `system.repair_integrations`，随后每 10 分钟检查一次。若程序被移动、覆盖升级或重命名，Run 键中的自启命令会重新指向当前可执行文件；若看门狗脚本或计划任务缺失，会在备份仍存在且看门狗启用时重新注册。程序不会覆盖其他程序写入的自启值。
- **手动修复**：`EgressScope.exe --repair-integrations` 打印 JSON 结果后退出，适合安装、迁移或被安全软件清理后立即修复。
- **独立恢复**：`EgressScope.exe --restore-proxy` 不需要启动审计台，也不需要代理仍在运行；安装版的开始菜单快捷方式直接调用它。启动校准与端口变化时，仍会把系统代理从旧端口改指当前监听端口；看门狗在代理停止监听时恢复启用前的原始代理。
- **边界**：自愈依赖当前用户对 Run 键和 Task Scheduler 的权限。组策略禁用计划任务、注册表被锁定、数据目录被删除时，自愈可能失败，需要手动恢复。状态 API 的 `integration_health` 与日志会记录每次修复的动作和错误。

---

## 平台与 GitHub Actions

### 产物矩阵

| 平台 | 产物 | 桌面控制台 / 托盘 | 一键 CA / 系统代理 | 安装包与自动更新 |
| --- | --- | --- | --- | --- |
| Windows x64 | `EgressScope-Setup-v0.4.0.exe`（安装包）+ `EgressScope-v0.4.0-windows-x64.exe`（便携版） | ✅ / ✅（x64 人工冒烟验证） | ✅ | ✅ per-user 安装包；✅ Windows x64 自动更新 |
| Windows arm64 | `EgressScope-v0.4.0-windows-arm64.exe` | ✅（共用 Windows 代码；Tk UI 未在 ARM64 实机验收）/ ⚠️ 未验证 | ✅ | ❌ 无安装包；手动更新 |
| Linux x64 | `EgressScope-v0.4.0-linux-x64.tar.gz` | 命令行 / Web；❌ 无托盘 | ❌ | 手动 |
| Linux arm64 | `EgressScope-v0.4.0-linux-arm64.tar.gz` | 命令行 / Web；❌ 无托盘 | ❌ | 手动 |
| macOS x64 | `EgressScope-v0.4.0-macos-x64.tar.gz` | 命令行 / Web；❌ 无托盘 | ❌ | 手动 |
| macOS arm64 | `EgressScope-v0.4.0-macos-arm64.tar.gz` | 命令行 / Web；❌ 无托盘 | ❌ | 手动 |

Windows 版本是功能完整的桌面产品。**安装包只构建 Windows x64**；Windows ARM64 继续发布便携 EXE，桌面 Tk 控制台未在 ARM64 实机做 UI 验收，托盘也未在 ARM64 验证。Windows ARM64 因上游只提供到 `cryptography 46.0.3` 的 `win_arm64` wheel，构建时固定该版本；`aioquic 1.2.0`、`mitmproxy_rs` 与 `brotli` 从源码编译。`aioquic` 的 `_crypto` 扩展需要 OpenSSL 头文件和导入库，CI 用 runner 自带的 vcpkg 现场构建 ARM64 OpenSSL，并把 `libcrypto` 运行库打进单文件 EXE；Rust 依赖 `ring` 则使用 `vcvarsall arm64` 的 MSVC 环境编译。

Linux / macOS 版本共享同一套代理、归因、策略、证据和 Web 审计台，面向“手动配置代理与环境变量”的审计场景；系统代理备份/恢复、当前用户 CA 一键安装与 Windows 托盘仍只支持 Windows。Linux 的 PID 归因依赖 `/proc/net/tcp`；macOS 在非 root 下无法读取系统 TCP 归属表，会诚实降级为不含 PID 的流量记录。macOS 与 Linux 构建未签名，首次运行可能需要手动放行。

非 Windows 启动示例（发布包内的可执行文件名为 `EgressScope-<tag>-<platform>`）：

```bash
tar -xzf EgressScope-v0.4.0-linux-x64.tar.gz
./EgressScope-v0.4.0-linux-x64 --headless --home ~/.egressscope --proxy-port 8899 --web-port 8898
# 另一个终端加载接入变量
source ~/.egressscope/data/agent-env.sh
```

### 工作流

| 文件 | 触发 | 内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | push / PR / 手动 | Windows x64、Linux x64、macOS arm64 上运行冒烟、更新器、断网保护 / 自启 / 热更新、可见性、旁路观测、托盘、上游链路与官网页面门禁 |
| `.github/workflows/release.yml` | `v*` tag / 手动 | 六平台构建；Windows x64 额外构建 per-user 安装包并支持可选签名；Windows x64 / ARM64 运行打包验收；tag 时由 publish job 汇总产物、生成 `SHA256SUMS.txt`、从 `CHANGELOG.md` 截取发布说明并创建 GitHub Release |
| `.github/workflows/pages.yml` | push main（介绍页变更）/ 手动 | 把 `web/intro.html` 与 `web/tech.html` 发布到 GitHub Pages |

### 首次推送到 GitHub

```bash
git remote add origin git@github.com:<owner>/EgressScope.git
git push -u origin main
```

发布一个版本：

1. 更新 `ai_audit/__init__.py` 的 `__version__`；
2. 在 `CHANGELOG.md` 顶部新增 `## v<版本>` 小节，写清这一版改了什么（发布工作流会把该小节原文写入 Release 正文；缺失时正文回退为指向 `CHANGELOG.md` 的一行提示）；
3. 同步更新 `tests/site_check.py` 的版本断言与官网版本文案；
4. 打 tag 并推送：

```bash
git tag v0.4.0
git push origin v0.4.0
```

### GitHub Pages 官网

1. 推送代码后，在仓库 **Settings → Pages** 将 **Source** 设为 **GitHub Actions**（工作流也会尝试自动启用）。
2. 手动运行一次 **Deploy product site**，或修改 `web/intro.html` / `web/tech.html` 后推送到 `main`。
3. 页面地址通常为 `https://<owner>.github.io/EgressScope/`，技术文档为 `https://<owner>.github.io/EgressScope/tech.html`。
4. Pages 版本会把顶部和底部的“打开审计台”按钮改写为 **下载发布版本**，指向 `https://github.com/<owner>/EgressScope/releases/latest`；本地 `/intro` 与 `file://` 打开时仍指向本机审计台。

如果首次运行在 `configure-pages` 步骤报 `Resource not accessible by integration`，说明仓库尚未启用 Pages：在 **Settings → Pages** 把 **Source** 设为 **GitHub Actions**，再重新运行工作流。该一次性设置需要仓库管理员权限。

`macos-15-intel`、`ubuntu-24.04-arm` 与 `windows-11-arm` 属于 GitHub 公共仓库的托管运行器；如果仓库是私有且运行器不可用，保留其余平台构建或改用自托管 runner。

---

## 它解决什么问题

传统流量工具通常能显示连接、字节数和目标域名，但很难解释一次 AI 会话里到底夹带了什么。EgressScope 把四层信息串成一条证据链：

1. **入口**：请求是否真的经过审计器。
2. **内容**：在应用愿意配合、TLS 可终止时，请求正文是什么；如果看不到正文，明确标记为部分或仅元数据。
3. **发起者**：本机哪个 PID、哪条父进程链发起了连接。
4. **处置**：命中什么规则、风险分多少、是观察还是阻断，以及证据是否被完整保存。

这不是一个“抓包美化器”。它关注的是 AI 时代最常见、又最难解释的风险：上下文、源代码、环境变量、客户数据在一次普通 API 调用中被悄悄带出。

典型可回答的问题：

- `claude.exe` / `python.exe` / `Code.exe` 在向哪些 AI 端点发送请求？
- 请求里是否包含 API Key、私钥、身份证号、银行卡号或 `.env` 内容？
- 这次外发来自哪个进程和父进程链，而不是仅仅“来自本机”？
- 风险最高的请求能否被本地拦截，而不是只事后告警？
- 哪些流量只能看到元数据，哪些连接可能绕过了代理？覆盖边界到底是什么？

---

## 架构与取舍

```text
AI Agent / 编辑器 / SDK / 普通桌面应用
        │                                   │
        │ 遵循代理                           │ 忽略代理 / QUIC / DNS
        ▼                                   ▼
HTTP/HTTPS 本地转发代理              可选连接表观测（psutil，15s）
（127.0.0.1:8899）                   + Windows DNS 解析缓存（只读）
        │                                   │
        ▼                                   ▼
TLS 终止（本地 CA，仅应用信任时）     直连 / QUIC / DNS 候选
        │                            （仅元数据，检测不重定向）
        ▼
HTTP 语义 / 方法 / 路径 / 正文 / 流式元数据
        │
        ▼
可选上行链路（自动继承 Clash 等本机代理 / 手动指定）
        │
        ▼
进程归因（客户端端口 → 本机 TCP 表 → PID → 父进程链）
        │
        ▼
可见性分级（完整 / 部分 / 仅元数据 / 已阻断 / 错误）
        │
        ▼
策略引擎（AI 端点分类、DLP 规则、风险评分、处置）
        │
        ▼
SQLite（WAL）＋ AES-GCM 证据正文＋ SHA-256 审计链
        │
        ▼
本机 Web 审计台 + 桌面控制台 / Windows 托盘
```

连接表观测是 v0.4.0 新增的**旁路检测**，与代理路径并列而不是替代它：它不接管流量、不安装驱动、不做透明重定向，只帮助暴露“代理没看到”的直连、QUIC 和 DNS 目标。两条路径最终都进入可见性分级与证据库，避免把“没经过代理”误写成“没有发生”。

### 为什么选择“本地代理 + 本地 CA + 进程归因”

| 方案 | 内容可见性 | 落地成本 | 覆盖特点 | 主要问题 |
| --- | --- | --- | --- | --- |
| **本地代理 + 本地 CA + 只读连接表观测（v0.4.0）** | 可终止 TLS 时有正文；直连 / QUIC / DNS 仅有候选元数据 | 低：无驱动、无内核签名 | 依赖应用使用代理并信任 CA；旁路只能提示缺口 | 证书固定、QUIC 内容、服务进程仍不可见；候选不是内容证据 |
| WFP / WinDivert 透明重定向 | 仍受 TLS 固定 / 信任限制 | 高：驱动、签名、兼容性 | 不依赖应用代理设置 | 部署重、误伤风险高、仍不是“解密银弹”；本版未实现 |
| Agent 会话 / MCP 旁路 | 可读会话内容 | 低：读本地数据 | 仅覆盖特定 Agent 的私有格式 | 看不到真实外发网络路径，跨 Agent 不可复用 |
| 浏览器扩展 | 仅浏览器页面/请求 | 低 | 仅浏览器 | 桌面 Agent、CLI、后台服务完全看不到 |
| ETW / SACL / 文件过滤驱动 | 通常是事件而非内容 | 高 | 网络与文件事件范围广 | 事件量大、噪音高、需要管理员与规则工程 |

第一版选择本地代理，是因为它把“内容可见性”和“可解释的系统变更”放在了同一条工程路径上：

- 不需要内核驱动和代码签名，用户能理解它做了什么，也能随时停用。
- 内容、进程、策略、证据四件事可以闭环验证。
- 不依赖某个 Agent 的私有会话格式；Agent 换实现，代理层仍然成立。
- 允许用户从“只给一个 Agent 注入环境变量”开始，逐步扩大授权范围。
- 对不配合的流量，产品会诚实降级为“只有元数据 / 部分可见 / 完全不可见”，而不是伪装成全量可见；连接表观测只给出候选，不冒充证据。

**这不是也不能是“破解所有加密上传”的工具。** 本地 CA 只在应用信任它、且没有启用证书固定或双向 TLS 时有效。E2EE、QUIC 与恶意程序自建加密协议不在这条路径的可见范围内；UDP 443 的 QUIC 检测只记录候选元数据，不解密、不重定向。EgressScope 不尝试绕过证书固定、mTLS 或应用层端到端加密。

本版使用嵌入式 mitmproxy 负责成熟的 TLS 终止、HTTP/2、证书签发与流式转发，把工程精力集中在归因、策略、证据与产品边界上。mitmproxy 只作为本地代理运行时，不向外部服务转发数据。

### 上行链路：与 Clash / VPN 共存

很多开发机已经通过 Clash、v2rayN 等本地代理访问外网。EgressScope 接管系统代理后，如果直接连接上游，可能反而让原本正常的 Agent 断网。因此启动时会读取 Windows 当前代理设置，并仅在满足以下条件时自动串联：

- 代理已启用，且没有配置 PAC 脚本；
- 代理地址是本机回环地址（`127.0.0.1` / `localhost` / `::1`）的 HTTP 或 HTTPS 代理；
- 端口不是 EgressScope 自身的代理端口或审计台端口。

也可以在“上行链路”中手动指定，或用 `--upstream-proxy http://127.0.0.1:7890` 启动。手动指定优先于自动继承；`--no-inherit-upstream` 可完全关闭继承。该配置在代理启动时读取，修改后需要重启程序。

上游链路只负责把 mitmproxy 重新加密后的 TLS 字节转发出去。上游代理能看到目标主机与连接元数据，但**看不到** EgressScope 已解密的正文；如果上游本身也是会终止 TLS 的企业代理，则它可能按自己的策略看到内容，这属于另一层信任边界。当前不支持需要用户名密码认证的代理、PAC 脚本、SOCKS 上游与非回环自动继承，这些场景请使用单 Agent 环境变量或手动配置。

---

## 风险引擎

策略引擎综合分析目标主机、路径语义、JSON 字段、请求正文和进程上下文。

### AI 端点识别

- 内置常见云端 AI 服务清单：OpenAI、Anthropic、Google Gemini、OpenRouter、Mistral、Cohere、Groq、xAI、DeepSeek、阿里云百炼、Moonshot、智谱、百度千帆、火山方舟、SiliconFlow 等。
- 识别本地模型端点：Ollama `localhost:11434`、LM Studio `localhost:1234` 等。
- 对未知主机会结合路径（`/v1/chat/completions`、`/v1/messages`、`/api/chat` 等）和 JSON 请求结构判断为 **AI 候选端点**，不会强行当作已知服务。
- 尽可能从请求 JSON 中提取模型名，帮助区分实际调用的模型。

### 主要规则

| 类别 | 规则示例 | 说明 |
| --- | --- | --- |
| 密钥 | OpenAI / Anthropic / AWS / GitHub / Google / Slack Key、JWT、私钥 | 强匹配会显著抬升风险；预览与证据脱敏 |
| PII | 中国身份证、银行卡（Luhn 校验）、手机号、邮箱 | 展示时只保留掩码 |
| 凭据赋值 | `token=`、`password:`、`SECRET=...` | 捕获非标准键值型凭据 |
| 敏感环境 | 多行 `.env` / 环境变量结构 | 识别被整体打包上传的风险 |
| 代码与文件 | Markdown 代码块、Diff、源码/文件路径引用、multipart 上传 | 判断是否携带工作区上下文或附件 |
| 外发目标 | 敏感内容发往未识别目标 | 避免“未知目标 + 敏感正文”被静默忽略 |
| 体积 | 较大的请求正文 | 辅助识别批量外带或文件上传 |

评分是**信号强度**，不是事实结论。误报、漏报都可能发生；策略用于辅助判断，不应替代人工复核。

### 风险分与处置

| 风险分 | 等级 | 默认行为 |
| --- | --- | --- |
| 85–100 | 严重 | 观察 / 告警；若开启阻断则按阈值拦截 |
| 70–84 | 高风险 | 观察 / 告警 |
| 45–69 | 中风险 | 观察 / 告警 |
| 25–44 | 低风险 | 观察 |
| 0–24 | 信息 | 观察 |

阻断默认关闭，阈值默认 85。开启阻断后，达到阈值的请求会被本地代理直接返回 `403 egress_policy_blocked`，并在证据库中标记为 blocked；其可见性等级为 `blocked`（界面显示“已拦截”）。建议先观察一段时间确认真实误报率，再启用阻断。

### 响应侧检查

响应正文也会扫描明显的密钥与 PII，但这类发现标记为 `direction=response` 且不计入请求外发风险，避免把上游返回的数据误算成本机泄露。列表与导出默认不包含响应原文。

---

## 可见性分级与覆盖范围

v0.4.0 为每条流量增加 `visibility` 与中文 `visibility_reason`。等级描述的是**这次记录到底看到了多少内容**，不是对目标安全性的判断。

| 等级 | 界面显示 | 含义 | 典型场景 |
| --- | --- | --- | --- |
| `full` | 完整 | 请求/响应结构可读，正文按策略完整保留 | 应用信任本地 CA、TLS 正常终止、响应正文未超限 |
| `partial` | 部分 | 连接可读，但内容不完整 | WebSocket 握手可见但消息不持久化；正文流式/超限/缺失；请求正文未完整保留 |
| `metadata` | 仅元数据 | 只有连接元数据，没有可读正文 | CONNECT 隧道失败；TLS 握手失败（可能是证书固定、mTLS、客户端拒绝本地 CA）；客户端 TLS 未被终止 |
| `blocked` | 已阻断 / 已拦截 | 策略在本地拒绝转发 | 风险达到阻断阈值，返回 `403 egress_policy_blocked` |
| `error` | 错误 | 代理或上游错误，未获得响应 | 上游连接失败、代理异常、响应前错误 |

关键约定：

- **只有真正读到可读响应时才会标记 `full`。** 隧道失败、握手失败、正文缺失、WebSocket、请求正文不完整都会降级，并附中文原因；不会把元数据伪装成完整记录。
- **`metadata` 不是“没有发生”。** 它表示连接元数据可见、正文不可见；原因中会明确写出证书固定、mTLS 或本地 CA 被拒绝等可能性，但 EgressScope 不尝试绕过这些边界。
- **原因会脱敏。** `visibility_reason` 经过敏感信息脱敏并截断，避免把错误文本中的凭据写入证据库。
- **旧库迁移。** 升级前创建的数据库会自动增加 `visibility` / `visibility_reason` 列；历史流量迁移为 `partial`，原因写明“升级前的历史记录未做可见性分级”，不会事后臆造等级。
- **展示与导出。** 本机审计台在流量列表、详情与覆盖范围统计中显示等级与原因；`/api/status`、流量 API 与 JSONL 导出均包含 `visibility` 与 `visibility_reason`。导出清单会说明旁路事件只是观测元数据，不是抓包正文。

### 覆盖范围：能看见与看不见

| 场景 | v0.4.0 行为 | 说明 |
| --- | --- | --- |
| 系统代理生效后的 HTTP/HTTPS | ✅ 元数据 + 可解密正文 | 主要覆盖路径；按正文完整度标记 full / partial |
| 本机已有 Clash / v2rayN 等回环 HTTP 代理 | ✅ 解密后串联上游 | 自动继承，避免接管后断网 |
| Agent 使用 `HTTP_PROXY` / `HTTPS_PROXY` | ✅ 元数据 + 可解密正文 | 推荐用于单 Agent 试点 |
| 应用信任本地 CA、无证书固定 | ✅ TLS 1.2 / 1.3 正文 | 受应用实现影响 |
| 应用忽略代理 / 直连 | ⚠️ 仅直连候选元数据 | 连接表观测可发现公网直连 TCP 候选；**不拦截、不重定向**；WFP / WinDivert 透明重定向未实现 |
| 证书固定 / mTLS / 双向校验 | ⚠️ 仅元数据 | 握手失败记录为 metadata 并给出原因；不尝试绕过应用安全边界 |
| QUIC / HTTP3 | ⚠️ 仅 QUIC 候选元数据 | UDP 443 只记为候选；不解密、不重定向，QUIC 内容不可见 |
| DNS | ⚠️ 仅目标元数据 | TCP/UDP 53 与 TCP 853 只记录目标；Windows 解析缓存可补 IP→域名，**不记录查询内容** |
| WebSocket | ⚠️ 部分 | 握手可见；消息正文不持久化 |
| 应用层端到端加密 | ❌ 无密钥不可读 | 不承诺破解 |
| Windows 服务 / SYSTEM 会话 | ⚠️ 覆盖不完整 | 当前代理与归因面向登录用户 |
| 完整文件读取历史 | ❌ 不提供 | 只有打开句柄抽样 Beta |
| 文件内容本身 | ❌ 从不读取 | 文件守护只记录元数据 |
| 浏览器扩展 / 页面内脚本 | ⚠️ 仅当其请求经过代理 | 不做浏览器进程内的额外采集 |
| WFP / WinDivert 透明重定向 | ❌ 未实现 | 路线图中的未来工作，不是本版能力 |

**“没看到”不等于“没有发生”。** 审计台把覆盖状态与可见性等级实时列出来，而不是把所有流量都笼统标记为已覆盖。直连与 QUIC 事件只是候选信号，可能来自上游代理、非 HTTP 协议、短连接或共享 PID；不能仅凭候选判定数据已经外发。

---

## 旁路与协议观测（Beta）

`ai_audit/netwatch.py` 提供一个**只读**的连接表观测器，用于提示本地 HTTP 代理看不到的出口。它默认开启（`network_watch_enabled=true`），每 15 秒通过 psutil 读取一次本机连接表。

| 类型 | 触发条件 | 记录内容 | 不代表 |
| --- | --- | --- | --- |
| `direct_tcp` | 公网远端 TCP 80 / 443 / 8080 / 8443 | 时间、PID、进程名/路径、远端 IP/端口、协议、可选域名 | 不是“已绕过代理”的证明；可能是上游代理、非 HTTP 协议或短连接 |
| `quic` | 公网远端 UDP 443 | 同上，标记为 QUIC 候选 | 不解密 QUIC；也可能是其他 UDP 流量 |
| `dns` | 公网远端 TCP/UDP 53、TCP 853 | 目标 IP/端口、PID、可选域名 | 只记录目标，不记录查询内容、响应或 DoH 正文 |

工作机制与边界：

- **域名补全只在 Windows**：读取 Windows DNS 解析缓存，把 IP 映射到最近解析过的域名；缓存每 60 秒刷新一次，查询内容从不读取。Linux / macOS 不使用该缓存，连接表观测仍会继续，但没有域名补全。
- **归因**：复用现有 PID 解析器，记录进程名、路径与应用类型；解析失败时仍保留连接元数据，不伪造进程。
- **去重与上限**：相同类型 + PID + 远端 + 域名在 10 分钟内只记一次；单次扫描与单日有事件上限，避免异常网络把证据库写满。
- **展示**：覆盖范围页与状态卡显示当日 `direct_tcp` / `quic` / `dns` 计数和最近事件；`GET /api/network` 返回状态与事件。JSONL 导出包含 `net_event` 行，清单明确标注这是本地观测元数据，不是抓包正文。
- **暂停**：暂停采集（`capture_enabled=false`）会同时暂停旁路观测；恢复采集后继续。关闭 `network_watch_enabled` 只停止该观测，不影响代理与流量采集。
- **只检测，不接管**：不重定向、不拦截、不注入、不安装内核驱动、不解密 QUIC 或 E2EE。WFP / WinDivert 透明重定向**没有实现**。
- **候选不是证据**：直连与 QUIC 事件是“值得复核的信号”，不是“内容已外发”的结论。结合进程、目标、时间和代理状态人工判断。

---

## Windows 托盘与后台运行

Windows GUI 构建集成 pystray 0.19.5 与 Pillow 12.3.0，在通知区域显示 EgressScope 图标；其他平台不加载托盘依赖。

- **关闭即隐藏**：Windows 上托盘启动成功后，点击主窗口关闭按钮只会把窗口隐藏到通知区域，程序、代理、CA 与断网保护继续运行。首次隐藏会弹出一次气泡，说明如何完全退出。
- **托盘菜单**：**打开控制台**、**打开审计仪表盘**、**暂停审计 / 恢复审计**、**退出并恢复系统代理**。
- **暂停语义**：托盘暂停写入同一个 `capture_enabled` 设置，并同步暂停旁路观测；图标与提示文字会变为暂停态。它不会移除 CA，也不会恢复系统代理。
- **退出语义**：**退出并恢复系统代理** 走正常关停流程：停止采集、文件守护、代理、Web 审计台与旁路观测，恢复系统代理并移除断网保护任务。开机自启保持不变。
- **开机自启**：Windows 托盘可用时，`--autostart` 登录启动会直接隐藏到通知区域；托盘不可用时退化为最小化窗口。
- **禁用**：启动参数 `--no-tray` 禁用通知区域图标，关闭窗口恢复为退出程序。pystray / Pillow 缺失、非 Windows 平台或托盘初始化失败时，也保持“关闭即退出”的原有行为。
- **验证边界**：托盘在 **Windows x64** 上做过人工冒烟验证（关闭隐藏、菜单、暂停/恢复、退出恢复代理）；未在 Windows ARM64 的 Tk UI 上验收，也不由打包 CI 的 UI 测试覆盖。`tests/tray_test.py` 使用假的 pystray/Pillow 路径验证行为，不启动真实桌面通知区域。

---

## 数据与隐私设计

- **本地优先**：默认没有云端上报，没有外部字体、脚本或遥测。
- **凭据最小化**：列表、搜索、告警和导出的 JSONL 只含脱敏预览和元数据。
- **正文加密**：仅对 AI 流量或风险分 ≥ 25 的请求有选择地保存正文；使用 AES-256-GCM，主密钥由 Windows DPAPI 保护。换用户账户或搬走数据库后，原文不可解密。
- **显式解密**：在流量详情点击“解密原文”后，服务端才在本次响应中返回明文；不会将明文重新写回数据库或导出文件。
- **审计链**：每条流量写入时，将摘要与上一条哈希链接，提供可验证的完整性基线。注意：它不是外部公证，拥有完整数据库写入权限的攻击者仍可能重写整条链。
- **本地 Web 安全**：Web 审计台只监听 `127.0.0.1`，每次启动生成随机令牌，校验 Host，使用 CSP、`no-store`，并拒绝非回环 Host。
- **显式系统变更**：CA 安装、系统代理启用、文件诱饵创建都只在桌面控制窗口中发生，且都有确认步骤；Web 审计台没有系统级授权接口。
- **上游只接手重新加密的流量**：自动继承或手动指定的上游代理不会收到审计器已解密的正文，只会收到目标主机与重新加密的 TLS 字节。
- **更新检查不携带审计数据**：只向 GitHub Releases API 发送当前版本 User-Agent 等必要请求头，不上传流量、主机名、进程或证据。`--check-update` 同样只读公开 Release 信息。
- **更新下载可验证**：只接受 HTTPS 与 GitHub 控制域名，必须匹配发布页的 SHA-256；校验失败会删除文件。SHA-256 保证传输内容一致，但不等同于代码签名或发布者身份验证。
- **旁路观测只读元数据**：只读取本机连接表与 Windows DNS 解析缓存，不抓包、不读 DNS 查询内容、不读取应用正文，也不把观测数据发送到外部。事件保存在本机数据库，随保留期清理并随脱敏导出提供。
- **托盘不增加采集面**：托盘只是控制与展示入口，不读取窗口外内容，也不提供远程控制接口。
- **可撤销**：支持移除 CA、恢复原始系统代理、关闭开机自启、移除断网保护任务、暂停采集、清空本地数据和导出脱敏证据。

### 数据位置

默认根目录：`%LOCALAPPDATA%\EgressScope`

```text
%LOCALAPPDATA%\Programs\EgressScope\
  EgressScope.exe      per-user 安装版的程序文件（卸载时移除）

%LOCALAPPDATA%\EgressScope\
  data\
    egress.db          SQLite 流量、发现、文件事件、旁路观测事件、审计链
    secret.bin         DPAPI 保护的数据加密主密钥
    config.json        设置文件（外部编辑后按内容摘要热更新）
    certs\             审计 CA（公开证书可下载，私钥仅本地）
    exports\           JSONL 脱敏证据导出（含 net_event 元数据行）
    logs\              运行日志
    logs\proxy-recovery.log  断网保护恢复记录（仅恢复时写入）
    agent-env.cmd      Agent 环境变量脚本
    proxy-backup.json  启用系统代理前的原始设置（恢复后删除）
    proxy-guard.ps1    独立断网保护脚本（启用保护时生成）
  canaries\            可选诱饵文件目录（如启用）
```

注册表与计划任务侧只留下三处、且都可逐项撤销：`HKCU\...\Internet Settings`（系统代理，含备份）、`HKCU\...\CurrentVersion\Run` 的 `EgressScope` 值（开机自启）、当前用户计划任务 `EgressScope Proxy Recovery`（看门狗）。安装版额外在开始菜单与可选桌面创建快捷方式；卸载时移除程序文件与快捷方式，并按交互式选择决定是否删除 `%LOCALAPPDATA%\EgressScope` 数据。

可通过 `--home` 或环境变量 `EGRESSSCOPE_HOME` 覆盖根目录。

---

## 项目结构

```text
ai-agent-audit/
├─ .github/workflows/
│  ├─ ci.yml               三平台冒烟、更新、恢复、可见性、旁路观测、托盘与上游测试
│  ├─ release.yml          六平台构建、Windows x64 安装包、可选签名与 GitHub Release
│  └─ pages.yml            介绍页 GitHub Pages 部署
├─ installer/
│  ├─ EgressScope.iss      per-user Inno Setup 安装包（Windows x64）
│  └─ UNSIGNED-NOTE.txt    未签名安装包说明
├─ tools/
│  └─ shutdown_lab.ps1     可选的一次性虚拟机关机/注销实验工具（非 CI）
├─ app.py                  启动入口、命令行参数、桌面/无头模式、生命周期
├─ ai_audit/
│  ├─ addon.py             mitmproxy 请求/响应钩子、证据落库、可见性标记
│  ├─ attribution.py       客户端端口 → PID / 父进程链
│  ├─ config.py            设置持久化、默认值与热更新白名单
│  ├─ crypto.py            DPAPI + AES-GCM 封装
│  ├─ fileguard.py         打开句柄抽样 Beta + Canary
│  ├─ netwatch.py          只读连接表 / Windows DNS 缓存观测（Beta）
│  ├─ paths.py             数据目录、冻结/源码资源路径
│  ├─ policy.py            AI 识别、DLP 规则、风险评分
│  ├─ proxy.py             嵌入式代理与显式关闭监听
│  ├─ release_notes.py     从 CHANGELOG 截取指定版本的发布说明
│  ├─ store.py             SQLite、加密证据、哈希链、可见性、旁路事件、导出
│  ├─ system.py            CA、系统代理、开机自启、关机钩子、集成自愈、Windows 控制
│  ├─ tray.py              Windows 通知区域图标与菜单
│  ├─ ui.py                Tkinter 桌面控制窗口与托盘联动
│  ├─ updater.py           GitHub Releases 检查、SHA-256 校验与安装包启动
│  ├─ visibility.py        流量可见性分级与中文原因
│  └─ web.py               本地审计台 HTTP 服务与 API
├─ web/
│  ├─ dashboard.html       交互式审计台（无外部依赖）
│  └─ intro.html           产品介绍官网页面
├─ tests/
│  ├─ smoke_test.py        端到端冒烟测试（不修改系统设置）
│  ├─ recovery_test.py     断网保护、关机钩子、自愈、端口校准、开机自启、热更新
│  ├─ updater_test.py      版本比较、Release 资产选择、校验、下载与启动
│  ├─ visibility_test.py   可见性分级、隧道记录、旧库迁移、导出字段
│  ├─ netwatch_test.py     连接分类、DNS 解析、去重、归因、状态与导出
│  ├─ tray_test.py         托盘平台门禁、菜单、暂停/恢复、关闭语义（假实现）
│  ├─ upstream_test.py     上游代理串联与自动继承识别测试
│  ├─ packaged_test.py     打包后可执行文件的端到端验证（发布工作流）
│  └─ site_check.py        官网页面静态门禁（i18n 覆盖、ARIA、JSON-LD、无外部依赖）
├─ .gitignore              构建产物、虚拟环境、测试临时目录
├─ .gitattributes          跨平台换行与二进制标记
├─ build.spec              PyInstaller 单文件构建配置（含 Windows 托盘依赖）
├─ build.bat               Windows 一键构建脚本
├─ CHANGELOG.md            版本更新说明，发布 tag 时写入 Release 正文
├─ requirements.txt        运行时依赖
├─ requirements-dev.txt    构建与测试依赖
└─ PLAN.md                 调研与执行计划
```

---

## 开发、测试与构建

### 环境

- 桌面控制台、系统代理与托盘：Windows 10 / 11 x64（主要支持平台；托盘只在 x64 做过人工冒烟验证）
- Windows ARM64：同一套桌面代码的便携版；Tk 控制台与托盘未在 ARM64 实机验收
- 审计引擎与 Web 审计台：Windows、Linux、macOS（CI 构建 Linux x64/arm64、macOS x64/arm64）
- Python 3.12+
- 运行依赖：`mitmproxy 12.3.0`、`psutil 7.2.2`、`cryptography 50.0.2`（Windows ARM64 固定 `46.0.3`；Intel macOS 使用兼容的 `47.0.0`）、Windows 托盘依赖 `pystray 0.19.5` + `Pillow 12.3.0`

### 安装依赖

```bat
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

### 端到端测试

```bat
.venv\Scripts\python.exe tests\smoke_test.py
```

测试会：

- 在临时数据目录启动应用与本地代理；
- 启动一个自签名 HTTPS Mock 服务；
- 使用真实本地 CA 完成一次 HTTPS 请求并校验流量落库、PID 归因、AI 分类、DLP、可见性分级、加密解密、阻断、哈希链、旁路观测 API、导出脱敏与 Web 鉴权；
- **不会**安装根证书、修改系统代理、写开机自启或触碰真实业务数据。

当前基线：**61 项检查全部通过**。测试使用 `--insecure-upstream` 仅针对 Mock 服务端，生产运行不要开启；同时显式关闭系统代理继承与开机自启，避免连接本机日常使用的代理或改动真实 Run 键。CI 会在 Windows、Linux、macOS 三平台运行同一套源码测试；Windows 的发布构建还会运行打包验收。

断网保护、自愈与恢复逻辑测试：

```bat
.venv\Scripts\python.exe tests\recovery_test.py
```

覆盖代理端口精确匹配、外部代理不被覆盖、端口变化后的自动改指、失效代理的恢复、守护脚本语法与备份恢复路径、计划任务注册权限、“守护脚本缺失”降级状态、开机自启 Run 键的写入/查询/撤销（且不删除其他程序的自启项）、`--repair-integrations` 对自启与看门狗的重写、配置文件外部编辑后的热更新（按内容摘要检测、非白名单键被忽略、非法配置与删除文件时保留原设置）、关机钩子的隐藏顶层窗口与 `WM_QUERYENDSESSION` / `WM_ENDSESSION` 回调，以及从 `CHANGELOG.md` 截取当前版本发布说明。Windows 基线：**78 项检查全部通过**；Linux / macOS 会跳过关机窗口、计划任务等 Windows 专属检查。测试**不读写**真实代理注册表与真实 Run 键（winreg 被替换为内存假实现）；Windows 上会创建一个指向 `cmd.exe /c exit 0` 的临时计划任务并在测试结束时删除，用于验证当前用户的 Task Scheduler 权限和触发器结构；还会在当前进程创建隐藏的关机守卫窗口并发送模拟的会话结束消息，**不触发真实关机或重启**。

更新器测试：

```bat
.venv\Scripts\python.exe tests\updater_test.py
```

覆盖语义化版本比较、Release 资产选择、`.sha256` / `SHA256SUMS.txt` 校验、SHA-256 不匹配删除文件、HTTPS / GitHub 域名限制、静默安装参数、`update_check_enabled` 热更新与 `--check-update` JSON 输出。**52 项检查全部通过**。

可见性测试：

```bat
.venv\Scripts\python.exe tests\visibility_test.py
```

覆盖完整 / 部分 / 仅元数据 / 已阻断 / 错误分类、CONNECT 隧道记录、TLS 握手失败的诚实原因、WebSocket 部分可见、正文与请求正文降级、旧数据库迁移、列表/详情/统计/导出字段。**42 项检查全部通过**。

旁路观测测试：

```bat
.venv\Scripts\python.exe tests\netwatch_test.py
```

覆盖公网地址过滤、TCP/UDP 端口分类、Windows DNS 缓存解析、PID 归因、10 分钟去重、状态与启停、数据库事件计数、导出与清理。**69 项检查全部通过**。

托盘测试：

```bat
.venv\Scripts\python.exe tests\tray_test.py
```

覆盖平台门禁、关闭/隐藏/退出语义、菜单与回调、暂停/恢复、气泡通知、外部状态同步与延迟导入；使用假的 pystray/Pillow，不启动真实桌面 GUI。**67 项检查全部通过**，其中 6 项图标渲染检查需要 Pillow；缺少 Pillow 时会跳过这些检查。托盘另有 Windows x64 人工冒烟验证，但不属于 CI。

上游链路测试：

```bat
.venv\Scripts\python.exe tests\upstream_test.py
```

它会启动一个最小 CONNECT 中继，验证审计流量确实经上游转发、正文仍能捕获，并覆盖自动继承的识别条件（回环、PAC、非回环、排除端口）。**15 项检查全部通过**。

### 打包产物测试

```bat
.venv\Scripts\python.exe tests\packaged_test.py
```

该测试直接启动 `dist\EgressScope.exe --headless`，使用临时数据目录与随机端口，验证打包后的 Web 资源、介绍页、会话令牌与 API 鉴权、本地 CA 生成、真实 HTTPS 转发、PID 归因、AI 分类、DLP、加密正文的显式解密、脱敏导出、本地阻断、审计哈希链与端口释放。它由发布工作流在 Windows x64 / ARM64 上运行；本文档更新没有重新执行 PyInstaller，因此不在这里给出新的打包通过数。测试以 `--no-inherit-upstream` 启动，验证直连模式，并在临时数据目录预置 `config.json` 关闭开机自启，避免打包 EXE 往真实 Run 键写入指向临时目录的自启项；结束时只会结束自己启动的进程树，不修改系统代理或根证书。首次运行单文件 EXE 有解压开销，健康检查最多等待 120 秒。

### 关机实验工具（非 CI）

`tools/shutdown_lab.ps1` 是可选的一次性虚拟机实验工具：`prepare` 阶段记录注册表快照并安排 `-Phase verify`，`verify` 阶段检查恢复日志并写出 `lab-report.json` / `lab-report.txt`。`prepare` 必须显式传入 `-ConfirmReboot`，并会在 20 秒后真正重启、关机或注销当前虚拟机；请先创建快照。

它**只是实验工具，不是本版的验证结论**：本版没有在 CI 或真实虚拟机执行重启、关机或注销，关机钩子只有契约测试（模拟 `WM_QUERYENDSESSION` / `WM_ENDSESSION`），不构成真实重启验证。

### 构建可执行文件

```bat
build.bat
```

或手动执行：

```bat
.venv\Scripts\pyinstaller.exe build.spec --noconfirm --clean
```

产物：`dist\EgressScope.exe`（Windows 单文件、无控制台窗口）。首次启动会解压运行时，耗时数秒属于正常现象。构建会收集 mitmproxy、mitmproxy_rs（Rust 组件）、证书资源、本地 Web 页面与 Windows 托盘依赖；如果升级 mitmproxy 或托盘依赖版本，请重新运行完整测试。

构建 Windows x64 安装包（需要 Inno Setup 6.0+，发布工作流会自动执行）：

```bat
set EGRESS_SCOPE_VERSION=0.4.0
set EGRESS_SCOPE_EXE=%CD%\dist\EgressScope.exe
set EGRESS_SCOPE_OUTPUT_DIR=%CD%\dist
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\EgressScope.iss
```

产物为 `dist\EgressScope-Setup-v0.4.0.exe`。安装包只允许 x64（`ArchitecturesAllowed=x64`），不提供 ARM64 版本。

构建产物默认未做代码签名；如需分发，建议使用组织自己的代码签名证书对 EXE 与安装包签名，并重新生成校验清单：

```bat
certutil -hashfile dist\EgressScope.exe SHA256
```

仓库的发布工作流在配置 `WINDOWS_CERT_PFX_BASE64`（以及可选的 `WINDOWS_CERT_PASSWORD`）后，会对 Windows x64 EXE 与安装包执行可选的 `signtool` 签名；未配置时保持未签名。macOS / Linux 产物未签名。

如果打包时遇到 EXE 被扫描程序短暂占用导致资源写入失败，请关闭占用该文件的扫描/索引进程后重试，或先构建到新的输出目录（`--distpath dist-new`）再替换。

### 手动验证建议

1. 用安装包安装到固定目录，启动程序并打开审计台，确认无需管理员权限、开始菜单存在 **恢复系统代理**。
2. 只给一个临时终端注入 `agent-env.cmd`，用 `curl https://api.openai.com/v1/models`（无有效 Key 也可）验证代理连通。
3. 在审计台看到流量后，确认进程名、TLS、风险、可见性等级与覆盖方式。
4. 发送一段包含测试密钥（如 `sk-proj-` 前缀的假值）的请求，验证风险发现、预览脱敏与显式解密。
5. 开启阻断，重复请求，确认返回 `403` 且证据库标记为已阻断 / `blocked`。
6. Windows 托盘验证：关闭主窗口应隐藏并出现一次气泡；托盘“暂停审计”应停止新证据与旁路观测；托盘“退出并恢复系统代理”应正常关停；`--no-tray` 启动后关闭应直接退出。
7. 勾选断网保护后启用系统代理，打开「任务计划程序」确认存在 `EgressScope Proxy Recovery`，并在「注册表编辑器」中确认 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 下有 `EgressScope` 值；移动或重命名程序后运行 `--repair-integrations`，确认 Run 键被重写；手动结束程序进程，2 分钟内观察 `%LOCALAPPDATA%\EgressScope\logs\proxy-recovery.log` 中系统代理被恢复、任务被自动停用。
8. 保持系统代理启用，确认启动日志包含 `shutdown/logoff proxy restore hook installed` 且其中 `window=True`；执行一次 Windows 注销或重启（可在快照虚拟机中），重新登录后确认系统代理已被还原为启用前的值（优雅恢复），且程序已随登录隐藏启动到托盘。更高风险的关机实验请使用 `tools/shutdown_lab.ps1`，并先创建虚拟机快照。
9. 程序运行时直接编辑 `%LOCALAPPDATA%\EgressScope\data\config.json`（例如把 `retention_days` 改成 30），2 秒后在审计台“策略与设置 → 接入与代理”确认 `config_reload` 显示了本次生效的键名；再把文件改成非法 JSON，确认控制台热更新卡片标红为“配置有误 · 保留设置”，且当前设置没有被重置。
10. 在覆盖范围页观察直连 / QUIC / DNS 候选，确认它们被明确标注为候选、没有内容，也没有被重定向；暂停采集后确认计数不再增长。
11. 运行 `EgressScope.exe --check-update` 确认输出 JSON 且不安装；在“版本与更新”里手动检查一次，确认显示当前版本、最新版本与安装条件。
12. 结束后移除 CA、恢复系统代理、关闭开机自启并清空测试数据；卸载时确认安装程序会恢复代理并移除自启项。

---

## 安全边界与使用约束

**这是本项目的核心约束，不是附属声明。**

- 仅审计你拥有或已获得明确书面授权的设备。未经授权拦截他人流量可能违法。
- 安装本地 CA 会扩大本机可被中间人解密的范围。只在受控设备上安装；审计结束后移除。
- 怀疑设备已被未知恶意软件控制时，**不要**在日常设备上安装受信 CA。请在隔离虚拟机 / 快照中分析，避免让攻击者利用你的审计信任边界。
- 不要用本工具拦截、修改或伪造第三方服务流量；它的目的是本机可见性与合规审计。
- 不承诺破解证书固定、mTLS、E2EE 或恶意程序的私有加密。连接元数据、旁路候选与内容可见性是三件事；`metadata` 行和 `quic` 候选都不是已解密内容。
- 直连 / QUIC / DNS 观测只做检测，不重定向、不拦截、不安装驱动、不解密 QUIC。候选可能来自上游代理、非 HTTP 协议或短连接，不能单独作为数据外发的事实结论。
- 阻断是“本地拒绝转发”，不是网络层防火墙；它不能阻止应用换用直连或自行实现协议。WFP / WinDivert 透明重定向尚未实现。
- 风险分是启发式信号。不要把单条发现直接当作违规事实；结合进程、目标、业务语境和人工复核。
- 哈希链提供篡改可见性基线，但不是不可篡改的外部公证。
- 文件触达是打开句柄抽样，不能证明一次读取已经发生，也不覆盖已关闭的句柄；文件内容从不读取。
- 托盘“暂停审计”只停止写入新证据与旁路观测，不会移除 CA 或恢复系统代理；关闭窗口也可能只是隐藏。需要停止审计时请使用托盘退出或 `--no-tray` 后关闭。
- 安装包与 Windows 可执行文件默认未签名；SHA-256 校验保证下载内容与发布页一致，但不验证发布者身份。请只从官方 Release 下载，并在条件允许时核验代码签名。
- 自动更新只对 Windows x64 提供，且必须通过 SHA-256 校验；Windows ARM64、Linux、macOS 需手动下载。更新器只接受 HTTPS 与 GitHub 控制域名，不会把审计数据上传到 GitHub。
- 使用前请确认组织内的监控、数据保护与员工告知要求；在需要告知或同意的场景中，先完成相应流程。

---

## 路线图与已知限制

### v0.4.0 已交付

- Windows x64 per-user 安装包、固定安装目录、可选桌面快捷方式与卸载时恢复代理 / 移除自启。
- GitHub Releases 更新检查、SHA-256 强制校验、Windows x64 自动安装，以及 `update_check_enabled` / `--check-update`。
- 当前用户 Run 键与断网保护任务的自愈，以及独立的 `--restore-proxy` / `--repair-integrations`。
- 流量可见性分级（完整 / 部分 / 仅元数据 / 已阻断 / 错误）与旧库迁移。
- 只读连接表观测：直连、QUIC、DNS 候选（检测，不是重定向或解密）。
- Windows 通知区域托盘、关闭隐藏、暂停/恢复与退出恢复代理。
- 一次性虚拟机关机实验工具（可选，未在 CI / 真实 VM 执行）。

### P1（扩大入口，不放松诚实边界）

- WFP / WinDivert 透明重定向，覆盖不遵循系统代理的应用；需要驱动签名、兼容性与误伤评估。
- Agent / MCP 清单与会话导入，补充代理层看不到的 Agent 私有数据。
- SIEM / OpenTelemetry 导出、导出签名与可信时间戳。
- 规则包签名、企业策略分发与更完整的自托管模型端点清单。
- 代理链路健康检查、误报反馈与更细的覆盖诊断。

### P2（系统与文件视角）

- ETW / SACL / USN / 文件系统微过滤驱动级别的完整读取审计。
- Windows 服务 / SYSTEM 会话的进程归因与机器级部署。
- 与网络时间线关联的文件读取证据视图。
- 企业级留存、告警与只读审计员角色。
- macOS / Linux 的代理接管、CA 安装与托盘等价能力。
- 关机实验工具的虚拟机自动重启/注销编排（当前需人工执行 `shutdown_lab.ps1`）。

### 已知限制（主动暴露）

- 不解析、不解密 QUIC / HTTP3；只记录 UDP 443 候选元数据。没有 WFP / WinDivert 透明重定向。
- 不绕过证书固定、mTLS、E2EE；握手失败只记录 metadata 与原因，不伪造完整记录。
- 服务 / SYSTEM 进程覆盖不完整。
- 文件触达不读取文件内容，只记录元数据。
- 流式响应正文不保存，仅保留元数据；WebSocket 消息不持久化。
- 上游链路可热更新（保存后自动重连并重新校准系统代理），但不支持代理认证、PAC 自动发现、SOCKS 上游；监听端口、Web 端口与证书目录改动仍需重启。
- Linux / macOS 构建不提供一键安装 CA、系统代理接管或托盘，也不写开机自启项；需手动信任公开证书并注入环境变量。
- 关机 / 注销优雅恢复依赖系统把会话结束消息投递给本进程；直接断电、内核崩溃或强制结束进程时收不到，恢复退化为下一次登录后的启动校准与看门狗。`tools/shutdown_lab.ps1` 未在 CI 或真实虚拟机执行，不能据此宣称真实重启验证完成。
- 断网保护看门狗与开机自启都只覆盖当前登录用户，且依赖 Windows 任务计划程序与 Run 键。若策略禁止创建计划任务、任务被删除、自启被组策略清理或数据目录被清空，异常退出后需要手动恢复代理（`--restore-proxy`）或重新运行 `--repair-integrations`。
- Linux 进程归因依赖 `/proc/net/tcp`；macOS 非 root 无法读取系统 TCP 归属表，PID 归因会降级；Windows 为完整归因路径。
- Linux / macOS 与 Windows ARM64 产物未在开发机上逐一执行；Windows ARM64 的源码冒烟与打包验收在 GitHub 的 `windows-11-arm` runner 上完成，桌面 Tk 控制台与托盘未做 ARM64 实机 UI 验收。
- 托盘只在 Windows x64 做过人工冒烟验证；打包 CI 不启动真实桌面 UI，`tests/tray_test.py` 使用假实现。
- mac 与 Linux 二进制未签名；Windows EXE 与安装包默认未签名，除非仓库配置签名密钥。macOS Gatekeeper 与 Windows SmartScreen 都可能要求手动放行。
- Windows ARM64 使用上游最后的 `cryptography 46.0.3` wheel，并在构建时从源码编译 `aioquic`、`mitmproxy_rs` 与 `brotli`；`aioquic` 依赖的 ARM64 OpenSSL 由 CI 通过 vcpkg 构建，`libcrypto` 运行库已随 EXE 打包。这是可复现的构建约束，不影响 HTTP 代理审计路径。
- 旁路观测每 15 秒采样一次，短于采样间隔的连接可能遗漏；DNS 域名补全仅限 Windows 解析缓存，缓存未命中时只有 IP；候选可能误报，不能替代内容证据。
- 更新检查依赖 GitHub 网络可达；自动安装仅 Windows x64，SHA-256 校验不等同于发布者身份验证。
- 单文件可执行包较大，首次启动有解压开销。
- UI 与 API 面向本机单用户审计，不提供多租户或远程访问。

---

## License / 使用声明

本项目为本地安全审计工程与产品原型。使用即表示你理解并接受上述授权、安全与覆盖边界。对因超出授权范围使用、在生产设备上安装审计 CA、或依赖启发式风险分做出处置而造成的后果，作者不承担责任。
