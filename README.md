# EgressScope

**本机数据外发审计 · Local Egress Audit for AI Agents & Desktop Apps**

项目名：**EgressScope**（中文：本机数据外发审计；仓库：[1wu-davy-2/EgressScope](https://github.com/1wu-davy-2/EgressScope)）。

- 官网 / 产品介绍页：<https://1wu-davy-2.github.io/EgressScope/>
- 发布版本与 SHA-256 校验：<https://github.com/1wu-davy-2/EgressScope/releases/latest>

EgressScope 是一个以 Windows 为主的本机审计工具。它在用户明确授权的前提下，通过本地 HTTP/HTTPS 转发代理、本地 CA、进程归因和内容策略，回答一个传统流量面板经常回答不了的问题：

> **是谁，在什么时候，把什么内容，发到了哪里？**

它面向 AI Agent、IDE 插件、脚本运行时，也适用于其他需要观察数据外发行为的桌面应用。所有证据默认保存在本机，不依赖云端服务。

> 仅用于你拥有或已获明确授权的设备。不要在日常使用、存有真实凭据的设备上分析疑似恶意软件；受信 CA 会扩大本机可被中间人解密的范围。未知样本请在隔离虚拟机或快照中处理。详见[安全边界](#安全边界与使用约束)。

---

## 目录

- [交付内容](#交付内容)
- [快速开始](#快速开始)
- [平台与 GitHub Actions](#平台与-github-actions)
- [它解决什么问题](#它解决什么问题)
- [架构与取舍](#架构与取舍)
- [风险引擎](#风险引擎)
- [覆盖范围：能看见与看不见](#覆盖范围能看见与看不见)
- [数据与隐私设计](#数据与隐私设计)
- [项目结构](#项目结构)
- [开发、测试与构建](#开发测试与构建)
- [安全边界与使用约束](#安全边界与使用约束)
- [路线图与已知限制](#路线图与已知限制)

---

## 交付内容

| 产物 | 位置 | 说明 |
| --- | --- | --- |
| Windows 可执行文件 | `dist\EgressScope.exe` | 单文件 GUI 程序；双击启动桌面控制台。未做代码签名，详见下方说明 |
| 静态产品介绍页 | `web\intro.html` | 可直接双击打开的完整介绍页；启动程序后同样可通过 `/intro` 访问 |
| 本机审计台 | 启动后 `http://127.0.0.1:8898/` | 流量、发现、文件触达、覆盖范围、策略设置 |
| 桌面控制窗口 | 可执行文件启动后的主窗口 | 安装/移除 CA、启用/恢复系统代理、暂停采集、导出证据 |
| 构建校验清单 | `dist\SHA256SUMS.txt` | 可执行文件的 SHA-256，用于确认文件完整性 |
| GitHub Actions | `.github/workflows/` | CI 冒烟、五平台发布构建、介绍页 Pages 部署 |
| GitHub Release | [releases/latest](https://github.com/1wu-davy-2/EgressScope/releases/latest) | Windows x64、Linux x64 / arm64、macOS x64 / arm64；每个产物附带 `.sha256` 与汇总 `SHA256SUMS.txt` |
| 研究/执行计划 | `PLAN.md` | 本项目的技术与产品调研底稿 |

审计台固定访问 `http://127.0.0.1:8898/`（端口可在设置中修改）。`18898` 只是自动化测试临时使用的端口，不是产品默认端口；临时测试进程关闭后访问会被拒绝。

首次启动会在 `%LOCALAPPDATA%\EgressScope` 下生成数据目录、数据库和审计 CA。**不会自动安装根证书，也不会自动修改系统代理**；两者都需要在桌面控制窗口中显式确认。

> 当前构建未做 Authenticode 代码签名，Windows SmartScreen 可能显示“未知发布者”。请先核对 `dist\SHA256SUMS.txt` 中的哈希，再决定是否运行；不要从来源不明的渠道获取本程序。

---

## 快速开始

### 方式一：直接运行可执行文件

1. 双击 `dist\EgressScope.exe`。
2. 在控制窗口中点击 **打开审计控制台**，先熟悉界面与当前覆盖状态。
3. 如需审计 HTTPS 正文，点击 **安装本地 CA（当前用户）**，确认 Windows 安全警告中的证书名为 `EgressScope Local Audit CA`。
4. 二选一接入流量：
   - **系统代理**：点击 **启用系统代理**。只影响遵循 WinINet / 系统代理设置的应用；退出时会尝试恢复原设置。
   - **单 Agent 环境变量**：点击 **复制 Agent 环境变量**，在启动目标 Agent 的终端先运行生成的脚本。影响范围更小，适合先验证一个 Agent 或 IDE 插件。
5. 如果本机原本通过 Clash、v2rayN 等本地 HTTP 代理上网，EgressScope 启动时会自动识别 **当前生效的回环系统代理** 并串联它，避免接管后断网；也可以在“策略与设置 → 上行链路”手动指定。该设置需重启程序生效。
6. 回到审计控制台，查看流量、风险和发现。
7. 结束审计时关闭控制窗口：程序会停止代理并尝试恢复系统代理；仍不再需要 HTTPS 解密时，点击 **移除本地 CA**。

### 方式二：从源码运行

需要 Windows 10/11 与 Python 3.12+。

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
--home PATH          覆盖数据目录
--proxy-port PORT    本地代理端口（默认 8899）
--web-port PORT      审计台端口（默认 8898）
--upstream-proxy URL 串联的上游 HTTP/HTTPS 代理，如 http://127.0.0.1:7890
--no-inherit-upstream 不自动继承当前回环系统代理
--upstream-ca PEM    额外的上游 CA（测试）
--insecure-upstream  关闭上游 TLS 校验（仅测试）
--no-fileguard       关闭打开句柄抽样
--open               启动后打开审计台
--log-level LEVEL    DEBUG / INFO / WARNING / ERROR
```

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

---

## 平台与 GitHub Actions

### 产物矩阵

| 平台 | 产物 | 桌面控制台 | 一键 CA / 系统代理 | 说明 |
| --- | --- | --- | --- | --- |
| Windows x64 | `EgressScope-<tag>-windows-x64.exe` | ✅ | ✅ | 主要发行版本 |
| Linux x64 | `EgressScope-<tag>-linux-x64.tar.gz` | 命令行 / Web | ❌ | 审计引擎 + 本机审计台；手动信任 CA，使用环境变量接入 |
| Linux arm64 | `EgressScope-<tag>-linux-arm64.tar.gz` | 命令行 / Web | ❌ | 使用 `ubuntu-24.04-arm` 构建 |
| macOS x64 | `EgressScope-<tag>-macos-x64.tar.gz` | 命令行 / Web | ❌ | `macos-15-intel` 构建；Intel 版固定使用兼容的 `cryptography 47.0.0` |
| macOS arm64 | `EgressScope-<tag>-macos-arm64.tar.gz` | 命令行 / Web | ❌ | Apple Silicon；未签名，首次运行需在系统设置中放行 |
| Windows arm64 | — | — | — | 暂不构建原生版本：`mitmproxy_rs 0.12.15` 没有 `win_arm64` wheel；可在 Windows 11 ARM64 上尝试运行 x64 构建（系统模拟层，未单独验证） |

Windows 版本是功能完整的桌面产品。Linux / macOS 版本共享同一套代理、归因、策略、证据和 Web 审计台，面向“手动配置代理与环境变量”的审计场景；系统代理备份/恢复、当前用户 CA 一键安装仍只支持 Windows。Linux 的 PID 归因依赖 `/proc/net/tcp`；macOS 在非 root 下无法读取系统 TCP 归属表，会诚实降级为不含 PID 的流量记录。

非 Windows 启动示例（发布包内的可执行文件名为 `EgressScope-<tag>-<platform>`）：

```bash
tar -xzf EgressScope-<tag>-linux-x64.tar.gz
./EgressScope-<tag>-linux-x64 --headless --home ~/.egressscope --proxy-port 8899 --web-port 8898
# 另一个终端加载接入变量
source ~/.egressscope/data/agent-env.sh
```

### 工作流

| 文件 | 触发 | 内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | push / PR / 手动 | Windows、Linux、macOS 上运行源码冒烟与上游链路测试 |
| `.github/workflows/release.yml` | `v*` tag / 手动 | 五平台构建并上传 Actions artifact；tag 时由一个 publish job 汇总所有产物、生成 `SHA256SUMS.txt` 并创建 GitHub Release |
| `.github/workflows/pages.yml` | push main（介绍页变更）/ 手动 | 把 `web/intro.html` 发布到 GitHub Pages |

### 首次推送到 GitHub

```bash
git remote add origin git@github.com:<owner>/EgressScope.git
git push -u origin main
```

发布一个版本：

```bash
git tag v0.1.0
git push origin v0.1.0
```

### GitHub Pages 官网

1. 推送代码后，在仓库 **Settings → Pages** 将 **Source** 设为 **GitHub Actions**（工作流也会尝试自动启用）。
2. 手动运行一次 **Deploy intro page**，或修改 `web/intro.html` 后推送到 `main`。
3. 页面地址通常为 `https://<owner>.github.io/EgressScope/`。
4. Pages 版本会把顶部和底部的“打开审计台”按钮改写为 **下载发布版本**，指向 `https://github.com/<owner>/EgressScope/releases/latest`；本地 `/intro` 与 `file://` 打开时仍指向本机审计台。

如果首次运行在 `configure-pages` 步骤报 `Resource not accessible by integration`，说明仓库尚未启用 Pages：在 **Settings → Pages** 把 **Source** 设为 **GitHub Actions**，再重新运行工作流。该一次性设置需要仓库管理员权限。

`macos-15-intel` 与 `ubuntu-24.04-arm` 属于 GitHub 公共仓库的托管运行器；如果仓库是私有且运行器不可用，保留其余平台构建或改用自托管 runner。

---

## 它解决什么问题

传统流量工具通常能显示连接、字节数和目标域名，但很难解释一次 AI 会话里到底夹带了什么。EgressScope 把四层信息串成一条证据链：

1. **入口**：请求是否真的经过审计器。
2. **内容**：在应用愿意配合、TLS 可终止时，请求正文是什么。
3. **发起者**：本机哪个 PID、哪条父进程链发起了连接。
4. **处置**：命中什么规则、风险分多少、是观察还是阻断，以及证据是否被完整保存。

这不是一个“抓包美化器”。它关注的是 AI 时代最常见、又最难解释的风险：上下文、源代码、环境变量、客户数据在一次普通 API 调用中被悄悄带出。

典型可回答的问题：

- `claude.exe` / `python.exe` / `Code.exe` 在向哪些 AI 端点发送请求？
- 请求里是否包含 API Key、私钥、身份证号、银行卡号或 `.env` 内容？
- 这次外发来自哪个进程和父进程链，而不是仅仅“来自本机”？
- 风险最高的请求能否被本地拦截，而不是只事后告警？
- 在没有密钥的情况下，哪些流量只能看到元数据？覆盖边界到底是什么？

---

## 架构与取舍

```text
AI Agent / 编辑器 / SDK / 普通桌面应用
                │
                ▼
   HTTP/HTTPS 本地转发代理（127.0.0.1:8899）
                │
                ▼
   TLS 终止（本地 CA，仅应用信任时）
                │
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
   策略引擎（AI 端点分类、DLP 规则、风险评分、处置）
                │
                ▼
   SQLite（WAL）＋ AES-GCM 证据正文＋ SHA-256 审计链
                │
                ▼
   本机 Web 审计台 + 桌面控制台
```

### 为什么选择“本地代理 + 本地 CA + 进程归因”

| 方案 | 内容可见性 | 落地成本 | 覆盖特点 | 主要问题 |
| --- | --- | --- | --- | --- |
| **本地代理 + 本地 CA（本版）** | 可终止 TLS 时有正文 | 低：无驱动、无内核签名 | 依赖应用使用代理并信任 CA | 证书固定、直连、服务进程、QUIC 不可见 |
| WFP / WinDivert 透明重定向 | 仍受 TLS 固定 / 信任限制 | 高：驱动、签名、兼容性 | 不依赖应用代理设置 | 部署重、误伤风险高、仍不是“解密银弹” |
| Agent 会话 / MCP 旁路 | 可读会话内容 | 低：读本地数据 | 仅覆盖特定 Agent 的私有格式 | 看不到真实外发网络路径，跨 Agent 不可复用 |
| 浏览器扩展 | 仅浏览器页面/请求 | 低 | 仅浏览器 | 桌面 Agent、CLI、后台服务完全看不到 |
| ETW / SACL / 文件过滤驱动 | 通常是事件而非内容 | 高 | 网络与文件事件范围广 | 事件量大、噪音高、需要管理员与规则工程 |

第一版选择本地代理，是因为它把“内容可见性”和“可解释的系统变更”放在了同一条工程路径上：

- 不需要内核驱动和代码签名，用户能理解它做了什么，也能随时停用。
- 内容、进程、策略、证据四件事可以闭环验证。
- 不依赖某个 Agent 的私有会话格式；Agent 换实现，代理层仍然成立。
- 允许用户从“只给一个 Agent 注入环境变量”开始，逐步扩大授权范围。
- 对不配合的流量，产品可以诚实降级为“只有元数据 / 完全不可见”，而不是伪装成全量可见。

**这不是也不能是“破解所有加密上传”的工具。** 本地 CA 只在应用信任它、且没有启用证书固定或双向 TLS 时有效。E2EE、QUIC 与恶意程序自建加密协议不在这条路径的可见范围内。

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

阻断默认关闭，阈值默认 85。开启阻断后，达到阈值的请求会被本地代理直接返回 `403 egress_policy_blocked`，并在证据库中标记为 blocked。建议先观察一段时间确认真实误报率，再启用阻断。

### 响应侧检查

响应正文也会扫描明显的密钥与 PII，但这类发现标记为 `direction=response` 且不计入请求外发风险，避免把上游返回的数据误算成本机泄露。列表与导出默认不包含响应原文。

---

## 覆盖范围：能看见与看不见

| 场景 | 第一版行为 | 说明 |
| --- | --- | --- |
| 系统代理生效后的 HTTP/HTTPS | ✅ 元数据 + 可解密正文 | 主要覆盖路径 |
| 本机已有 Clash / v2rayN 等回环 HTTP 代理 | ✅ 解密后串联上游 | 自动继承，避免接管后断网；需重启生效 |
| Agent 使用 `HTTP_PROXY` / `HTTPS_PROXY` | ✅ 元数据 + 可解密正文 | 推荐用于单 Agent 试点 |
| 应用信任本地 CA、无证书固定 | ✅ TLS 1.2 / 1.3 正文 | 受应用实现影响 |
| 应用忽略代理 / 直连 | ❌ 不可见 | 需要 WFP 透明重定向（路线图） |
| 证书固定 / mTLS / 双向校验 | ❌ 不可解密 | 不尝试绕过应用安全边界 |
| QUIC / HTTP3 / 非 HTTP 协议 | ❌ 第一版不解析 | 可能看到部分连接元数据 |
| 应用层端到端加密 | ❌ 无密钥不可读 | 不承诺破解 |
| Windows 服务 / SYSTEM 会话 | ⚠️ 覆盖不完整 | 当前代理与归因面向登录用户 |
| 完整文件读取历史 | ❌ 不提供 | 只有打开句柄抽样 Beta |
| 文件内容本身 | ❌ 从不读取 | 文件守护只记录元数据 |
| 浏览器扩展 / 页面内脚本 | ⚠️ 仅当其请求经过代理 | 不做浏览器进程内的额外采集 |

**“没看到”不等于“没有发生”。** 审计台把覆盖状态实时列出来，而不是把所有流量都笼统标记为已覆盖。

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
- **可撤销**：支持移除 CA、恢复原始系统代理、暂停采集、清空本地数据和导出脱敏证据。

### 数据位置

默认根目录：`%LOCALAPPDATA%\EgressScope`

```text
data\
  egress.db           SQLite 流量、发现、文件事件、审计链
  secret.bin          DPAPI 保护的数据加密主密钥
  certs\              审计 CA（公开证书可下载，私钥仅本地）
  exports\            JSONL 脱敏证据导出
  logs\               运行日志
  agent-env.cmd       Agent 环境变量脚本
canaries\             可选诱饵文件目录（如启用）
```

可通过 `--home` 或环境变量 `EGRESSSCOPE_HOME` 覆盖根目录。

---

## 项目结构

```text
ai-agent-audit/
├─ .github/workflows/
│  ├─ ci.yml               三平台冒烟与上游链路测试
│  ├─ release.yml          五平台构建与 GitHub Release
│  └─ pages.yml            介绍页 GitHub Pages 部署
├─ app.py                  启动入口、桌面/无头模式、生命周期
├─ ai_audit/
│  ├─ addon.py             mitmproxy 请求/响应钩子、证据落库
│  ├─ attribution.py       客户端端口 → PID / 父进程链
│  ├─ config.py            设置持久化与默认值
│  ├─ crypto.py            DPAPI + AES-GCM 封装
│  ├─ fileguard.py         打开句柄抽样 Beta + Canary
│  ├─ paths.py             数据目录、冻结/源码资源路径
│  ├─ policy.py            AI 识别、DLP 规则、风险评分
│  ├─ proxy.py             嵌入式代理与显式关闭监听
│  ├─ store.py             SQLite、加密证据、哈希链、导出
│  ├─ system.py            CA、系统代理、Windows 控制
│  ├─ ui.py                Tkinter 桌面控制窗口
│  └─ web.py               本地审计台 HTTP 服务与 API
├─ web/
│  ├─ dashboard.html       交互式审计台（无外部依赖）
│  └─ intro.html           产品介绍官网页面
├─ tests/
│  ├─ smoke_test.py        端到端冒烟测试（不修改系统设置）
│  ├─ upstream_test.py     上游代理串联与自动继承识别测试
│  └─ packaged_test.py     打包后可执行文件的端到端验证
├─ .gitignore              构建产物、虚拟环境、测试临时目录
├─ .gitattributes          跨平台换行与二进制标记
├─ build.spec              PyInstaller 单文件构建配置（Windows GUI，其他平台 console）
├─ build.bat               Windows 一键构建脚本
├─ requirements.txt        运行时依赖
├─ requirements-dev.txt    构建与测试依赖
└─ PLAN.md                 调研与执行计划
```

---

## 开发、测试与构建

### 环境

- 桌面控制台与系统级接入：Windows 10 / 11 x64（主要支持平台）
- 审计引擎与 Web 审计台：Windows、Linux、macOS（CI 构建 Linux x64/arm64、macOS x64/arm64）
- Python 3.12+
- 运行依赖：`mitmproxy 12.3.0`、`psutil 7.2.2`、`cryptography 50.0.2`（Intel macOS 构建使用兼容的 `47.0.0`）

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
- 使用真实本地 CA 完成一次 HTTPS 请求并校验流量落库、PID 归因、AI 分类、DLP、加密解密、阻断、哈希链、导出脱敏与 Web 鉴权；
- **不会**安装根证书、修改系统代理或触碰真实业务数据。

当前基线：53 项检查全部通过。测试使用 `--insecure-upstream` 仅针对 Mock 服务端，生产运行不要开启；同时显式关闭系统代理继承，避免连接本机日常使用的代理。CI 会在 Windows、Linux、macOS 三平台运行同一套源码测试；Windows 的本地验证同时覆盖打包 EXE。

上游链路测试：

```bat
.venv\Scripts\python.exe tests\upstream_test.py
```

它会启动一个最小 CONNECT 中继，验证审计流量确实经上游转发、正文仍能捕获，并覆盖自动继承的识别条件（回环、PAC、非回环、排除端口）。当前基线：15 项检查全部通过。

### 打包产物测试

```bat
.venv\Scripts\python.exe tests\packaged_test.py
```

该测试直接启动 `dist\EgressScope.exe --headless`，使用临时数据目录与随机端口，验证：

- 打包后的 Web 资源、介绍页、会话令牌与 API 鉴权；
- 本地 CA 生成、真实 HTTPS 转发与上游响应；
- PID 归因、AI 分类、DLP 命中、风险评分；
- 加密正文的默认隐藏与显式解密；
- 脱敏导出、本地阻断与审计哈希链；
- 退出后代理与 Web 端口释放。

当前基线：46 项检查全部通过。测试以 `--no-inherit-upstream` 启动，验证直连模式；结束时只会结束自己启动的进程树，不修改系统代理或根证书。首次运行单文件 EXE 有解压开销，健康检查最多等待 120 秒。

### 构建可执行文件

```bat
build.bat
```

或手动执行：

```bat
.venv\Scripts\pyinstaller.exe build.spec --noconfirm --clean
```

产物：`dist\EgressScope.exe`（Windows 单文件、无控制台窗口，约 33 MB）。首次启动会解压运行时，耗时数秒属于正常现象。

构建产物未做代码签名；如需分发，建议使用组织自己的代码签名证书对 EXE 签名，并重新生成校验清单：

```bat
certutil -hashfile dist\EgressScope.exe SHA256
```

如果打包时遇到 EXE 被扫描程序短暂占用导致资源写入失败，请关闭占用该文件的扫描/索引进程后重试，或先构建到新的输出目录（`--distpath dist-new`）再替换。

打包时会收集 mitmproxy、mitmproxy_rs（Rust 组件）、证书资源与本地 Web 页面；如果升级 mitmproxy 版本，请重新运行完整冒烟测试，重点验证代理启动、TLS 终止和证书生成。

### 手动验证建议

1. 启动程序，打开审计台。
2. 只给一个临时终端注入 `agent-env.cmd`，用 `curl https://api.openai.com/v1/models`（无有效 Key 也可）验证代理连通。
3. 在审计台看到流量后，确认进程名、TLS、风险与覆盖方式。
4. 发送一段包含测试密钥（如 `sk-proj-` 前缀的假值）的请求，验证风险发现、预览脱敏与显式解密。
5. 开启阻断，重复请求，确认返回 `403` 且证据库标记为已阻断。
6. 结束后移除 CA、恢复系统代理并清空测试数据。

---

## 安全边界与使用约束

**这是本项目的核心约束，不是附属声明。**

- 仅审计你拥有或已获得明确书面授权的设备。未经授权拦截他人流量可能违法。
- 安装本地 CA 会扩大本机可被中间人解密的范围。只在受控设备上安装；审计结束后移除。
- 怀疑设备已被未知恶意软件控制时，**不要**在日常设备上安装受信 CA。请在隔离虚拟机 / 快照中分析，避免让攻击者利用你的审计信任边界。
- 不要用本工具拦截、修改或伪造第三方服务流量；它的目的是本机可见性与合规审计。
- 不承诺破解证书固定、mTLS、E2EE 或恶意程序的私有加密。连接元数据与内容可见性是两件事。
- 阻断是“本地拒绝转发”，不是网络层防火墙；它不能阻止应用换用直连或自行实现协议。
- 风险分是启发式信号。不要把单条发现直接当作违规事实；结合进程、目标、业务语境和人工复核。
- 哈希链提供篡改可见性基线，但不是不可篡改的外部公证。
- 文件触达是打开句柄抽样，不能证明一次读取已经发生，也不覆盖已关闭的句柄。
- 使用前请确认组织内的监控、数据保护与员工告知要求；在需要告知或同意的场景中，先完成相应流程。

---

## 路线图与已知限制

### P1（扩大入口，不放松诚实边界）

- WFP / WinDivert 透明重定向，覆盖不遵循系统代理的应用。
- QUIC 元数据可见性与降级提示。
- 更完整的本地模型端点与自托管服务清单。
- 规则包签名、证据导出签名与企业策略分发。
- 代理链路健康检查与更细的误报反馈。

### P2（系统与文件视角）

- ETW / SACL / 文件系统微过滤驱动级别的完整读取审计。
- Windows 服务 / SYSTEM 会话的进程归因。
- 与网络时间线关联的文件读取证据视图。
- 企业级留存、告警与只读审计员角色。

### 已知限制（第一版主动暴露）

- 不解析 QUIC / HTTP3。
- 不绕过证书固定、mTLS、E2EE。
- 服务 / SYSTEM 进程覆盖不完整。
- 文件触达不读取文件内容，只记录元数据。
- 流式响应正文不保存，仅保留元数据。
- 上游链路修改需重启生效；不支持代理认证、PAC 自动发现、SOCKS 上游。
- Linux / macOS 构建不提供一键安装 CA 或接管系统代理；需手动信任公开证书并注入环境变量。
- Linux 进程归因依赖 `/proc/net/tcp`；macOS 非 root 无法读取系统 TCP 归属表，PID 归因会降级；Windows 为完整归因路径。
- Linux / macOS、macOS Intel、Windows ARM 等产物未在本机逐一验证；以 GitHub Actions 的构建结果为准。Windows ARM64 目前只能尝试 x64 模拟运行，不宣称原生支持。
- mac 与 Linux 二进制未签名；macOS Gatekeeper 与 Windows SmartScreen 都可能要求手动放行。
- Windows arm64 暂无官方构建，原因是 `mitmproxy_rs 0.12.15` 缺少 `win_arm64` wheel。
- 单文件可执行包较大，首次启动有解压开销。
- UI 与 API 面向本机单用户审计，不提供多租户或远程访问。

---

## License / 使用声明

本项目为本地安全审计工程与产品原型。使用即表示你理解并接受上述授权、安全与覆盖边界。对因超出授权范围使用、在生产设备上安装审计 CA、或依赖启发式风险分做出处置而造成的后果，作者不承担责任。
