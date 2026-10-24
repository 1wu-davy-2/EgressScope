# AI Agent / 本机数据外发审计系统 — 调研与执行计划

> 版本：v0.2（2026-10-24，补充文件读取、Windows 服务覆盖与加密边界）  
> 目标平台：Windows 10/11 x64 优先，后续 macOS / Linux  
> 文档性质：技术调研 + 实施计划，尚未开始编码  
> 安全边界：仅用于本人设备或已获得明确授权的设备；默认可见、可暂停、可卸载，不做隐蔽监控。  
> **定位修订：** 产品不再只做「AI Agent 抓包」，而是「本机数据外发与数据流审计」。AI Agent 是第一个策略包；流氓软件、后台服务、浏览器扩展、计划任务、普通桌面应用同样纳入。  
> **能力承诺修订：** 不做「破解加密」的承诺。能解密处看内容；不能解密处看文件读取 → 进程 → 网络外发的行为链。

---

## 0. 结论摘要

1. **这个方向有真实空白。** 开源世界里已有「按进程的网络防火墙」（OpenSnitch、Portmaster、LuLu、simplewall）和「LLM/MCP 网关/可观测性」（mcp-firewall、agentgateway、LiteLLM、Langfuse），但**在 Windows 上同时做到「进程级归因 + HTTPS 正文审计 + AI 应用识别 + 本地策略/证据链」的成熟开源项目，本次调研没有发现**。
2. **最接近的参考是 AgentSight。** 它用 Linux eBPF + SSL uprobe 在 TLS 读写边界抓明文，不需要代理和 CA；但 eBPF 采集是 Linux-only，Windows 版本目前主要读取 Claude/Codex/Gemini 等 Agent 自己的会话文件，不做系统级 TLS 正文捕获。
3. **Windows 上「抓正文」没有银弹。** 必须同时解决两个独立问题：  
   - **流量怎么进审计器**：系统代理 / 环境变量代理 / 透明重定向（WFP/WinDivert）；  
   - **TLS 怎么解密**：本地 CA + 应用信任该 CA，或改用 Agent 原生会话/MCP 代理等旁路数据源。  
   这两件事的覆盖面不同，产品必须诚实展示「哪些应用已审计、哪些只看到元数据、哪些完全没覆盖」。
4. **推荐路线：先做「系统代理 + 本地 CA + 进程归因」的 Windows MVP，再补透明代理驱动。** MVP 以 AI 应用为主要内容审计对象，其他应用默认只记连接元数据；这样隐私、性能、兼容性风险都可控。透明重定向放到二期，不要一上来写内核驱动。
5. **最大风险不是写不出代理，而是兼容性和信任。** Node/Electron 主进程、Python/httpx、证书 pinning、QUIC、公司代理/VPN/TUN、代理崩溃后断网，都会直接影响可用性。P0 必须先做兼容性矩阵和失效恢复验证。
6. **建议 MVP 技术栈：Python 3.12 + mitmproxy + SQLite + PySide6（或本地 Web UI）。** 这与当前工作区的 Python/PySide6 经验一致，能最快验证价值；代理/策略/存储接口保持模块化，后续可将代理核心换成 Rust（hudsucker）或加 C++/Rust WFP 驱动。
7. **「解密」要分层看。** TLS 本身不是问题：只要应用信任本地 CA 且没有 pinning，就能做授权 MITM，看到 HTTPS 里的 JSON。真正看不到的是：证书 pinning/mTLS、QUIC 直连、应用层端到端加密、恶意软件自定义加密协议。对这些场景不能承诺「破解」，只能做元数据/行为/文件访问关联，或在隔离环境里做逐样本逆向。
8. **如果目标包含「流氓软件偷偷读文件再上传」，核心能力应是「文件读取 + 网络外发关联」，而不是只抓正文。** 即使上传内容被加密，仍可检测：某进程读取了哪些敏感文件、读了多大、随后连接了哪个新域名/IP、上传了多少、时间是否吻合。这个行为链对 AI Agent、后台服务、流氓软件都适用。
9. **Windows 服务/后台进程是另一个覆盖层。** 当前用户代理和 CurrentUser CA 通常覆盖不到 SYSTEM 服务；这些进程可能用 WinHTTP、原始 socket、自带 TLS 库，甚至驱动。MVP 先明确「用户态应用优先」，P2 再做机器级服务 + WFP/ETW/透明代理。

**规模预估：** P0 约 2–3 周；只做「网络元数据 + AI 内容审计」的 P1a 约 4–6 周；再加「敏感文件读取关联」的 P1b 约 3–4 周；带透明代理、服务覆盖、阻断、MCP、多用户的较完整版本约 5–7 个月（1–2 人）。如果一开始就做内核驱动和全量覆盖，周期和风险都会显著上升。

---

## 1. 问题定义

### 1.1 要解决的场景

AI Agent / AI 编程工具 / 普通桌面应用在用户不知情或未授权的情况下：

- 把源代码、`.env`、密钥、内部文档、聊天记录上传到外部 API；
- 连接未批准的 AI 厂商、中转站、未知域名；
- 被提示词注入后，把本地数据发往攻击者端点；
- 通过 MCP 工具、子进程、浏览器自动化间接外发数据；
- 后台静默调用模型，产生费用与合规风险；
- 后台服务、流氓软件、浏览器劫持程序读取文档/密钥/源码，再上传到未知服务器；
- 普通应用/更新器/遥测组件在后台持续上传用户数据，用户无法说清「谁读了什么、发到了哪里」。

### 1.2 产品目标

- **看得见**：按进程/应用展示网络连接、目标域名、请求内容摘要、数据量、时间线。
- **认得准**：把连接归因到具体 PID、可执行文件、签名者、父进程，进而识别 AI Agent 及其子进程。
- **判得了**：基于目标域名、请求结构、敏感数据、代码特征、上传量、应用白名单等给出可解释的风险结论。
- **连得上（关键增强）**：把「文件读取 → 进程 → 网络外发」串成数据流证据；即使正文被加密，也能回答「谁读了什么、什么时候、发了多少、发到哪」。
- **留得住**：本地加密存储、可检索、可导出、带完整性校验的审计证据。
- **管得住（可选）**：对明确违规的请求执行告警、阻断、脱敏或人工确认。
- **不添乱**：代理故障时自动恢复网络；不破坏已有公司代理/VPN；默认不上传任何审计数据到云端。

### 1.3 非目标（至少 MVP 不做）

- 不是 EDR/杀毒：不承诺对抗内核级恶意软件、进程注入、定制加密 C2。
- 不是全流量 DPI：不解析所有私有协议；gRPC、QUIC、E2EE 内容默认只能看到元数据。
- 不是隐蔽监控软件：不提供隐藏运行、规避用户发现、绕过安全软件的功能。
- 不是通用恶意软件清除/杀毒产品：可以检测和取证可疑外发行为，但不承诺查杀、移除驱动级恶意软件。
- 不是「万能解密器」：不破解证书 pinning、mTLS、应用层 E2EE 或恶意软件自定义加密。
- 不默认抓取所有应用的完整正文：默认只对 AI 相关端点抓正文，其余应用只记元数据。
- MVP 不做全盘文件读取监控：先对「敏感目录」做有限读取审计（SACL/金丝雀文件），P2 再评估 ETW/minifilter 全量方案。

### 1.4 威胁模型与边界

**覆盖：** 正常但权限过大的 AI Agent、影子 AI、误上传、提示词诱导外发、未知应用连接 AI 端点；读取敏感文件后上传的后台服务/流氓软件（在权限和可见性允许范围内）。  
**不覆盖：** 已拿到管理员权限、能篡改审计器/CA/代理的恶意软件；内核级 rootkit/驱动；使用证书 pinning 且拒绝信任本地 CA 的应用；应用层 E2EE/自定义加密协议；走 TUN/VPN 且未接入审计器的流量；服务使用原始 socket 且拒绝代理、又不愿上透明驱动的场景。  
**结论：** 审计是「检测与取证」层，不是「隔离」层。对流氓软件/高安全场景，必须配合应用管控、防火墙出口白名单、独立用户/虚拟机/网络隔离。

---

## 2. 同类项目调研

### 2.1 项目清单

| 项目 | 平台 / 类型 | 关键能力 | 对本项目的价值与局限 |
|---|---|---|---|
| [AgentSight](https://github.com/eunomia-bpf/agentsight) | Linux eBPF；Rust/C；MIT | 系统级观察 AI Agent：进程、文件、网络、Prompt/模型调用；在 SSL 读写边界抓明文，无需 SDK/代理；Windows 可读取 Agent 原生会话文件 | **最接近的概念参考**。但 eBPF/TLS 采集 Linux-only；Windows 不做系统级正文捕获；偏观测，不是策略/阻断/DLP 产品 |
| [OpenSnitch](https://github.com/evilsocket/opensnitch) | Linux；Python/Go；GPL-3.0 | 交互式按应用出站防火墙，连接提示、规则、进程归因 | 交互和规则模型可借鉴；无正文审计；Linux-only |
| [Portmaster](https://github.com/safing/portmaster) | Windows/Linux；GPL-3.0 | 按应用网络防火墙/隐私控制；Windows 侧有内核组件与 IP Helper API 归因 | 证明 Windows 上进程归因可行；默认不做通用 TLS 正文解密；GPL 代码不适合闭源直接复用 |
| [LuLu](https://github.com/objective-see/LuLu) | macOS；GPL-3.0 | 开源出站防火墙，未知连接提示 | macOS 交互/UX 参考；无内容审计 |
| [simplewall](https://github.com/henrypp/simplewall) | Windows；C；GPL-3.0 | 基于 WFP 的按应用网络规则 | Windows 阻断/规则参考；不检查包内容；GPL |
| [WinDivert](https://github.com/basil00/WinDivert) | Windows；C；LGPL-3.0 | 用户态抓包/改包/重定向，带签名驱动 | 透明重定向的可行路径；包本身不带 PID，需 `GetExtendedTcpTable` 等旁路归因；LGPL 商用需法务确认 |
| [WFP Traffic Redirection Driver](https://github.com/bot-man-jl/wfp-traffic-redirection-driver) | Windows；C；GPL-3.0 | WFP 网络层/帧层流量重定向示例 | 透明代理驱动参考；GPL，不能直接搬进闭源产品；驱动签名/稳定性成本高 |
| [ProxyIntercept](https://github.com/huaraz/ProxyIntercept) | Windows；C | 用 WFP callout 做代理拦截的实验 | 仅作技术验证参考；仓库无明确许可证，避免复用代码 |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | 跨平台；Python；MIT | 成熟 TLS MITM 代理；HTTP/1.1、HTTP/2、WebSocket、SSE、Addon API、证书生成、透明/上游/SOCKS 等模式 | **MVP 最合适的代理内核**；但 Windows 不支持 transparent 模式（官方为 Linux/macOS），Windows 需要显式代理或外部重定向 |
| [hudsucker](https://github.com/omjadas/hudsucker) | Rust；MIT/Apache-2.0 | Rust 的 HTTP/S MITM 代理库，支持请求/响应/WebSocket 修改 | 如果后续做 Tauri/Rust 产品，可作为代理核心候选；成熟度和生态小于 mitmproxy |
| [mcp-firewall](https://github.com/ressl/mcp-firewall) | 跨平台；Python；AGPL-3.0 | MCP 安全网关：YAML 策略、工具调用扫描、签名审计、合规报告 | **互补而非替代**：只覆盖走它的 MCP 流量，不覆盖未接入的桌面 Agent；策略/审计字段可借鉴，AGPL 代码不要直接并入闭源产品 |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust；Apache-2.0 | AI Agent/MCP 的连接代理，路由、安全、可观测 | 企业网关思路参考；要求 Agent 主动接入，不解决本机影子 AI 发现问题 |
| [LiteLLM](https://github.com/BerriAI/litellm) / [Langfuse](https://github.com/langfuse/langfuse) | Python/TS；开源 | LLM Gateway / LLM 可观测性：统一 API、日志、成本、Trace | 需要改应用或走网关；无法审计未接入的桌面应用；可作为上游/导出集成 |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) / ETW | Windows；系统组件 | 进程创建、网络连接（Event ID 3）、DNS 等元数据；ETW 可做更细的内核事件 | **元数据层的最佳补充**；不含正文；Sysmon 需额外安装/许可评估，MVP 不应强依赖 |
| [awesome-auditable-ai](https://github.com/yzhao062/awesome-auditable-ai) | 资料集 | AI 审计的论文、工具、标准、基准 | 后续做风险分类/审计标准时参考 |

> 说明：以上许可证来自各仓库元数据或官方文档；商用前仍需逐项做法务确认，尤其是 WinDivert（LGPL）、GPL/AGPL 项目、以及 Sysmon 的分发条款。

### 2.2 调研结论

1. **「按进程防火墙」和「正文审计」是两类产品。** 前者成熟（OpenSnitch/Portmaster/simplewall），后者在 Windows 上通常只存在于商业抓包工具（Fiddler、Charles、Proxyman、Reqable）或需要应用接入的 AI 网关。
2. **抓包工具不是审计产品。** Fiddler/Charles/Proxyman 偏手动调试，缺少持续的 Agent 发现、策略、风险评分、加密证据链、失败恢复和合规导出。
3. **AI 网关解决不了「影子 AI」。** LiteLLM、agentgateway、mcp-firewall 都要求流量主动接入网关；用户装了一个 Cursor 插件、一个 CLI Agent 或一个未知 Electron 应用，不会自动走网关。
4. **AgentSight 证明了「不装 CA 也能抓明文」在 Linux 上可行**（uprobe SSL 读写），但 Windows 没有等价的开源低成本方案；Windows 上要么 MITM + CA，要么做 API Hook（高侵入、易被 AV 拦截），要么只用 Agent 原生会话/元数据。
5. **产品机会：** 以「本机数据外发审计」为切入点，先解决 Windows 上「哪个进程读了什么、把什么数据发到了哪里」，再逐步扩展到阻断、MCP、服务/团队管理。

### 2.3 对 AgentSight Windows 侧能力的再判断

你提到其 Windows 版本主要是「上下行流量异常波动 + 磁盘读取」，而不是系统级 HTTPS 正文捕获。如果按正文审计目标看，这确实不够；但它反而验证了另一条更普适的路线：

- 对**能解密**的应用，抓正文做内容 DLP；
- 对**不能解密**的应用，用流量特征 + 文件读取 + 进程行为做关联判断；
- 对**恶意/流氓软件**，不要指望它配合代理或信任你的 CA；行为链和出口管控比「抓正文」更现实。

因此本项目的差异化不应是「复刻 AgentSight 读会话文件」，也不应是「承诺抓所有加密流量」，而是：

> **进程级数据流审计：文件 → 进程 → 网络，能看内容时看内容，不能看内容时看行为。**

---

## 3. 技术路线对比

### 3.1 五种可选路线

| 路线 | 流量覆盖 | 正文 | 进程归因 | 工程量 | 主要风险 | 建议 |
|---|---|---|---|---|---|---|
| A. 系统代理 + 本地 MITM + 本地 CA | 中（遵守系统代理的应用） | 是 | 强（代理侧 5 元组反查 PID） | 低–中 | 应用不遵守代理、CA 不信任、pinning | **MVP 主线** |
| B. 透明重定向（WFP/WinDivert）+ MITM | 高 | 是 | 强（WFP 层可拿 PID；WinDivert 需旁路） | 高 | 驱动签名、蓝屏/兼容性、AV 误报、QUIC | **P2** |
| C. 仅元数据（ETW/Sysmon/DNS/SNI/连接表） | 高 | 否 | 中–强 | 低–中 | 看不到正文；SNI/ECH；短连接漏采 | **默认兜底/隐私模式** |
| D. Agent 原生数据（会话日志、MCP 代理、OTel/SDK） | 取决于 Agent | 是（结构化） | 强 | 低–中 | 格式变更、需要接入、覆盖有限 | **P1.5/P2 增强** |
| E. API Hook（SSL_write/SSL_read、WinHTTP） | 取决于目标进程 | 是 | 强 | 高 | 崩溃、版本适配、AV、法律风险 | **不推荐作为主线** |

### 3.2 关键认识：路由与信任是两个问题

- **路由问题：** 应用是否愿意把流量交给审计器。系统代理能覆盖 WinINet/Chromium/Electron 等；Node/Python/Go 等运行时不一定遵守；透明重定向可以强制接管。
- **信任问题：** 即使流量被接管，应用是否信任审计器的本地 CA。Electron/Chromium、.NET、Go 等通常使用系统证书库；Node 默认使用自带 Mozilla CA；Python `requests` 使用 certifi；Java 使用自己的 cacerts。不同运行时需要不同的 CA 注入策略。
- **因此：** 透明驱动只解决「路由」，不解决「信任」。反过来，环境变量注入可以同时解决部分运行时的路由和信任，但对 GUI/已运行进程无效。产品必须组合使用，并明确显示覆盖缺口。

### 3.3 推荐组合

```
MVP：A（AI 应用正文） + C（全应用元数据） + 可选的 D（Agent 会话/MCP）
P2：  B（透明重定向，覆盖不遵守代理的应用） + 策略阻断 + 机器级部署
```

### 3.4 加密边界：到底能看什么、不能看什么

先把「加密」拆成几层，很多误解来自把它们混为一谈：

| 场景 | 能否看到正文 | 可行手段 | 产品结论 |
|---|---|---|---|
| HTTP 明文 | 能 | 代理/抓包 | 直接审计 |
| HTTPS/TLS，应用信任本地 CA，无 pinning | **能** | 授权 MITM：本地 CA + 代理签叶证书 | 这是企业 DLP/网关的标准做法，不是「破解 TLS」 |
| HTTPS + Node/Python 等自带 CA 的运行时 | 能，但需注入 | `NODE_EXTRA_CA_CERTS`、合并 CA、启动器/环境变量 | 运行时不信任就看不到；需兼容矩阵 |
| 证书 pinning / 公钥 pinning | **不能**（不改应用的前提下） | 只能 passthrough + 元数据/行为/Agent 原生数据 | 不要尝试 patch/绕过第三方应用；记录覆盖缺口 |
| mTLS（双向证书） | 通常不能 | 没有客户端私钥无法完整冒充 | 元数据 + 服务端日志 |
| TLS 1.3 | **不影响**是否可 MITM | 只要 CA 被信任，TLS 1.3 同样可终止 | 真正的障碍是 pinning/E2EE，不是 TLS 版本 |
| QUIC / HTTP/3 | 技术上可拦截，工程上很难 | 阻断 UDP/443 强制回落 TCP；或元数据 | MVP 不承诺；P2 评估 |
| WebSocket over TLS | 能（CA 信任时） | MITM + WS 消息解析 | 支持 |
| 应用层 E2EE / 自定义 AES / 私有协议 | **不能**通用解密 | 端点 Hook、内存、DOM、SDK/MCP 旁路；逐样本逆向 | 不承诺；用文件/行为关联兜底 |
| 恶意软件自定义 C2/加密上传 | 通常不能 | 沙箱动态分析、行为链、网络元数据、YARA/内存取证 | 不是本产品的主线；建议隔离 VM + EDR |
| 本地 stdio MCP / 命名管道 | 不走网络 | MCP 代理/包装器、进程间通信审计 | 单独做适配 |

**结论：**

- **TLS 不是「破解」问题，而是「信任」问题。** 本地 CA 被应用信任时，MITM 是合法的授权审计；应用 pinning 时，无法通用解密。
- **应用层 E2EE/自定义加密是硬边界。** 即使拿到 TLS 明文，里面仍是密文；没有密钥就只能看元数据/行为。
- **不要卖「万能解密」。** 应该卖「可见性分层 + 行为关联 + 证据」：能解密的应用给正文，不能解密的应用给数据流证据。
- **对可疑恶意软件，不要在日用主机上安装信任 CA 做分析。** 在隔离 VM/快照里做，避免 CA 私钥被恶意软件窃取后扩大风险。

### 3.5 两条产品路线，建议合并

| 路线 | 核心 | 优点 | 局限 |
|---|---|---|---|
| **内容审计路线** | 代理 + CA + 协议解析 + DLP | 能直接看到 Prompt/代码/密钥，证据直观 | 受 pinning/E2EE/代理覆盖限制；对恶意软件不可靠 |
| **行为/数据流路线** | 进程 + 文件读取 + 网络元数据 + 关联 | 加密也能用；覆盖服务/流氓软件；隐私侵入较小 | 不知道具体内容；需要文件读取遥测；误报调优难 |

**推荐定位：** 以行为/数据流路线为骨架，以内容审计为增强。这样即使客户的应用全部 pinning，产品仍能回答「谁读了什么、发了多少、发到哪」；对可解密应用再补上「具体发了什么」。

---

## 4. 推荐架构

### 4.1 总体结构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI Agent / 普通应用                           │
│   Electron / Node / Python / Go / .NET / curl / 浏览器 / MCP 进程     │
└───────────────┬───────────────────────────────┬─────────────────────┘
                │ 系统代理 / 环境变量代理        │ 直连（元数据旁路）
                ▼                               ▼
┌───────────────────────────────┐   ┌─────────────────────────────────┐
│ 本地审计代理 (127.0.0.1:PORT) │   │ 元数据采集器（可选 ETW/Sysmon） │
│ - TLS MITM / CA               │   │ - TCP 连接 / DNS / 进程事件     │
│ - HTTP/1.1, HTTP/2, WS, SSE   │   │ - 5 元组 → PID（轮询/ETW）      │
│ - 流式/大小限制/解压限制      │   └──────────────┬──────────────────┘
│ - 上游代理链（保留公司代理）  │                  │
└───────────────┬───────────────┘                  │
                │                                  │
                ▼                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      进程归因 / Agent 识别层                         │
│ 代理侧 5 元组 → GetExtendedTcpTable/psutil → PID → 进程树 → App ID  │
│ 可执行文件签名、路径、命令行、父进程、已知 AI 应用指纹               │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                协议解析 + 脱敏 + 检测 + 策略 + 风险评分               │
│  端点识别（OpenAI/Anthropic/Gemini/…）、Prompt/代码/密钥/PII、上传量  │
│  YAML 策略、告警/阻断/脱敏、可解释证据                               │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    本地存储 / 证据链 / UI / 导出                    │
│  SQLite WAL + AES-GCM + DPAPI；正文加密；哈希链；保留期；本地仪表盘  │
└─────────────────────────────────────────────────────────────────────┘
```

> 图中是简化版。文件读取遥测、金丝雀文件和「读取→外发」关联见 4.11；Windows 服务/SYSTEM 进程的额外覆盖见 4.12。

### 4.2 进程与应用发现

**MVP 数据源（无需驱动）：**

- `psutil` 轮询进程列表（1–2 秒）+ `pywin32` 的 WMI 进程创建事件；
- 记录 PID、PPID、进程启动时间（避免 PID 复用）、可执行路径、命令行、用户名、会话 ID；
- 用 WinVerifyTrust/Authenticode 读取签名者、产品名、文件版本；
- 计算 SHA-256（大文件可延迟/缓存）；
- 构建进程树，找出「根 Agent」与子进程（如 Agent 启动 `git`、`curl`、浏览器、MCP server）；
- 已知 AI 应用指纹：进程名、路径、签名者、命令行模式（如 `@anthropic-ai/claude-code`、`mcp-server-*`、`ollama`、`lm-studio`）、安装位置；
- 已知 AI 端点与路径模式：`api.openai.com/v1/chat/completions`、`api.anthropic.com/v1/messages`、`generativelanguage.googleapis.com/v1beta/models/...:generateContent` 等；
- 本地模型服务发现：Ollama `11434`、LM Studio `1234`、vLLM/OpenAI-compatible 端口等（仅本地，不计为外发风险，但用于识别 Agent）；
- MCP 配置发现（需用户允许）：`claude_desktop_config.json`、`.cursor/mcp.json`、VS Code 设置等，识别 stdio/HTTP MCP server；
- 安装清单/自启动项：注册表 Uninstall、Startup、计划任务，用于「已安装但未运行」的盘点。

**P2 增强：** ETW（Kernel-Process、Kernel-Network、DNS-Client）；可选读取 Sysmon 事件（不强制捆绑）；文件访问监控（微过滤/ETW）另立项目。

### 4.3 流量接管

**MVP：显式代理。**

- 设置当前用户 WinINet 代理：`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`，然后调用 `InternetSetOptionW(INTERNET_OPTION_SETTINGS_CHANGED/REFRESH)`；
- 保存原始代理/PAC 设置，退出/崩溃/重启后恢复；
- 上游链：如果用户已有公司代理或 Clash，审计代理必须能链到原上游，而不是简单覆盖；支持 HTTP 上游、认证、`NO_PROXY`；
- 绑定 `127.0.0.1`，随机高端口，避免局域网暴露；
- 本地地址、回环、代理自身流量加入 bypass，防止环路；
- 可选 `netsh winhttp`（需管理员）覆盖 WinHTTP 应用；MVP 默认不做机器级改动；
- 对 Node/Python/Go 等运行时：
  - Node 24+：`NODE_USE_ENV_PROXY=1` + `HTTPS_PROXY/HTTP_PROXY`；CA 用 `NODE_EXTRA_CA_CERTS`（必要时 `NODE_USE_SYSTEM_CA=1`）；
  - Python：`HTTPS_PROXY`/`HTTP_PROXY` + `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`/`CURL_CA_BUNDLE` 指向「系统 CA + 审计 CA」合并包；
  - Go：`HTTPS_PROXY`（`http.ProxyFromEnvironment`）+ 系统根证书（通常可用）；
  - 其他运行时：给出启动器/环境变量配方，P0 逐项验证；
- 提供 `ai-audit run -- <command>` 启动器：只对目标 CLI Agent 注入环境变量，避免全局影响；这是比「全局 setx」更安全的默认；
- 全局环境变量只作为高级选项，并明确提示「只影响新启动进程」。

**P2：透明重定向。**

- 优先 WFP callout（能在 ALE 层拿到 PID，策略/重定向更自然）；WinDivert 作为快速验证/备选；
- 需要内核驱动签名（EV 证书 + Microsoft attestation）、崩溃恢复、升级/卸载、AV 兼容性测试；
- 透明模式仍需要 CA 信任；对不信任本地 CA 的应用无效；
- 处理 IPv6、UDP/QUIC、回环、VPN/TUN、分片、连接跟踪；
- 不建议在 MVP 前启动驱动开发。

### 4.4 进程归因（MVP 的关键技巧）

当应用通过显式代理连接 `127.0.0.1:PORT` 时：

1. 代理在 `client_connected` 拿到客户端源地址 `127.0.0.1:EPHEMERAL`；
2. 调用 `GetExtendedTcpTable`（或 `psutil.net_connections`）查找 `local_port == EPHEMERAL && remote_port == PORT` 的 TCP 行；
3. 该行的 `OwningPid` 即客户端 PID；
4. 结合进程启动时间、可执行路径、签名、父进程树，得到 App ID / 根 Agent；
5. 对 HTTP/2 多路复用：一条 TCP 连接对应一个进程，所有 stream 共用归因；
6. 对长连接/keep-alive：在连接建立时缓存归因，定期校验；
7. IPv4/IPv6 双栈分别查表；失败则标记 `attribution_confidence=low`，不要瞎猜。

**优点：** 不需要驱动，归因准确率高，能覆盖所有走代理的应用。  
**限制：** 如果应用先经过 Clash/公司代理再到本代理，看到的是上游代理 PID；UWP/服务进程可能显示 broker PID；需要覆盖矩阵和降级标记。  
**性能：** 用后台线程缓存 TCP 表 + 按源端口索引，避免每条请求全表扫描；P0 做 500–1000 次连接准确率测试。

### 4.5 TLS 与本地 CA

- 每次安装生成**独立 CA**（RSA 3072 或兼容性更好的参数），绝不内置共享 CA 私钥；
- 私钥保存在 `%LOCALAPPDATA%` 下，ACL 仅当前用户，DPAPI 加密；UI 显示 CA 指纹；
- 安装到 `Cert:\CurrentUser\Root`（当前用户，无需管理员）需用户明确确认；机器级模式（P2）才装 `LocalMachine\Root`；
- 按主机动态签发叶证书，缓存，短有效期；
- **pinning/不信任处理：** 捕获 TLS 错误，标记该主机/应用「无法解密」，自动 passthrough 或提示用户；绝不为了抓包而无限重试/破坏应用；
- 卸载时移除信任、删除私钥、清理缓存；
- 兼容性策略详见第 7 节；P0 必须用真实/模拟客户端验证，而不是假设「装了 CA 就能解」；
- 对高安全应用，提供「只元数据、不解密」白名单。

### 4.6 内容解析

**协议：** HTTP/1.1、HTTP/2、WebSocket、SSE；gRPC 先只记元数据（P2 再考虑解析）。

**请求侧（重点）：**

- 识别 AI API：域名 + 路径 + 请求头/JSON 结构（`model`、`messages`、`input`、`contents`、`tools` 等）；
- 提取 Prompt/消息/工具调用/文件上传（multipart 文件名、MIME、大小）；
- 检测代码块、diff、仓库路径、文件扩展名、语言关键字；
- 检测密钥/PII/内部标识（见 4.7）；
- 大文件上传：只保留前 N KB + 文件元数据 + 首尾哈希，禁止把整个仓库读进内存。

**响应侧（可选/默认摘要）：**

- 状态码、模型、usage、SSE 事件数、工具调用、响应预览；
- 默认不长期保存完整响应正文；需要时按策略开启；
- 避免把模型输出中的恶意 HTML/JS 直接渲染到 UI（XSS 风险）。

**脱敏：**

- `Authorization`、`Cookie`、`Set-Cookie`、`X-Api-Key` 等请求头；
- JSON 中 key 匹配 `api_key|token|secret|password|authorization|cookie` 的值；
- query 参数中的 key/token/signature；
- 已知密钥正则（OpenAI/Anthropic/GitHub/AWS/私钥/JWT 等）；
- 用 HMAC/哈希保留「同一密钥再次出现」的关联能力，但不存明文；
- 脱敏在**写入存储前**完成；原始正文如确需保留，必须单独加密并限制访问。

**大小与流式：**

- 请求正文预览上限建议 256 KB，硬上限 1 MB；超过则流式转发、只审计前缀+元数据；
- 响应预览 64 KB；SSE 只保留事件摘要；
- 解压限制（gzip/br/zstd），防 zip bomb；
- 二进制/图片/音视频默认不解析内容，只记 MIME、大小、哈希；
- 使用 mitmproxy 的 `stream_large_bodies` 等机制，避免默认缓冲整个大文件。

### 4.7 风险判定

**分阶段，先确定性规则，后语义模型：**

1. **范围过滤：** 是否 AI 端点/已批准端点/本机模型/未知外发。
2. **策略匹配：** 进程/应用、域名、路径、方法、大小、时间、用户、父进程、MCP 工具名。
3. **检测器：**
   - 密钥/凭据：regex + 熵 + gitleaks 规则（注意许可证）；
   - PII：中国身份证/手机号/银行卡/邮箱/地址；可选用 Presidio（MIT）扩展；
   - 代码：代码围栏、diff 头、文件扩展名、import/package 关键字、仓库名、行数/大小；
   - 数据量：单次/单位时间上传字节、请求数、相对基线异常；
   - 目的地：AI 厂商白名单、未知域名、新出现域名、地域（GeoIP 可选，注意隐私）；
   - 行为：Agent 子进程启动 `curl`/浏览器、向非 AI 域名上传、异常 MIME。
4. **语义模型（P2，可选）：** 本地小模型/嵌入分类，异步、只做建议，不参与实时阻断；默认不把审计数据发给云端 LLM。
5. **评分与动作：**
   - `info / low / medium / high / critical`；
   - `log / alert / block / redact / ask`；
   - MVP 默认 `alert`；只对确定性高危策略启用 `block`；
   - 所有结论必须可解释：命中规则、证据片段、进程链、策略版本。

**策略示例（YAML，示意）：**

```yaml
id: ai-audit.code-exfil
title: 非白名单 AI 端点的代码/密钥外发
match:
  destination:
    category: ai_provider
    vendor_not_in: [openai, anthropic, google, approved-internal]
  request:
    any:
      - secrets: any
      - code_score: ">= 0.7"
      - upload_bytes: "> 2MB"
action: alert        # 可改为 block / redact / ask
severity: high
```

**降噪：**

- 按应用/仓库/厂商/端点做 allowlist；
- 同一规则短时间去重；
- 用户可标记误报/漏报，作为规则调优输入；
- 不追求「零误报」，但必须让用户能快速看懂为什么报。

### 4.8 存储与审计证据

**SQLite（WAL）**，元数据明文可检索，正文加密：

| 表 | 关键字段（示意） |
|---|---|
| `processes` | pid, ppid, start_time, name, path, sha256, signer, cmdline, app_id, root_agent_id, first_seen, last_seen |
| `apps` | app_id, display_name, vendor, fingerprint, risk_level, allowlisted |
| `connections` | id, ts, pid, app_id, local/remote addr, host, port, protocol, bytes_in/out, attribution_confidence |
| `transactions` | id, connection_id, method, url, status, req_headers_redacted, req_body_enc, resp_preview_enc, sizes, content_type, risk_score, rule_hits |
| `findings` | id, transaction_id, policy_id, severity, evidence, action, status, created_at |
| `policies` | id, version, yaml, enabled, signed_by |
| `audit_chain` | seq, prev_hash, record_hash, signed_at, anchor |
| `settings` | key, encrypted_value (CA ref, retention, proxy config) |

**加密与密钥：**

- 每安装随机 DEK；DPAPI（当前用户）保护 DEK；正文 AES-256-GCM，AAD 绑定记录 ID；
- 元数据可明文，便于搜索；如合规要求更高，可整体 SQLCipher；
- CA 私钥、DEK、UI token 分开放置，ACL 限制；
- 日志/崩溃转储禁止出现正文和密钥。

**完整性：**

- 每个审计记录 `record_hash = SHA256(prev_hash || canonical_json(record))`；
- 每日 anchor 写入独立文件/外部 syslog（可选）；
- 导出 JSONL + manifest + 校验工具；
- 说明局限：本地管理员仍可重写整条链；要更强保证需 TPM/外部锚定。

**保留与访问：**

- 默认元数据 30 天、正文 7 天（可配置）；支持按应用/策略覆盖；
- 自动清理有审计事件；支持 legal hold；
- UI/导出需要本地 token；敏感正文查看可要求二次确认；
- 访问/导出本身也记审计日志。

### 4.9 UI 与交互

- **首次引导：** 解释采集范围、CA 风险、代理影响、隐私选项；必须显式同意才装 CA/改代理；
- **托盘：** 代理状态、CA 状态、暂停/恢复、恢复网络、打开面板；
- **总览：** 当前 AI 会话/进程、目标厂商、上传量、风险告警、覆盖状态；
- **应用详情：** 身份、签名、路径、子进程、端点、历史、策略；
- **交易详情：** 请求/响应（脱敏）、命中规则、证据、进程树、原始导出（授权）；
- **覆盖页：** 明确列出「已解密正文 / 仅元数据 / 未接管」的应用和原因（不遵守代理、pinning、运行时 CA 未注入等）；
- **策略页：** 模板（代码外发、密钥、PII、未知 AI 厂商、异常上传量）；
- **审计页：** 搜索、时间线、导出、链校验；
- **设置：** 采集范围、保留期、排除项、上游代理、CA 管理、更新；
- **安全渲染：** Prompt/响应中的 HTML/JS 一律按文本/安全 Markdown 渲染，CSP + sanitizer。

### 4.10 失效恢复与稳定性

这是审计代理类产品最容易翻车的地方：

- 独立 watchdog（托盘进程/计划任务/服务）监控代理端口；代理退出立即恢复原代理设置；
- 启动时检测「上次异常退出留下的代理设置」，自动清理；
- 默认 **fail-open**（审计器故障时恢复直连），企业模式可选 fail-closed；
- 端口冲突自动换端口并持久化；睡眠/唤醒后健康检查；
- 网络切换/VPN/TUN/公司代理变化时重新评估上游，给出提示；
- 上游代理认证（Basic/NTLM/Negotiate）单独设计；MVP 至少支持 Basic + 明确不支持提示；
- 退出/卸载：恢复代理、移除 CA、按确认删除数据；
- 100 次 kill/restart、断网/恢复、证书删除等故障注入测试纳入 P0/P1 验收。

### 4.11 文件读取遥测与「读取 → 外发」关联

这是把产品从「AI 抓包工具」升级为「本机数据外发审计」的关键。

**要回答的问题：**

- 哪个进程读取了哪些敏感文件？
- 读了多少字节/多少个文件？
- 读取后多短时间内发起了网络连接？
- 目标域名/IP 是否首次出现、是否在批准列表？
- 上传字节数与读取量是否大致匹配？
- 是否由 AI Agent/服务/子进程发起？

**Windows 文件读取遥测的可用手段：**

| 手段 | 能力 | 权限/成本 | 适合阶段 | 注意 |
|---|---|---|---|---|
| Sysmon | 进程创建、网络连接、文件创建/删除、RawAccessRead（Event 9） | 需安装；配置/许可 | 网络/进程元数据补充 | **不记录普通文件读取**；不能拿它当文件读取审计 |
| Windows 安全审计 + SACL（Event 4663） | 对指定目录记录读取/写入等访问，含进程 ID、文件路径、访问掩码 | 管理员；需启用「Audit File System」；日志量大 | **P1b 首选（有限目录）** | 只对敏感目录开，避免全盘日志风暴；需处理日志轮转 |
| ETW `Microsoft-Windows-Kernel-File`（FileIORead 等） | 内核文件 I/O 事件，实时；可含进程/线程/文件对象信息 | 管理员；事件量巨大；路径关联复杂 | P2 原型/增强 | 需要过滤、聚合、FileObject→路径关联；可能影响性能 |
| 文件系统 minifilter 驱动 | 读取/写入/重命名等完整文件事件；可在 pre-op 阻断；含进程 ID、路径 | 内核驱动签名、稳定性、AV 兼容 | P3 全量/阻断 | 工程量大；蓝屏风险；需 EV 签名/WHQL 评估 |
| Procmon | 文件读取、进程、网络等，调试强 | Sysinternals 工具，非产品集成 | P0 验证/取证辅助 | 不适合常驻产品；许可是 EULA |
| 商用 EDR / MDE / Purview | 文件/进程/网络行为，企业级 | 授权/成本 | 企业集成 | `DeviceFileEvents` 主要覆盖创建/修改等，不应假设含全部读取；不要作为 MVP 依赖 |

**推荐分期：**

- **P1b（无驱动、有限路径）：** 建立敏感目录清单（项目目录、`.ssh`、`.env`、Documents 等，用户选择）；用 SACL + 安全日志 4663 采集读取；只采集配置的路径，设置 TTL 和日志上限；同时布置**金丝雀文件**（见下）；把读取事件与网络连接按 PID + 时间窗关联。
- **P2（更完整）：** ETW Kernel-File 或 minifilter 试验；支持服务/SYSTEM 进程；降低开销；考虑实时阻断（minifilter）。
- **P3（企业级）：** 签名 minifilter + 中央策略 + 文件内容指纹/分类；与 DLP/EDR 集成。

**金丝雀文件（Honeytoken）建议：**

- 在敏感目录放置少量看似真实、但内容是唯一标记的假文件（如 `internal-credentials.env`、`customer_backup.csv`）；
- 正常用户/正常 Agent 不应读取；
- 如果文件被读取，触发高优先级告警；如果上传内容可解密，匹配唯一标记可确认外发；
- 如果上传是加密的，仍然能通过文件读取遥测知道「金丝雀被读了」，再结合网络外发时间/目标判断；
- 需要避免干扰正常业务；默认关闭，用户显式启用；不要放在会被自动备份/同步的目录（否则正常软件也会读）。

**关联与评分：**

```
文件读取事件(file_path, bytes, pid, ts)
        │
        ├── 进程身份(签名/路径/父进程/是否 AI Agent/服务)
        ├── 网络连接(dst_host/ip, bytes_out, ts, 首次出现?)
        └── 策略(敏感路径, 目标白名单, 上传量阈值, 时间窗)
                ↓
        数据流证据链 + 风险分 + 告警
```

**典型规则：**

- 未签名/新出现进程读取 ≥N 个敏感文件后，10 分钟内上传 ≥X MB 到首次出现的域名；
- AI Agent 读取工作区外的文件（如 `~/.ssh`、浏览器配置）后发起外部请求；
- 后台服务读取用户文档目录并连接非批准云存储；
- 金丝雀文件被读取或内容标记出现在可解密的上传中；
- 压缩/加密上传的字节量与刚读取的敏感文件总量高度相关（只能做风险提示，不能当确证）。

**关联的工程难点：**

- PID 复用：必须带进程启动时间；
- 文件路径规范化：大小写、短路径、符号链接、网络盘；
- 读取字节 vs 上传字节：压缩、编码、加密、分批上传会导致不相等；
- 子进程/服务宿主：`svchost.exe` 等需要拆解到具体服务；
- 时间同步：统一 UTC，允许合理时间窗；
- 误报：备份、同步盘、杀毒扫描、索引器都会大量读文件，必须有进程/路径白名单和基线。

### 4.12 Windows 服务、SYSTEM 进程与机器级覆盖

AI Agent 多数是用户态进程，但「流氓软件/劫持服务」经常是：

- Windows 服务（SYSTEM/LocalService/NetworkService）；
- 计划任务；
- 自启动程序；
- 浏览器扩展/插件；
- 驱动/内核组件。

**MVP 的边界：**

- 当前用户代理（HKCU）和 CurrentUser CA 主要覆盖当前登录用户的应用；
- 服务不读用户代理；`netsh winhttp` 只能覆盖使用 WinHTTP 的服务；原始 socket、自带 OpenSSL、Go/Node 服务可能绕过；
- 因此 MVP 对服务只能提供「元数据可见性」（ETW/Sysmon/连接表），正文审计只对「愿意走代理且信任 CA」的服务生效；
- 必须在 UI 的覆盖页明确区分「用户应用 / 服务 / 驱动级 / 未覆盖」。

**P2 机器级方案：**

- 安装 Windows 服务（SYSTEM）+ 机器级 CA（LocalMachine Root）+ WFP/ETW + 代理/透明重定向；
- 机器级代理/证书需要管理员权限，且影响所有用户；必须提供企业策略、回滚、审计；
- 服务化后要防止自我更新/崩溃导致全机断网；fail-open/fail-closed 可配置；
- 驱动级恶意软件仍可能绕过；不要把它当 EDR。

**对流氓软件的现实建议：**

- 审计工具负责「发现 + 证据 + 告警」，不承诺「清除」；
- 预防优先：Windows 防火墙出站白名单、WDAC/AppLocker（版本支持有限）、卸载不需要的服务、最小权限账户、DNS 过滤、隔离 VM；
- 对可疑样本：在隔离 VM/快照中运行，使用独立的分析 CA/代理，不要在日常主机上安装信任 CA；先取证再清理；
- 如果对方是内核级/驱动级，用户态审计不可靠，应使用成熟 EDR/杀毒/系统重装。

---

## 5. 覆盖矩阵与兼容性策略（P0 必测）

> 下表是**假设 + 待验证**，不是承诺。P0 必须用实际客户端逐项测试并产出矩阵。

| 运行时/应用 | 系统代理 | CA 信任 | 建议策略 | 备注 |
|---|---|---|---|---|
| Chromium / Electron 渲染进程 | 通常遵守 | 通常用 Windows 根证书 | 系统代理 + CurrentUser Root | 需验证具体应用；部分应用自带代理设置 |
| Electron 主进程（Node） | 通常不遵守 | Node 默认用自带 Mozilla CA | `NODE_USE_ENV_PROXY=1` + `NODE_EXTRA_CA_CERTS`；或启动器注入 | Electron 内置 Node 版本可能 <24，无 env proxy；需逐应用测 |
| Node CLI（Node 24.18） | 不读系统代理 | 需额外 CA | `NODE_USE_ENV_PROXY=1`、`HTTPS_PROXY`、`NODE_EXTRA_CA_CERTS`；可加 `NODE_USE_SYSTEM_CA=1` | Node 24 支持 fetch 环境代理；老版本需库/启动器 |
| Python requests/httpx | 读 `HTTPS_PROXY` | requests 默认 certifi | `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` + 合并 CA；启动器注入 | httpx/openai SDK 的证书行为需实测 |
| Go | 读 `HTTPS_PROXY` | 通常用系统根证书 | 环境变量代理 | 有些库自定义 Transport |
| .NET | 通常用系统代理 | 通常系统证书库 | 系统代理 + 根证书 | 自定义 HttpClient 需测 |
| Java | 需 `-Dhttps.proxyHost` | 自带 cacerts | 不建议全局改；按应用配置或启动器 | 企业 Java 应用单独处理 |
| Windows curl | 读环境变量 | Schannel/系统证书（视构建） | 环境变量 + 系统 CA | 内置 curl 与 Git curl 行为可能不同 |
| Rust/reqwest | 读环境变量 | native-tls 用系统；rustls 可能用内置根 | 逐应用验证 | 代码签名高的 Agent 可能用 rustls |
| UWP / 服务 | 当前用户代理可能不生效 | 视账户 | P2 机器级模式 | MVP 明确不覆盖 |
| 证书 pinning 应用 | 可代理 | 拒绝本地 CA | 自动 passthrough + 标记未覆盖 | 不要尝试绕过 pinning |
| 已有 Clash/公司代理/VPN | 可能冲突 | 视上游 | 上游链 + 检测 TUN；提示用户 | 国内环境高发，必须优先处理 |
| QUIC/HTTP3 直连 | 可能绕过 | — | 元数据/阻断 UDP 443（P2） | 系统代理下 Chromium 通常不用 QUIC，但其他应用需测 |
| Windows 服务/SYSTEM 进程 | 当前用户代理通常不生效 | 视服务运行时 | P2 机器级/WFP/ETW；MVP 仅元数据 | 服务可能用 WinHTTP、原始 socket、自带 TLS；不要假设可代理 |
| 文件读取（敏感目录） | 不走网络 | — | SACL 4663（P1b）/ETW/minifilter（P2） | Sysmon 不记录普通文件读取；全盘采集开销大 |
| 应用层 E2EE/自定义加密 | 可代理也可能解不开 | 无法解密 | 只做元数据/行为/文件访问关联 | 不承诺正文；恶意 C2 需隔离分析 |
| 证书 pinning / mTLS | 可连接但无法冒充 | 拒绝本地 CA | passthrough + 覆盖页标记；Agent 原生数据兜底 | 不要 patch 第三方应用；不要承诺绕过 |

**产品要求：** 仪表盘必须显示「覆盖置信度」和「未覆盖原因」，而不是让用户以为「已经在审计所有流量」。

---

## 6. 安全、隐私与合规

### 6.1 产品安全

- UI/API 只绑定 `127.0.0.1`，随机 token，校验 Origin，防 CSRF；
- 审计内容按不可信输入处理：XSS、日志注入、路径穿越、SQL 注入全部防护；
- CA 私钥是最高价值资产：ACL、DPAPI、绝不导出、绝不写日志；安装/卸载需确认；
- 更新包签名校验；依赖锁定 + SBOM；构建可复现（尽量）；
- 不上传原始审计数据；崩溃报告/遥测默认关闭，开启时脱敏；
- 不使用共享/内置 CA；不提供「隐藏运行/规避检测」模式；
- 明确提示用户：安装本地 CA 会降低对本机中间人攻击的门槛，必须保护私钥；
- 与 EDR/AV 的兼容性：MVP 无驱动可降低误报；代码签名、厂商白名单、安装说明准备好。

### 6.2 数据隐私

- 默认最小化：所有应用只记元数据；AI 端点才抓正文；响应默认只留摘要；
- 正文加密、脱敏、短保留期；支持按应用排除；
- 本地优先，不上云；如未来做团队版，必须端到端加密/明确告知/可审计的管理员访问；
- 不采集与审计目标无关的个人通信内容；
- 提供「暂停审计」「删除我的数据」「导出我的数据」。

### 6.3 法律与组织合规

- 仅用于自有设备或获得明确授权的设备；企业部署必须提前告知员工/工会/数据保护负责人；
- 中国场景需评估《个人信息保护法》《数据安全法》《网络安全法》及员工监控、告知同意/人力资源管理必要性、数据最小化、留存期限、跨境传输等要求；
- 审计证据可能包含个人信息、商业秘密、源代码；访问权限、保留期、删除流程要写进制度；
- AI 厂商的数据处理条款（是否用于训练、保留多久、跨境）应作为策略的一部分提示用户；
- 本文不是法律意见，企业落地前需法务/合规评审。

### 6.4 分析可疑恶意软件/流氓软件时的额外边界

- **不要在日用主机上为可疑软件安装信任 CA。** 恶意软件若拿到管理员权限，可能窃取 CA 私钥，进而扩大中间人风险。应在隔离 VM/快照/专用分析机中做。
- **不要采集真实凭据。** 分析环境使用假账号/假数据；默认脱敏；避免把分析样本上传到云端沙箱（除非确认合规）。
- **不要承诺通用解密。** 自定义加密、E2EE、pinning 是硬限制；产品价值在于行为链和证据，而不是「破解」。
- **取证优先于清除。** 先保存网络/文件/进程时间线，再决定卸载/重装；驱动级恶意软件建议直接重建系统。
- **明确授权。** 仅分析自有设备或书面授权的设备/样本；遵守当地法律和平台条款。

---

## 7. 执行计划

### 7.1 阶段总览

| 阶段 | 建议周期 | 目标 | 关键交付 | 退出条件 |
|---|---|---|---|---|
| **P0 可行性验证** | 2–3 周（10–15 工作日） | 证明 Windows 上「代理 + CA + PID 归因 + 内容审计 + 文件读取关联」可行，量化覆盖缺口 | 兼容性矩阵、归因准确率报告、文件读取遥测报告、失效恢复报告、透明代理技术备忘录、Go/No-Go 结论 | 目标 Agent 中 ≥70% 能抓正文；代理归因 ≥99%；SACL 读取关联可用；50 次崩溃恢复无残留；明确 pinning/QUIC/公司代理策略 |
| **P1a 网络与内容审计 MVP** | 4–6 周 | 单用户、本地、AI 应用内容审计 + 全应用网络元数据 + 进程归因 | 可安装托盘应用；CA/代理向导；Agent 识别；正文审计；DLP 规则；加密存储；仪表盘；导出；测试/文档 | 3 类 Agent 端到端可用；模拟密钥/代码外发可检出；24h 连续运行；断网恢复；无明文正文落盘；覆盖页准确 |
| **P1b 文件读取关联** | 3–4 周 | 敏感目录读取 + 金丝雀文件 + 「读取→外发」关联 | SACL 4663 采集；敏感路径清单；金丝雀文件；PID/时间窗关联；风险规则；隐私开关 | 能复现「进程读 .env → 上传未知域名」证据链；开销可控；误报有白名单；只覆盖配置目录 |
| **P2 覆盖与阻断** | 6–8 周 | 覆盖不遵守代理的应用与服务；可阻断；MCP/Agent 原生数据；机器级 | WFP/WinDivert 透明重定向；Windows 服务/机器级 CA；ETW/minifilter 评估；阻断/审批；MCP stdio/HTTP 审计；Agent 会话导入；上游代理认证；IPv6/QUIC 处理 | 目标应用/服务覆盖 ≥90%（含透明模式）；阻断可回滚；驱动签名/稳定性/AV 测试通过；多用户/服务场景验收 |
| **P3 产品化** | 4–6 周 | 可分发、可维护、可支持 | 安装器/签名/自动更新；性能与安全加固；团队控制台/SIEM 导出（可选）；macOS/Linux 评估；渗透测试/合规材料 | 干净机安装成功率 ≥99%；升级/回滚/卸载可靠；安全评审无高危；支持文档完备 |

**总量级：** 1 人全职约 5–7 个月到「较完整产品」；P1a 约 6–8 周（含 P0）；P1a+P1b 约 10–12 周；2 人并行可压缩到约 3–4 个月。内核驱动、代码签名、企业合规另计 4–8 周。

> 建议不要等 P1b 才开始验证文件读取：P0 就用 SACL 4663 做一个敏感目录原型，确认「进程读取 → 网络外发」关联是否足够可靠。如果 P0 发现日志量/权限/误报不可接受，P1b 改为金丝雀文件 + 有限 ETW，而不是硬上全盘 minifilter。  
> **排序建议：** 如果主要目标是「流氓软件/后台服务偷文件上传」，而不是 AI 正文审计，应把 **P1b 提前到 P1a 之前**：先做「全应用网络元数据 + 敏感目录读取 + 金丝雀 + 关联告警」，AI 正文审计作为后续增强。这样不依赖解密，先解决更普适的问题。

### 7.2 P0 详细验证清单（先做，不写产品代码）

| # | 验证项 | 方法 | 通过标准 |
|---|---|---|---|
| P0-1 | 代理 + CA 兼容性 | 用 mitmproxy 原型 + 自签 CA，测试 Chrome/Electron/Node 24/Python/Go/.NET/curl/Java/真实 Agent | 目标 Agent ≥70% 正文可读；失败项有明确原因和降级方案 |
| P0-2 | PID 归因 | 代理接受连接时查 `GetExtendedTcpTable`/psutil；1000 次连接，含 IPv4/IPv6、HTTP/2、keep-alive、WebSocket | 归因准确率 ≥99%；PID 复用/失败有标记；性能可接受 |
| P0-3 | Node/Python CA 注入 | Node 24 `NODE_USE_ENV_PROXY`/`NODE_EXTRA_CA_CERTS`；Python 合并 CA + 环境变量；Electron 主/渲染进程分别测 | 至少 Node 24 CLI 与 Python SDK 可控；Electron 行为记录清楚 |
| P0-4 | 系统代理失效恢复 | 杀进程/崩溃/重启/睡眠/端口冲突/CA 删除；50 次循环 | 无残留代理设置；恢复 <5 秒；不阻断用户网络 |
| P0-5 | 公司代理/VPN/Clash | 模拟上游代理、TUN、PAC、认证 | 能链上游或不接管并提示；不出现环路/断网 |
| P0-6 | pinning/QUIC/ECH | 构造 pinning 客户端；观察 QUIC/ECH 行为 | 可识别并 passthrough；覆盖页正确标记；不崩溃 |
| P0-7 | 大文件/流式 | 10MB 上传、长 SSE、WebSocket、压缩包 | 不整包缓冲；内存/CPU 可控；正文截断有标记 |
| P0-8 | DLP 原型 | 用合成请求测试密钥/代码/PII/上传量规则 | 密钥检出率 ≥90%；良性样本误报可接受；证据可解释 |
| P0-9 | 透明重定向 | WinDivert 重定向 + TCP 表归因原型；WFP 资料评估 | 能接管一个不遵守代理的客户端；明确 P2 工程量/签名/风险 |
| P0-10 | 数据安全 | 加密存储、DPAPI、CA 私钥 ACL、UI 本地鉴权 | 无明文正文/密钥落盘；本地 API 不可被任意网页调用 |
| P0-11 | 文件读取遥测 | 对 1–2 个测试目录启用 SACL/4663；用测试进程读取 `.env`/文档；解析事件并关联 PID | 能稳定拿到「进程/路径/时间/访问类型」；评估日志量、权限、轮转、性能 |
| P0-12 | 读取→外发关联 | 测试进程读文件 → 上传到本地假服务器；用 PID+时间窗关联；构造压缩/加密/分批场景 | 能生成可解释证据链；明确误报来源；确定 MVP 只覆盖敏感路径 |
| P0-13 | 服务/加密兜底 | 用一个 Windows 服务/不遵守代理的客户端；测试仅元数据/ETW 可见性；构造 E2EE/自定义加密样本 | 覆盖页能正确区分「正文/元数据/未覆盖」；不对加密内容做错误承诺 |
| P0-14 | 金丝雀文件 | 放置带唯一标记的假凭据/假文档；测试正常软件/Agent 是否误读；测试可解密与加密上传两种场景 | 读取告警可用；默认可关闭；不干扰备份/同步/索引 |

**P0 产出：** `docs/p0-compat-matrix.md`、`docs/p0-attribution-report.md`、`docs/p0-failover-report.md`、`docs/p0-file-access-report.md`、`docs/p0-transparent-proxy-memo.md`、Go/No-Go 决策记录。  
**Go/No-Go 规则：** 若正文覆盖 <70% 或归因 <95%，MVP 调整为「元数据 + Agent 原生会话 + 少量可控应用正文」，透明代理提前到 P1.5；若文件读取遥测的日志量/权限/误报不可接受，P1b 限定为金丝雀文件 + 重点目录，不承诺全盘文件审计；若代理失效恢复不可靠，暂停功能开发先解决可靠性。

### 7.3 P1a 网络与内容审计 MVP 范围

**必须有（Must）：**

- Windows 10/11 x64；托盘 + 本地 UI；安装/卸载；暂停/恢复。
- 当前用户系统代理 + 本地 CA（显式同意）；上游代理保留/链式。
- 进程/应用发现：PID、路径、签名、命令行、父进程树、已知 AI 应用指纹。
- AI 端点识别；代理侧 PID 归因；覆盖状态页。
- AI 端点请求正文采集（脱敏/截断/加密）；其他应用元数据。
- 规则/检测：厂商白名单、密钥、PII、代码、上传量、未知端点。
- 告警 + 风险分级 + 可解释证据；交易/应用/时间线视图。
- SQLite 加密存储；保留期；哈希链；JSONL 导出 + 校验。
- 失效恢复 watchdog；日志脱敏；基础单元/集成测试；使用文档。
- 3 类真实 Agent 的端到端验收（建议：一个 Electron IDE/桌面应用、一个 Node CLI、一个 Python SDK 脚本）。

**应该有（Should）：**

- 按策略阻断（先只对确定性高危）；
- 每应用/仓库/厂商例外；
- 会话分组（同一进程树/时间窗）；
- MCP 配置发现与展示；
- 本机模型服务识别；
- 覆盖原因诊断（pinning/不遵守代理/运行时 CA 缺失）。

**P1a 不做（Out）：**

- WFP/WinDivert 透明重定向（P2）；
- 机器级/多用户/服务部署（P2）；
- 文件读取监控（P1b）；
- 全应用完整正文、全量响应长期保存；
- 本地 LLM 语义判定（P2）；
- 团队控制台/SSO/计费；
- macOS/Linux。

### 7.3.1 P1b 文件读取关联范围

**必须有（Must）：**

- 用户选择 1–N 个敏感目录（项目目录、`.ssh`、Documents、配置目录等），默认不选全盘。
- 通过 SACL + 安全日志 4663 采集「读取」事件：进程、路径、时间、访问类型；只覆盖配置的目录。
- 金丝雀文件：可选放置带唯一标记的假凭据/假文档，读取即告警；默认可关闭。
- 「读取 → 外发」关联：PID + 进程启动时间 + 时间窗 + 目标域名/IP + 字节量。
- 数据流证据页：文件路径、读取字节、进程身份、网络目标、上传量、风险原因。
- 隐私控制：只看路径/元数据，不读文件内容；可排除备份/同步/索引进程；可随时关闭。
- 日志量/性能/权限的实测报告；不能拖垮系统。

**明确不做（Out）：**

- 全盘文件读取监控；
- 在内核里阻断文件读取（minifilter pre-op，P3）；
- 对服务/SYSTEM 进程的完整文件审计（P2 机器级）；
- 从加密上传中还原文件内容（做不到）；
- 自动删除/隔离恶意软件（不是杀毒产品）。

> P1b 是「流氓软件读文件上传」需求的核心。它不依赖解密，因此即使对方用 E2EE/自定义加密，也能提供「谁读了什么、何时外发、发到哪里、发了多少」的证据。

### 7.4 P1a 迭代拆分（建议 4 个 Sprint）

| Sprint | 重点 | 交付 |
|---|---|---|
| S1 | 骨架 + 代理/CA 向导 + 系统代理恢复 + 基础存储 | 能启动/暂停/恢复；CA 安装/卸载；SQLite schema；进程列表 |
| S2 | 抓取 + 归因 + 脱敏 + 加密 + 实时流 | AI 端点识别；PID→App；交易列表；正文加密；截断/流式 |
| S3 | Agent 指纹 + 规则/检测 + 告警 + 证据 | 白名单/密钥/PII/代码/上传量；风险分级；应用详情；覆盖页 |
| S4 | UI 完整化 + 导出/保留 + 测试/打包/文档 + 内测 | 安装包；24h soak；3 类 Agent 验收；用户手册；问题清单 |

### 7.4.1 P1b 迭代拆分（建议 2 个 Sprint）

| Sprint | 重点 | 交付 |
|---|---|---|
| S5 | SACL/4663 采集 + 敏感目录配置 + 事件解析 + 性能/日志量测试 | 读取事件表；路径/进程/时间；开关；只覆盖选定目录 |
| S6 | 读取→外发关联 + 金丝雀 + 证据页 + 误报白名单 | 关联规则；金丝雀告警；数据流证据；排除备份/索引进程 |

### 7.5 建议代码结构

```
ai-agent-audit/
├─ app/                     # PySide6 托盘/窗口壳、通知、单实例
├─ core/
│  ├─ proxy/                # mitmproxy addon、CA、系统代理、上游链
│  ├─ attribution/          # TCP 表查询、进程树、PID→App
│  ├─ inventory/            # 进程/安装项/AI 指纹/MCP 配置
│  ├─ fileaccess/           # SACL/4663 采集、路径规则、金丝雀、读取→外发关联
│  ├─ policy/               # YAML 策略、检测器、评分
│  ├─ storage/              # SQLite、加密、哈希链、保留期
│  └─ telemetry/            # 可选 ETW/Sysmon、Agent 会话导入
├─ webui/                   # 本地 Web UI（如采用 QWebEngineView/浏览器）
├─ tests/
│  ├─ fixtures/             # 假 OpenAI/Anthropic/Gemini 服务、SSE/WS
│  └─ e2e/                  # 多运行时客户端、故障注入
├─ scripts/                 # 构建、签名、安装、诊断
└─ docs/                    # 兼容矩阵、威胁模型、隐私说明、运维
```

### 7.6 验收标准（MVP）

1. 干净 Windows 10 22H2/Windows 11 虚拟机，10 分钟内完成安装、CA/代理引导。
2. 至少 3 类 AI 客户端（Electron/Node CLI/Python）的 HTTPS 请求被正确归因并展示；失败项在覆盖页说明原因。
3. 模拟 `.env`/API Key/源代码上传：高风险告警可复现，证据包含进程、端点、规则、脱敏片段。
4. 策略阻断开启时，目标请求被拒绝；关闭后恢复正常。
5. 代理进程被强杀/重启 50 次，系统代理设置无残留，网络自动恢复。
6. 24 小时连续运行：无崩溃/明显内存增长；数据库写入正常；保留期清理生效。
7. 磁盘上无明文正文/密钥；CA 私钥 ACL 仅当前用户；审计链可验证。
8. 单元测试覆盖策略/脱敏/加密/哈希链；集成测试覆盖 HTTP/1.1、HTTP/2、SSE、WebSocket、大文件截断。
9. **P1b：** 测试进程读取配置目录中的 `.env` 后向本地假服务器上传，系统能生成「文件路径 → 进程 → 目标域名/字节 → 时间」证据链；金丝雀文件被读取能告警；关闭开关后无采集。
10. **P1b 性能：** SACL 只覆盖配置目录；空闲时 CPU 增幅可接受；日志滚动/清理正常；备份/同步/索引进程可排除。

---

## 8. 技术选型建议

### 8.1 推荐（MVP）

| 层 | 选择 | 理由 |
|---|---|---|
| 语言/运行时 | Python 3.12 | 与现有项目经验一致；mitmproxy 生态成熟；开发快 |
| 代理内核 | mitmproxy（嵌入 Addon） | HTTP/2、WebSocket、SSE、证书生成、流式/上游模式齐全；MIT |
| UI | PySide6 壳 + 本地 Web UI（QWebEngineView）或纯 PySide6 | 复用现有 PySide6 经验；复杂交易详情用 Web 更好 |
| 进程/系统 | psutil + pywin32 + ctypes | 无需驱动即可做 MVP |
| 文件读取遥测 | SACL + 安全日志 4663（P1b）；ETW Kernel-File（P2） | 先做敏感目录，避免全盘开销和驱动风险 |
| 存储 | SQLite WAL + AES-GCM + DPAPI | 简单、可检索、易打包；后续可换 SQLCipher |
| 策略 | YAML + pydantic + 自定义检测器 | 可解释、易迭代；后续可接 OPA/签名规则包 |
| 打包 | PyInstaller + Inno Setup | 现有经验；注意 mitmproxy 隐式导入/QtWebEngine 体积 |
| 测试 | pytest + 假 AI API + 多语言客户端 | 不调用真实模型，可重复 |

### 8.2 产品化演进

- 若追求更小体积/更好性能/更强内存安全：Tauri 2 + React + Rust 代理核心（hudsucker 或自研）+ Windows 服务/驱动；
- 不建议 MVP 同时上 Electron + Python（双运行时、体积大、打包复杂）；
- 不建议一开始写 WFP 驱动：先把产品价值（发现、审计、证据、策略）跑通；
- 代理/归因/策略/存储定义稳定接口，未来替换代理内核不影响上层。

### 8.3 许可证注意

- mitmproxy：MIT，适合商用；仍需保留版权声明。
- hudsucker：MIT/Apache-2.0，适合。
- AgentSight：MIT；可参考架构，但注意其 eBPF 代码平台限制。
- WinDivert：LGPL-3.0；动态链接/分发的合规方式需法务确认，驱动部分尤其。
- OpenSnitch/LuLu/Portmaster/simplewall/WFP 重定向示例：GPL-3.0；不要直接复制代码到闭源产品，只参考设计与接口。
- mcp-firewall：AGPL-3.0；不要并入闭源代码；可参考策略/审计字段。
- Sysmon：微软工具，分发/捆绑需看 EULA；MVP 不强制依赖。
- 依赖库（Presidio、gitleaks 规则等）逐项核对许可证；gitleaks 规则集与软件许可证可能不同。

---

## 9. 主要风险登记册

| 风险 | 概率/影响 | 触发表现 | 缓解 |
|---|---|---|---|
| CA/运行时信任不兼容 | 高/高 | Node/Python/Electron 报证书错误，抓不到正文 | P0 矩阵；按运行时注入；passthrough；Agent 原生数据兜底；覆盖页诚实提示 |
| 应用不遵守系统代理 | 高/中 | 连接可见但无正文，或完全看不到 | 覆盖页；启动器；P2 透明重定向；MCP/会话导入 |
| 公司代理/VPN/TUN 冲突 | 高/高 | 断网、环路、Clash TUN 绕过 | 上游链、PAC 保留、TUN 检测、明确提示；P0 专项 |
| 代理崩溃导致断网 | 中/高 | 退出后浏览器打不开 | watchdog、fail-open、启动清理、50 次故障注入 |
| 证书 pinning/QUIC/ECH | 中高/中 | 无法解密或绕过 | 标记覆盖缺口；passthrough；UDP/443 策略（P2）；不承诺全量 |
| 隐私/合规争议 | 高/高 | 员工/用户反对；监管风险 | 默认最小化、告知同意、加密、短保留、本地化、法务评审 |
| AV/EDR 误报 | 中高/中 | 安装/代理/CA 被拦截 | 无驱动 MVP、代码签名、厂商白名单、用户说明 |
| DLP 误报/漏报 | 中/中 | 告警疲劳或漏掉外发 | 可解释规则、allowlist、反馈调优；语义模型只辅助 |
| 大文件/流式性能 | 中/中 | 内存暴涨、代理卡死 | 流式阈值、正文上限、异步、WAL、压测 |
| 驱动开发/签名 | 高/高 | 蓝屏、兼容性、无法分发 | P2 再做；优先 WFP；预算签名/WHQL/回归测试 |
| Agent 日志格式变化 | 中/中 | 会话导入失效 | 适配器版本化；网络基线不依赖会话格式 |
| 应用层 E2EE/自定义加密 | 高/高 | 抓到 TLS 明文也看不懂；恶意 C2 无法还原 | 明确不承诺解密；文件读取/行为链兜底；隔离环境逐样本分析 |
| 文件读取遥测开销/权限 | 中高/高 | 4663 日志暴涨、系统变慢、需要管理员 | 只覆盖敏感目录；日志滚动；排除备份/索引；P0 压测；P2 再评估 ETW/minifilter |
| Windows 服务覆盖不足 | 高/高 | 用户态代理看不到 SYSTEM 服务；流氓服务照常外发 | 覆盖页明确；MVP 只做元数据；P2 机器级 + WFP/ETW；配合防火墙/EDR |
| 可疑样本环境下 CA 风险 | 中/高 | 恶意软件窃取 CA 私钥/绕过代理 | 不在日用主机装信任 CA；隔离 VM/快照；分析用独立 CA；先取证后清理 |
| 范围蔓延 | 高/高 | 做成 EDR/CASB，周期失控 | 明确非目标；MVP Gate；按阶段验收 |
| 本地管理员篡改 | 中/中 | 证据不可信 | 哈希链、外部锚定、TPM（可选）；明确不是防篡改硬件 |

---

## 10. 待确认的产品决策

在进入 P0 前，需要确认以下决策（括号内是建议默认值）：

1. **目标范围：** 只审计 AI Agent（默认先做） / AI Agent + 普通应用 / 还要覆盖 Windows 服务与流氓软件？  
   → 影响：用户态代理 vs 机器级服务/WFP/ETW；MVP 边界和周期。
2. **使用场景：** 个人自用（默认） / 小团队 / 企业统一部署？  
   → 影响：是否需要机器级服务、集中策略、多用户、合规材料。
3. **处置方式：** 只审计告警（默认） / 需要实时阻断 / 需要人工审批？  
   → 影响：代理是否必须同步阻塞、失败策略、UI 流程、可靠性要求。
4. **正文采集范围：** 只抓 AI 端点（默认） / 所有应用 / 按应用配置？  
   → 影响：隐私、性能、存储、法律风险。
5. **是否要做「文件读取 → 外发」关联：** 这是流氓软件需求的核心，建议做（P1b）。  
   → 影响：是否接受管理员权限、SACL 日志量、敏感目录配置、金丝雀文件。
6. **是否接受本地 CA：** 内容审计的前提；不接受则只能元数据 + 文件/行为关联。  
   → 影响：产品定位和功能承诺。
7. **技术栈：** Python 快速 MVP（默认） / Rust+Tauri 产品化优先？  
   → 影响：周期、体积、性能、后续驱动集成。
8. **首批必测应用：** 例如 Cursor、Claude Code/Desktop、Qoder、VS Code + Copilot/Cline、Codex CLI、Gemini CLI、Aider、Ollama/LM Studio，以及 1–2 个后台服务/流氓软件样本。  
   → 影响：P0 兼容矩阵和验收清单。
9. **运行环境：** 日用主机 / 隔离 VM / 企业终端？  
   → 影响：CA 风险、权限、是否允许驱动、数据保留与合规。
10. **平台优先级：** Windows 10/11 先（默认），macOS/Linux 何时加入？  
   → 影响：架构抽象和测试矩阵。

---

## 11. 参考来源

- [AgentSight](https://github.com/eunomia-bpf/agentsight) — eBPF/TLS 系统级 AI Agent 观测；Windows 会话文件支持说明见其 README/installation 文档。
- [AgentSight SSL capture 文档](https://github.com/eunomia-bpf/agentsight/blob/master/docs/ssl-capture.md)
- [OpenSnitch](https://github.com/evilsocket/opensnitch)
- [Portmaster](https://github.com/safing/portmaster)
- [LuLu](https://github.com/objective-see/LuLu)
- [simplewall](https://github.com/henrypp/simplewall)
- [WinDivert](https://github.com/basil00/WinDivert) / [WinDivert 文档](https://github.com/basil00/WinDivert/wiki/WinDivert-Documentation)
- [WFP Traffic Redirection Driver](https://github.com/bot-man-jl/wfp-traffic-redirection-driver)
- [ProxyIntercept](https://github.com/huaraz/ProxyIntercept)
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) / [mitmproxy 模式文档](https://docs.mitmproxy.org/stable/concepts/modes/)
- [hudsucker](https://github.com/omjadas/hudsucker)
- [mcp-firewall](https://github.com/ressl/mcp-firewall)
- [agentgateway](https://github.com/agentgateway/agentgateway)
- [LiteLLM](https://github.com/BerriAI/litellm)
- [Langfuse](https://github.com/langfuse/langfuse)
- [Microsoft Presidio](https://github.com/microsoft/presidio)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [awesome-auditable-ai](https://github.com/yzhao062/awesome-auditable-ai)
- [Node.js Enterprise Network Configuration](https://nodejs.org/learn/http/enterprise-network-configuration) — `NODE_USE_ENV_PROXY`、`NODE_EXTRA_CA_CERTS`、`NODE_USE_SYSTEM_CA`。
- [Electron issue #11741](https://github.com/electron/electron/issues/11741) — Chromium 与 Node 证书信任差异。
- [GetExtendedTcpTable (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Windows Filtering Platform (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Sysmon (Microsoft)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Security Event 4663（对象访问）](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4663) — SACL 审计读取/写入。
- [Windows 文件系统审计说明](https://techcommunity.microsoft.com/discussions/windowsinsiderprogram/file-system-auditing---event-id-4663-not-logging/4429279) — Audit File System + SACL 配置。
- [ETW 文档 (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Microsoft Defender XDR DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) — 注意其事件范围，不假设包含全部文件读取。
- [Minifilter 驱动 / DLP 参考](https://medium.com/@0xaslihan/minifilter-technique-in-data-leakage-prevention-systems-64cf3c97aa19)
- [Certificate Pinning 与 SSL/TLS 检查](https://help.zscaler.com/zia/certificate-pinning-and-ssltls-inspection) — pinning 会阻止企业 TLS 检查。
- [TLS 检查概述 (Microsoft Entra)](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-transport-layer-security) — pinning 导致检查失败/功能受损。
- [Responsibly Intercepting TLS and the Impact of TLS 1.3](https://docs.broadcom.com/doc/responsibly-intercepting-tls-and-the-impact-of-tls-1.3.en) — TLS 1.3 与授权拦截。
- [ETW Threat Intelligence 与 PPL 限制](https://connormcgarr.github.io/securitytrace-etw-ppl/) — ETW-TI 不是普通用户态工具可随意使用的数据源。
- [Canary Tokens / Honeytokens](https://www.decryptiondigest.com/blog/how-to-deploy-canary-tokens-honeytokens-breach-detection)
- [WinHTTP / 系统代理配置](https://learn.microsoft.com/en-us/purview/device-onboarding-configure-proxy) — 机器级 WinHTTP 代理与设备代理说明。
- [加密流量外发检测（NDR 视角）](https://www.trellix.com/security-awareness/network/why-is-encrypted-traffic-analysis-key-to-ndr/) — 不解密时依靠元数据/行为。
- [Reqable 透明代理 issue #337](https://github.com/reqable/reqable-app/issues/337) — Windows 透明代理的工程复杂度参考。

---

## 12. 下一步

1. 确认第 10 节的关键决策（至少确认：目标范围是否含服务/流氓软件、是否做文件读取关联、个人/团队、是否阻断、首批应用、是否接受 CA、个人主机还是隔离 VM）。
2. 执行 P0：先搭一个**不产品化**的验证仓库，完成代理+CA+归因+多运行时兼容矩阵+故障恢复+文件读取/SACL 关联+透明代理评估。
3. 用 P0 报告决定 MVP 边界：是「AI 应用正文审计」优先，还是「文件读取 + 网络外发行为链」优先；两者都做则按 P1a/P1b 顺序推进。
4. P0 通过后再进入 P1，不建议先写 UI 或驱动。
5. 如果目标是分析可疑流氓软件，先在隔离 VM 里跑 P0，不要在日常主机上安装信任 CA。

> 注：本计划中的「未验证」项都应在 P0 用实际 Windows 客户端测试，不要直接把假设写进产品承诺。
