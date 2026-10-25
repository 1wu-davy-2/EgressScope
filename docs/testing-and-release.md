# EgressScope 测试与发布手册

> 状态快照：v0.4.0，文档更新于 2026-10-25。
> 读者：发布维护者、CI 维护者、需要判断证据强度的评估者。
> 测试数量是当前快照，实际以运行输出为准。

## 1. 测试策略

EgressScope 的测试分为五层：

1. **静态门禁**：官网页面结构、i18n 覆盖、ARIA、JSON-LD、外部依赖、版本与许可链接。
2. **源码级端到端冒烟**：在临时数据目录启动真实代理与自签名 HTTPS 服务，验证代理、CA、归因、DLP、加密、阻断、哈希链、旁路观测与导出。
3. **契约与回归测试**：断网保护、关机钩子、自启、自愈、热更新、更新器、可见性、旁路观测、托盘与上游链路。
4. **打包验收**：直接启动 PyInstaller 产物，验证打包后的 Web 资源、CA、转发、鉴权与端口释放。
5. **人工冒烟与发布检查**：Windows x64 托盘、安装器、真实网络与页面部署；这些不由自动化测试完全覆盖。

原则：

- 自动化测试不安装根证书、不修改真实系统代理、不写真实 Run 键、不调用真实模型。
- 需要验证系统行为时，使用内存假实现、临时计划任务或模拟会话结束消息。
- 发布结论不得超出测试与可复现记录能证明的范围；未验证项必须写入[验证缺口](#10-验证缺口)。

## 2. 测试矩阵

| 测试 | 覆盖 | 平台 | 当前基线 | 备注 |
| --- | --- | --- | --- | --- |
| `tests/site_check.py` | 首页与技术页、i18n、ARIA、JSON-LD、版本、许可、跨页链接 | 任意 | 48 项 | 无外部样式/脚本；`__REPO_URL__` 占位符 |
| `tests/smoke_test.py` | 代理、CA、HTTPS 转发、归因、AI/DLP、可见性、加密、阻断、哈希链、旁路 API、导出、Web 鉴权 | Windows / Linux / macOS | 64 项 | 使用临时数据目录与自签名 HTTPS Mock |
| `tests/recovery_test.py` | 代理恢复、端口校准、看门狗、计划任务、自启、自愈、热更新、关机钩子、发布说明 | Windows；其他平台跳过 Windows 专属项 | Windows 78 项 | 不读写真实代理注册表；会创建并删除临时计划任务 |
| `tests/updater_test.py` | 版本比较、资产选择、`.sha256` / `SHA256SUMS.txt`、域名限制、下载校验、静默参数、`--check-update` | 任意 | 52 项 | 不下载真实 Release |
| `tests/visibility_test.py` | 五级分类、CONNECT 隧道、TLS 握手失败、WebSocket、正文降级、旧库迁移、导出字段 | 任意 | 42 项 | 不依赖真实外部网络 |
| `tests/netwatch_test.py` | 公网过滤、TCP/UDP 分类、DNS 缓存、PID 归因、去重、启停、事件计数、导出与清理 | 任意；DNS 缓存仅 Windows 行为 | 69 项 | 只读元数据 |
| `tests/tray_test.py` | 平台门禁、关闭/隐藏/退出、菜单、暂停/恢复、气泡、状态同步 | 任意（假 pystray/Pillow） | 67 项 | 6 项图标渲染检查依赖 Pillow；不启动真实托盘 |
| `tests/upstream_test.py` | 上游 CONNECT 中继、正文捕获、自动继承条件 | 任意 | 15 项 | 本地最小中继 |
| `tests/packaged_test.py` | 打包 EXE 的 Web 资源、令牌、CA、HTTPS、归因、DLP、解密、导出、阻断、哈希链、端口释放 | Windows x64 / ARM64 | 无固定项数 | 由发布工作流执行；需先构建产物 |

当前本地基线：`smoke_test.py` 64 项、`site_check.py` 48 项通过（2026-10-25）。其他数量来自现有 README/CHANGELOG 记录，发布前应重新运行确认。

## 3. 本地运行

### 3.1 环境

- Python 3.12+
- 安装依赖：

```bat
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

- 源码测试不需要预先打包；`tests/packaged_test.py` 需要 `dist\EgressScope.exe`。

### 3.2 Windows

```bat
.venv\Scripts\python.exe tests\smoke_test.py
.venv\Scripts\python.exe tests\recovery_test.py
.venv\Scripts\python.exe tests\updater_test.py
.venv\Scripts\python.exe tests\visibility_test.py
.venv\Scripts\python.exe tests\netwatch_test.py
.venv\Scripts\python.exe tests\tray_test.py
.venv\Scripts\python.exe tests\upstream_test.py
.venv\Scripts\python.exe tests\site_check.py
```

打包验收：

```bat
build.bat
.venv\Scripts\python.exe tests\packaged_test.py
```

### 3.3 Linux / macOS

```bash
.venv/bin/python tests/smoke_test.py
.venv/bin/python tests/updater_test.py
.venv/bin/python tests/recovery_test.py
.venv/bin/python tests/visibility_test.py
.venv/bin/python tests/netwatch_test.py
.venv/bin/python tests/tray_test.py
.venv/bin/python tests/upstream_test.py
.venv/bin/python tests/site_check.py
```

`recovery_test.py` 会跳过 Windows 专属的窗口、计划任务与注册表检查；Linux/macOS 的 PID 归因与端到端覆盖也弱于 Windows。

### 3.4 测试边界

- 不安装根证书、不启用系统代理、不写真实自启项。
- `recovery_test.py` 在 Windows 上会创建一个指向 `cmd.exe /c exit 0` 的临时计划任务并在结束时删除；如果当前用户无权创建计划任务，相关检查会失败或降级。
- 关机钩子只接收模拟的 `WM_QUERYENDSESSION` / `WM_ENDSESSION`，**不会触发真实关机或重启**。
- 测试使用 `--insecure-upstream` 仅针对本地 Mock 服务；生产运行不要开启。

## 4. CI 工作流

### 4.1 `.github/workflows/ci.yml`

触发：push 到 `main`、Pull Request、手动运行。

矩阵：Windows x64（`windows-2022`）、Linux x64（`ubuntu-22.04`）、macOS arm64（`macos-15`）。

步骤：安装 Python 3.12 与开发依赖，依次运行：

1. `tests/smoke_test.py`
2. `tests/updater_test.py`
3. `tests/recovery_test.py`
4. `tests/visibility_test.py`
5. `tests/netwatch_test.py`
6. `tests/tray_test.py`
7. `tests/upstream_test.py`
8. `tests/site_check.py`

CI 不启动真实桌面 UI、不安装系统 CA、不修改真实系统代理。

### 4.2 `.github/workflows/release.yml`

触发：推送 `v*` tag，或手动运行。

构建矩阵与特殊处理：

| 平台 | Runner | 特殊步骤 |
| --- | --- | --- |
| Windows x64 | `windows-2022` | 构建单文件 EXE、打包验收、编译 Inno Setup 安装包、可选 `signtool` 签名 |
| Windows ARM64 | `windows-11-arm` | 安装 Rust ARM64 target、用 vcpkg 构建 ARM64 OpenSSL、进入 `vcvarsall arm64`、源码冒烟、构建、打包验收 |
| Linux x64 | `ubuntu-22.04` | 构建单文件产物并打成 `.tar.gz` |
| Linux ARM64 | `ubuntu-24.04-arm` | 同上 |
| macOS x64 | `macos-15-intel` | 同上 |
| macOS arm64 | `macos-15` | 同上 |

Windows ARM64 的特殊依赖：

- `cryptography` 固定为 `46.0.3`（上游最后的 `win_arm64` wheel）。
- `aioquic` 的 `_crypto` 扩展需要 ARM64 OpenSSL，由 CI 通过 vcpkg 构建。
- `libcrypto` 运行库随 EXE 打包；`mitmproxy_rs`、`brotli` 等从源码编译。

发布 job 只在 tag 上运行：

1. 下载所有平台产物。
2. 复制 `LICENSE` 到发布目录。
3. 生成每个产物的 `.sha256`（构建 job）与汇总 `SHA256SUMS.txt`（publish job）。
4. 从 `CHANGELOG.md` 截取对应版本小节作为 Release 正文；缺失时回退为指向 CHANGELOG 的提示。
5. 创建 GitHub Release 并上传所有资产。

> 手动运行 `release.yml` 不是 tag 时不会创建 Release；安装包版本回退为 `0.0.0-dev`。

### 4.3 `.github/workflows/pages.yml`

触发：`main` 上的 `web/**` 变更、工作流文件变更，或手动运行。

步骤：

1. 用 `sed` 把 `web/intro.html` 与 `web/tech.html` 中的 `__REPO_URL__` 替换为仓库地址。
2. 校验两个页面都包含替换后的仓库地址。
3. 复制 `web/assets/*`、`robots.txt`、`sitemap.xml`。
4. 上传并部署到 GitHub Pages。

页面地址：

- <https://1wu-davy-2.github.io/EgressScope/>
- <https://1wu-davy-2.github.io/EgressScope/tech.html>

## 5. 发布运行手册

发布必须在 `main` 上完成，并确保工作区干净。不要在本机构建用于发布的 Windows 安装包；使用 GitHub 托管 runner。

### 5.1 发布前检查

1. **确定版本号**：更新 `ai_audit/__init__.py` 的 `__version__`。
2. **写 CHANGELOG**：在 `CHANGELOG.md` 顶部新增 `## v<版本>` 小节，分别写中文与 English；发布工作流会原样截取。
3. **同步版本文案**：
   - `README.md` 的当前版本、安装包名、产物矩阵与示例命令；
   - `web/intro.html`、`web/tech.html` 的版本与下载文案；
   - `tests/site_check.py` 的版本断言；
   - `docs/` 中的状态快照（本文件、设计说明与执行计划）。
4. **同步能力边界**：新增能力要同时更新 README、docs 与站点；未验证项继续保留在“已知限制”。
5. **许可与安装器**：确认 `LICENSE` 存在；`installer/EgressScope.iss` 的 `LicenseFile` 与 `LICENSE.txt` 安装项未被移除。
6. **运行门禁**：至少运行与改动相关的源码测试与 `tests/site_check.py`；发布构建由 CI 再做打包验收。
7. **检查工作区**：`git status`、`git diff --check`，确认没有构建产物、审计数据或凭据。

### 5.2 发布命令

```bash
git status
git diff --check
git add <changed-files>
git commit -m "release: vX.Y.Z"
git push origin main

git tag -a vX.Y.Z -m "EgressScope vX.Y.Z"
git push origin vX.Y.Z
```

推送 tag 后：

1. 打开 GitHub Actions 的 **Release builds**，等待六个平台全部成功。
2. 确认 **Publish GitHub release** 成功，Release 正文来自 `CHANGELOG.md` 对应小节。
3. 验证资产列表：六平台产物、Windows x64 安装包、每个产物的 `.sha256`、`SHA256SUMS.txt`、`LICENSE`。
4. 如果修改了 `web/**`，确认 **Deploy product site** 成功，并检查线上首页与技术页。

### 5.3 发布后验证

- 下载 Windows x64 安装包，核对 `SHA256SUMS.txt` 中的哈希。
- 在干净环境安装，确认无需管理员权限、固定安装目录、开始菜单存在“恢复系统代理”。
- 启动后确认审计台可访问、CA 未自动安装、系统代理未自动修改。
- 注入 `agent-env.cmd`，用测试请求确认代理连通与归因。
- 确认 `--check-update` 输出 JSON，且不会自动安装。
- 检查 Release 页面没有虚构的客户案例、性能数字或“全量解密”承诺。

## 6. 产物矩阵

| 平台 | 发布资产 | 安装包 | 自动更新 |
| --- | --- | --- | --- |
| Windows x64 | `EgressScope-v<版本>-windows-x64.exe` + `EgressScope-Setup-v<版本>.exe` | 有（per-user） | 支持 |
| Windows ARM64 | `EgressScope-v<版本>-windows-arm64.exe` | 无 | 手动 |
| Linux x64 | `EgressScope-v<版本>-linux-x64.tar.gz` | 无 | 手动 |
| Linux ARM64 | `EgressScope-v<版本>-linux-arm64.tar.gz` | 无 | 手动 |
| macOS x64 | `EgressScope-v<版本>-macos-x64.tar.gz` | 无 | 手动 |
| macOS arm64 | `EgressScope-v<版本>-macos-arm64.tar.gz` | 无 | 手动 |

每个平台产物（以及 Windows 安装包）都有对应 `.sha256`；`SHA256SUMS.txt` 汇总所有资产（含 `LICENSE`）。

## 7. 校验与签名

### 7.1 校验 SHA-256

Linux / macOS：

```bash
sha256sum -c SHA256SUMS.txt
```

Windows PowerShell：

```powershell
Get-FileHash .\EgressScope-Setup-v0.4.0.exe -Algorithm SHA256
```

或使用：

```bat
certutil -hashfile EgressScope-Setup-v0.4.0.exe SHA256
```

SHA-256 只能证明下载内容与发布页一致，不能证明发布者身份。

### 7.2 代码签名

- Windows EXE 与安装包默认**未签名**。仓库配置 `WINDOWS_CERT_PFX_BASE64`（可选 `WINDOWS_CERT_PASSWORD`）后，发布工作流的可选 `signtool` 步骤会签名。
- macOS 与 Linux 产物未签名、未公证。macOS Gatekeeper 与 Windows SmartScreen 可能要求手动放行。
- 未配置签名时，不要在发布说明或官网写“已签名”。

### 7.3 许可证资产

- 发布工作流会把根目录 `LICENSE` 复制到 Release 资产，并计入 `SHA256SUMS.txt`。
- Inno Setup 安装器通过 `LicenseFile` 显示许可证，并把 `LICENSE.txt` 安装到程序目录。
- **v0.4.0 的既有二进制早于该变更**，不包含 `LICENSE`；下一次构建/发布起生效。

## 8. 故障恢复与回滚

### 8.1 系统代理异常

按影响从小到大：

1. 控制窗口点击 **恢复原始系统代理**。
2. 安装版开始菜单运行 **恢复系统代理**，或执行 `EgressScope.exe --restore-proxy`。
3. 自动化场景执行 `EgressScope.exe --recover-proxy`（仅在代理端口已停止监听时恢复）。
4. Windows 设置 → 网络和 Internet → 代理，关闭“使用代理服务器”。

强制结束、断电或蓝屏后，下一次登录会由启动校准与看门狗兜底；若计划任务被策略禁用，需要手动恢复。

### 8.2 安装与更新回滚

- 安装包升级只覆盖程序文件，不改动 `%LOCALAPPDATA%\EgressScope` 审计数据。
- 需要回滚时，下载上一版本的安装包/便携版，核对 SHA-256 后覆盖安装；数据目录默认保留。
- 更新器下载的安装包校验失败会被删除，不会启动。
- 卸载时交互式安装器会询问是否删除数据目录；需要保留证据时选择保留。

### 8.3 停止审计

- 托盘可用时：右键托盘图标 → **退出并恢复系统代理**。
- 托盘不可用或使用 `--no-tray`：关闭窗口即退出。
- 需要移除 HTTPS 解密能力时，再点击 **移除本地 CA**。
- 需要撤销开机自启时，点击 **关闭开机自启** 或运行 `--disable-autostart`。
- 需要导出证据时，先完成脱敏 JSONL 导出，再清理数据目录。

## 9. 发布记录与证据

- 发布历史与每个版本的变更：<https://github.com/1wu-davy-2/EgressScope/releases>
- CI 运行记录：<https://github.com/1wu-davy-2/EgressScope/actions>
- 版本说明源：`CHANGELOG.md`
- 测试代码：`tests/`
- 工作流：`.github/workflows/`

发布说明应链接到这些可验证来源，而不是仅凭文字声明。

## 10. 验证缺口

以下事项没有完整验证，发布材料必须保留这些边界：

1. **真实关机/注销/重启恢复**：没有在 CI 或真实虚拟机执行；只有契约测试与可选的 `tools/shutdown_lab.ps1`。
2. **WFP / WinDivert 透明重定向**：未实现，也未做驱动原型验证。
3. **多运行时兼容矩阵**：没有针对 Electron、Node CLI、Python SDK、Go、.NET、Java 等逐项形成公开报告。
4. **Windows ARM64 UI**：Tk 控制台与托盘未在 ARM64 实机做 UI 验收；源码冒烟与打包验收在 GitHub runner 上完成。
5. **Windows x64 托盘**：只做过人工冒烟；`tests/tray_test.py` 使用假 pystray/Pillow，不启动真实通知区域。
6. **Linux / macOS 产物**：由 GitHub runner 构建，未在开发机逐一执行；没有系统代理接管、CA 安装、托盘或开机自启。
7. **签名与公证**：Windows 默认未签名；macOS/Linux 未签名、未公证。
8. **打包测试覆盖**：`packaged_test.py` 依赖已构建的 EXE，只在发布工作流运行；文档改动不会自动重跑打包验收。
9. **24 小时连续运行 / soak**：没有公开的通过记录；持续运行稳定性需在实际环境自行验证。
10. **页面视觉验证**：本地双语/响应式检查使用浏览器手动或脚本模拟，不构成对所有浏览器与设备的保证。
11. **既有 v0.4.0 许可证**：该版二进制早于 `LICENSE` 加入仓库，不包含许可证文件。
12. **独立 P0 报告**：计划中的 `docs/p0-*.md` 未交付；实际证据在测试、CI 与 CHANGELOG 中，未验证项以本节为准。

## 11. 相关文档

- [文档中心](README.md)
- [设计说明](design.md)
- [执行计划](execution-plan.md)
- [README 开发、测试与构建](../README.md#开发测试与构建)
- [CHANGELOG](../CHANGELOG.md)
