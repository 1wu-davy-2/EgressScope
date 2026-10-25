# EgressScope 文档中心

本目录集中存放 EgressScope 的工程设计与执行文档，面向使用者、开发者、安全评审与发布维护者。

> 当前快照：v0.4.0（文档更新于 2026-10-25）。根目录 [`README.md`](../README.md) 是安装与使用的权威入口，[`PLAN.md`](../PLAN.md) 是立项前的调研底稿，[`CHANGELOG.md`](../CHANGELOG.md) 记录版本事实。本目录负责把设计与执行信息整理成可维护的工程文档，不替代这些原始来源。

## 文档地图

| 文档 | 内容 | 主要读者 |
| --- | --- | --- |
| [design.md](design.md) | 问题定义、设计原则、总体架构、模块职责、关键设计决策、安全与隐私边界 | 架构与安全评审、开发者 |
| [execution-plan.md](execution-plan.md) | P0/P1/P2 阶段映射、v0.4.0 交付状态、验收证据、风险、后续路线 | 项目维护者、贡献者 |
| [testing-and-release.md](testing-and-release.md) | 测试矩阵、CI 工作流、发布运行手册、产物与校验、验证缺口、故障恢复 | 发布维护者、CI 维护者 |
| [../README.md](../README.md) | 安装、启动参数、配置热更新、断网保护、数据位置、构建与手动验证 | 使用者、集成者 |
| [../PLAN.md](../PLAN.md) | 调研结论、技术路线对比、详细阶段计划、威胁模型与研究参考 | 需要完整背景的人 |
| [../CHANGELOG.md](../CHANGELOG.md) | 按版本记录变更；发布工作流据此生成 Release 正文 | 使用者、发布维护者 |
| [../web/tech.html](../web/tech.html) | 对外技术说明页，覆盖数据路径、归因、可见性、断网保护与验证状态 | 产品访客、评估者 |
| [../LICENSE](../LICENSE) | PolyForm Noncommercial License 1.0.0 全文 | 所有使用者 |

对外页面：

- 产品介绍：<https://1wu-davy-2.github.io/EgressScope/>
- 技术说明：<https://1wu-davy-2.github.io/EgressScope/tech.html>
- 发布与校验：<https://github.com/1wu-davy-2/EgressScope/releases/latest>

## 建议阅读路径

### 第一次使用

1. [README 快速开始](../README.md#快速开始)：选择安装包、便携版或源码运行。
2. [README 系统代理的失败模式与断网保护](../README.md#系统代理的失败模式与断网保护)：理解全局代理的风险与四层恢复。
3. [design.md 安全与隐私](design.md#7-安全与隐私)：确认授权范围与本地 CA 的影响。
4. [README 已知限制](../README.md#已知限制主动暴露)：确认哪些流量本来就看不到。

### 评估是否适合

1. [design.md 问题与目标](design.md#1-问题与目标)：确认产品定位。
2. [design.md 覆盖与可见性](design.md#63-可见性分级)：区分正文、元数据与未覆盖。
3. [testing-and-release.md 验证缺口](testing-and-release.md#10-验证缺口)：确认哪些结论有测试、哪些仍待验证。
4. [execution-plan.md 当前交付状态](execution-plan.md#2-当前交付状态)：确认 v0.4.0 已实现与未实现的能力。

### 参与开发

1. [design.md 总体架构](design.md#4-总体架构)与[模块职责](design.md#5-模块与职责)。
2. [PLAN.md](../PLAN.md) 的技术路线、威胁模型与风险登记册。
3. [testing-and-release.md 测试矩阵](testing-and-release.md#2-测试矩阵)：先跑通与改动相关的测试。
4. [README 项目结构](../README.md#项目结构)：定位具体模块。

### 发布维护

1. [testing-and-release.md 发布运行手册](testing-and-release.md#5-发布运行手册)。
2. [CHANGELOG.md](../CHANGELOG.md)：为待发布版本补充小节。
3. [testing-and-release.md 验证缺口](testing-and-release.md#10-验证缺口)：发布说明不得越过这些边界。

## 权威来源与冲突处理

同一事实出现多个版本时，按以下优先级判断：

1. **代码、测试与工作流**：实际行为以 `ai_audit/`、`tests/`、`.github/workflows/` 为准。
2. **README**：面向使用者的操作说明、启动参数与数据位置。
3. **CHANGELOG**：某个版本实际包含的变更；发布说明由它生成。
4. **docs/**：对设计与执行的综合整理，应与前三者保持一致。
5. **PLAN.md**：立项前的研究与计划，包含当时的假设；其中的“待验证”“建议”不等于已实现能力。

如果 docs 与代码或测试冲突，以代码与测试为准，并在同一次改动中修正文档。不要为了叙述完整而补写未经验证的能力。

## 当前状态快照

- 版本：**v0.4.0**；仓库另有未发布的许可变更（PolyForm Noncommercial 1.0.0）。
- 主要平台：Windows 10/11 x64（安装包、托盘、系统代理接管、自动更新）。
- Windows ARM64：便携版；Tk 控制台与托盘未在 ARM64 实机做 UI 验收。
- Linux / macOS：审计引擎与 Web 审计台；不提供系统代理接管、一键 CA、托盘或开机自启。
- 许可：源码可用（source-available），非 OSI 开源；允许非商业使用，禁止商业用途。
- 既有 v0.4.0 二进制早于许可文件加入仓库；下一次构建/发布起，安装器、安装目录与 Release 资产会携带 `LICENSE`。

状态标记约定：

| 标记 | 含义 |
| --- | --- |
| 已实现 | 代码、测试或发布产物可验证 |
| 部分实现 | 有明确能力，但覆盖或验证不完整，文档会写出边界 |
| 未实现 | 仅在路线图中，不应在对外材料中当作现有能力 |
| 计划 | 有方向，但没有承诺时间或版本 |

## 文档维护规则

- **版本发布时**：更新 `CHANGELOG.md`、`ai_audit/__init__.py` 的版本号、README 与站点中的版本文案，以及 `tests/site_check.py` 的版本断言。
- **能力变化时**：同步更新 README、`docs/design.md` 与 `docs/execution-plan.md`；涉及官网文案时还要更新 `web/intro.html` / `web/tech.html` 并运行站点门禁。
- **测试变化时**：更新 `docs/testing-and-release.md` 的矩阵与基线。测试数量只是快照，以实际运行输出为准。
- **发布流程变化时**：同步 `.github/workflows/`、README 与发布手册。
- **不要写入**：真实审计数据、凭据、客户信息、内部主机名、未脱敏日志，或任何无法从仓库验证的客户案例与性能数字。
- **不要过度承诺**：不把“检测候选”写成“已拦截”，不把“元数据”写成“正文”，不把“计划”写成“已发布”。

## 相关约束

- 仅审计你拥有或已获明确书面授权的设备。
- 不在存有真实凭据的日常主机上分析疑似恶意软件；使用隔离虚拟机或快照，并在结束后移除审计 CA。
- 不承诺绕过证书固定、mTLS、应用层端到端加密或恶意程序自定义加密。
- 文件触达只记录元数据，不读取文件内容。
- 商业使用需事先取得版权持有人的书面授权，详见 [LICENSE](../LICENSE)。
