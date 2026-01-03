<!--
AUDIT REPORT (ASCII preface).
This preface is intentionally long and contains ASCII characters only.
It exists to avoid Windows sandbox logging/truncation issues when tool output is truncated.
Keep this block ASCII-only and longer than 300 bytes.
----------------------------------------------------------------------
----------------------------------------------------------------------
----------------------------------------------------------------------
----------------------------------------------------------------------
-->

# 项目梳理与严格评分审计报告（core）

> 生成时间：2026-01-03  
> 作用域：`F:\ZMctf\core`（Rust workspace：`flag-detector` / `tool-runner` / `floss-integration` / `zmctf-constraints`）  
> 质量门槛：`-D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo`，且禁止使用任何 `#[allow(clippy::...)]` 规避。  
> 产物：严格 clippy 输出已落盘到 `clippy_flag_detector.log`（UTF-8）。

## 0. 验证命令与结果（硬门槛）

- 严格 clippy：`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo`（通过；输出：`clippy_flag_detector.log`）
- 格式校验：`cargo fmt --all -- --check`（通过）
- 全量测试：`cargo test --workspace --all-features --locked --offline`（通过）
- 规避检查扫描：未发现 workspace 成员源码存在 `#[allow(clippy::...)]`

## 1. 项目结构（架构视角）

- `flag-detector/`：核心检测引擎与 API（解码链、规则、归档分析、缓存、外部工具集成、`zmctf-server`）。
- `tool-runner/`：外部命令统一执行层（timeout/输出截断/环境变量/诊断字段），避免散落 `std::process::Command`。
- `floss-integration/`：对 FLOSS 的参数化封装（命令构建 + JSON 输出解析 + 截断语义治理）。
- `zmctf-constraints/`：全局资源与安全约束模型（输入大小、解压限制、外部工具 stdout/stderr/timeout 上限、截断语义）。

## 2. 严格门槛落地（关键整改点）

### 2.1 严格 clippy 零容忍

- 统一补齐公开 API 的 `# Errors` 文档、`#[must_use]`、`const fn`（可行处）。
- 将“过多 bool 字段”系统性替换为二态枚举（如 `Toggle`）或显式 enum，避免隐式状态组合爆炸。
- 将超长函数拆解为可测试/可复用的私有小函数，降低圈复杂度与维护成本。

### 2.2 `clippy::cargo` 的依赖冲突消除（`windows-sys` 多版本）

- 现象：`windows-sys` 同时出现 `0.60.x` 与 `0.61.x` 触发 `clippy::multiple_crate_versions`。
- 根因：`tokio` 链路引入 `mio -> windows-sys 0.61`；而 `tokio -> socket2 0.6.1 -> windows-sys 0.60`。
- 处理：对 `socket2 v0.6.1` 做 workspace 内 path patch（不改版本号，只改依赖约束），使其 Windows 目标依赖 `windows-sys = "0.61"`。
  - 根配置：`Cargo.toml` 的 `[patch.crates-io]`。
  - patched crate：`vendor/socket2/`（仅用于依赖统一；非 workspace member）。

### 2.3 工具链合规（workspace lints / rustfmt）

- `Cargo.toml`：workspace 根清单为 “virtual manifest”，不能使用 `[lints.*]`；已修正为 `[workspace.lints.*]`，确保 `cargo fmt/clippy/metadata` 可运行。
- `rustfmt.toml`：移除 nightly-only 配置项（`group_imports`/`imports_granularity`），并将废弃的 `fn_args_layout` 替换为 `fn_params_layout`；随后执行 `cargo fmt --all` 统一换行风格（Unix/LF）。

## 3. 回归测试（覆盖新增与高风险路径）

- 测试现状：`flag-detector` 单测 + doc tests 覆盖主要高风险路径（归档解包、PCAP/TCP 重组、规则解析、hashcat 输出解析、缓存一致性等）。
- 本次验证命令（离线锁定）：`cargo test --workspace --all-features --locked --offline`（已通过；`flag-detector` 76 个单测 + 16 个 doc tests）。

## 4. 原子模块严格评分（0-10）

评分维度（同权重）：架构清晰度 / 错误与诊断 / 安全约束 / 可测试性 / 可维护性 / 与 workspace 规范一致性。

### 4.1 Crate 级评分

| Crate | 分数 | 结论 |
|---|---:|---|
| `zmctf-constraints` | 8.5 | 约束模型统一、语义清晰；建议补充更多边界用例与文档示例。 |
| `tool-runner` | 8.0 | 执行/截断/诊断字段完备；建议补一个可观测的“命令行回显/参数可检视”接口（仅测试/调试）。 |
| `floss-integration` | 7.8 | 参数覆盖和截断语义治理到位；测试数量偏少，可补 JSON 解析与截断回归。 |
| `flag-detector` | 8.2 | 模块齐全、测试覆盖较高、严格 clippy 通过；但外部依赖补丁（`vendor/socket2`）引入维护成本。 |

### 4.2 `flag-detector` 模块级评分（摘要）

| 模块 | 分数 | 主要理由（短） |
|---|---:|---|
| `archive` | 8.0 | 路径穿越防护与限制较完善；建议扩展多格式/异常输入测试。 |
| `decoder`/`encoding` | 8.5 | 解码链与可打印判定清晰；建议加强性能基准与极端输入测试。 |
| `rules` | 8.0 | 解析/应用逻辑可读性提升；已补位置参数回归测试。 |
| `pcap` | 7.8 | 解析逻辑已分解并可测；建议补 PCAPNG 时间戳/多接口块测试。 |
| `stego` | 7.6 | 配置与外部工具参数更规范；建议分层“构建命令/执行/解析”以便更细粒度测试。 |
| `hashcat` | 7.7 | 命令构建与结果读取更稳健；外部工具依赖强，建议补 mock/离线解析测试。 |
| `history`/`cache` | 8.0 | 锁粒度与 IO 分离更合理；建议补并发/损坏文件恢复测试。 |
| `facade`/`api` | 8.0 | 门面层文档与参数治理增强；建议补端到端错误路径测试。 |

## 5. 风险清单（必须直面）

1. `vendor/socket2`：属于“依赖树治理补丁”，后续需要跟踪上游（若 `socket2` 发布兼容 `windows-sys 0.61` 的新版本，应优先回归到官方发布版，移除 vendor）。
2. Windows 环境下构建产物的写入/清理可能触发权限策略：建议在 CI/开发机上固定可写的 `CARGO_TARGET_DIR`，并显式记录验证命令。

## 6. 实用性审计（最高实用标准）

| Crate | 当前闭环程度 | 实用性结论 | 主要价值 | 主要缺口/建议 |
|---|---|---|---|---|
| `flag-detector` | 已闭环（核心） | 高 | 输入文件→提取→解码→规则→匹配→报告；并提供 `zmctf-server` 服务化入口 | 建议补“离线 CLI”入口与端到端错误路径测试，避免只能通过 server/examples 触达能力 |
| `tool-runner` | 已闭环（被依赖） | 高 | 统一外部工具执行：timeout/输出上限/截断语义/诊断字段，降低卡死与 OOM 风险 | 建议增加“可审计的命令行回显（含脱敏）”与更细的执行指标（仅调试/测试可用） |
| `zmctf-constraints` | 已闭环（被依赖） | 高 | 把资源上限、归档限制、外部工具上限集中化，形成“默认不信任输入”的底座 | 当前单测偏少；建议补序列化/默认值/边界值回归，并给出配置样例片段 |
| `floss-integration` | 未闭环（未被核心引用） | 中（潜力>现值） | 当环境具备 FLOSS 时，可对二进制做字符串提取与结构化解析 | 目前 workspace 内无调用点：建议要么在 `flag-detector` 中以 feature/配置开关接入，要么从 workspace 成员中移除以降低维护成本 |

