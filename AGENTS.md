# Repository Guidelines

## 项目结构与模块组织
- `core/`：Rust workspace 根目录（本仓库聚焦后端逻辑）。
- `core/flag-detector/`：核心分析与检测逻辑（字符串提取、解码链、规则、归档分析、缓存；包含 `zmctf-server` 二进制入口）。
- `core/floss-integration/`：对外部 `floss` 工具的集成封装（runner + 类型定义）。
- `core/tool-runner/`：统一外部命令执行器（timeout/输出截断/环境变量）；禁止直接使用 `std::process::Command`。
- `core/target/`：本地构建产物（不要提交）。

## 构建、测试与本地开发命令（在 `core/` 下执行）
- `cargo check --workspace --all-targets --all-features --locked --offline`：离线 + 锁定依赖的全量编译检查。
- `cargo test -p flag-detector --all-features --locked --offline`：运行核心单测与 doc tests。
- `cargo test -p tool-runner --locked --offline`：运行外部命令执行器单测。
- `cargo fmt --all -- --check`：格式校验（提交前必跑）。
- `cargo clippy --all-targets --all-features -- -D warnings`：静态检查（0 warnings 门槛）。
- 启动 API：`cargo run -p flag-detector --bin zmctf-server`（默认 `0.0.0.0:8080`），日志示例：`$env:RUST_LOG="info"`.

## 编码风格与命名约定
- 遵循 `rustfmt` 默认风格；避免无关重构，优先小步、可回滚改动。
- 命名：模块/文件 `snake_case`；类型/trait `PascalCase`；常量 `SCREAMING_SNAKE_CASE`。
- 错误处理：对外边界优先使用 `anyhow`，并用 `with_context` 补充可诊断信息。
- 生产代码避免 `unwrap/expect`（clippy gate）。

## 测试指南
- 单测就近放置在模块内 `#[cfg(test)]`；测试名使用行为描述（例如 `test_extract_to_dir_rejects_path_traversal`）。
- 修复缺陷优先补回归测试；新增能力需最小覆盖测试与可复现实例。

## 提交与 PR 指南
- 提交信息参考历史：常见格式为 `[Claude Code] ... prompt #N`；建议使用“动词 + 范围 + 原因”（如 `fix(cache): stream sha256 hashing`）。
- PR 需包含：变更动机、影响范围、验证命令/输出、风险点与回滚方式；避免引入前端资源或静态站点文件。

## 安全与配置提示
- 外部工具（`tshark`/`hashcat`/`unrar`/`floss`）可能缺失：核心逻辑应可在缺失时继续运行。
- 处理归档/路径输入默认不信任来源，注意路径穿越与覆盖写入；新增/修改外部命令调用必须走 `tool-runner` 并显式设置超时与输出上限。
- 配置由 `AppConfig` 读取 `config.toml`（默认路径见 `AppConfig::default_config_path()`，实现位于 `core/flag-detector/src/config.rs`）。

