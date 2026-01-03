# ZMctf Core

本目录为 ZMctf 后端 Rust workspace 根目录，目标是提供可复用、可审计、可离线构建的核心分析能力。

## Crates

- `flag-detector`：核心分析与检测逻辑（提取、解码、规则、归档分析、服务端入口等）。
- `tool-runner`：统一外部命令执行器（timeout/输出截断/环境变量），禁止直接使用 `std::process::Command`。
- `floss-integration`：对外部 `floss` 工具的集成封装（runner + 类型定义）。
- `zmctf-constraints`：全局资源与安全约束模型（文件大小、解压预算、外部命令限制与截断语义）。
