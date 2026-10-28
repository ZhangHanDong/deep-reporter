# deep-reporter

Rust 与 AI 编码方向的深度调研报告集。每份报告提供 Markdown 源文件和对应的 Word（docx）版本。

## 报告索引

| 报告 | 简介 | Markdown | Word |
|---|---|---|---|
| Rust 安全抽象与 unsafe Rust 生态全景调研：机制、工具链、最新进展与最佳实践 | unsafe Rust 的语义机制、验证工具链、政策与产业采纳（已并入 2026-08 至 10 月的增量更新，数据至 2026-10-27） | [rust_unsafe_report.agent.final.md](rust_unsafe_report.agent.final.md) | [docx](rust_unsafe_report.docx) |
| 大模型编码的缺陷与特点：业界已验证发现综述（2022–2026） | LLM 生成代码的缺陷类型、基准污染、幻觉依赖与验证瓶颈 | [llm_code_defects.agent.final.md](llm_code_defects.agent.final.md) | [docx](大模型编码缺陷与特点调研报告.docx) |
| Polonius 前世今生：Rust 下一代借用检查器的八年长路 | 从 NLL 到 Polonius Alpha（2026-08-04 在 nightly 默认启用）的演进与现状 | [polonius.agent.final.md](polonius.agent.final.md) | [docx](polonius.docx) |
| 从推理基础设施到可验证软件工厂：RustChinaConf 2026 议题总结 | RustChinaConf 2026 大会议题总结 | [RustChinaConf2026大会议题总结.md](RustChinaConf2026大会议题总结.md) | — |

## 其他文件

- `llm_code_defects_sec*.png`：LLM 缺陷综述中引用的配图。
- `polonius_mermaid_ch3.png`：Polonius 报告第 3 章流程图（Markdown 中为 mermaid 代码块，docx 中使用此图片）。

## 说明

- 报告中的 `[^n^]` 为脚注式引用，编号对应各文档末尾的参考文献列表。
- 部分来源（NSA/CISA 指南 PDF、OpenAI 对 SWE-bench Verified 的审计原文等）未能直接读取原文，相关数字在正文中已标注核实状态。
