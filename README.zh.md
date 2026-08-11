# Security Agent —— AI 安全事件研判与误报剔除智能体

> **English version**: [README.md](README.md)

以 **LLM 为决策核心**的安全事件研判与误报剔除智能体，2026 挑战杯参赛作品（赛题 XH-202614 / XH-202609）。融合确定性预筛、置信度门控 + 人工复核（HITL）、多 Agent 协作、RAG 知识接地、误报记忆与全链路审计账本。

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?logo=python&logoColor=white)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 🎯 核心亮点

- **LLM 决策引擎**：模型是核心裁判（非装饰品）——三模式对比（纯规则 vs 纯 LLM vs 预筛+LLM 混合）证明混合架构在真实 DeepSeek 上通过率达 **90%** 且成本最低
- **确定性预筛器**：三态分流（AUTO_CLOSE / AUTO_ESCALATE / NEED_LLM），规则可配置，**节省 70% LLM 调用**
- **置信度门控 + HITL**：低置信结果不自动处置，人工复核回写闭环
- **多 Agent 协作**：Triage → Hunt → Respond → Report，每个 Agent 独立可测、失败降级
- **RAG 知识接地**：21 条知识含 MITRE ATT&CK / CVE 映射，注入 prompt 降低幻觉
- **误报记忆**：相似历史裁决注入 prompt，同类误报不重复出现
- **Investigation Ledger**：每次研判完整证据链（工具调用 / LLM prompt 与响应 / 最终裁决）可在 Web 回放
- **MCP 集成**：10 个安全工具通过零依赖 stdio 服务器暴露为 MCP

## 🚀 快速开始

```bash
cd "E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体"

# 1. 环境验证（无需 API Key，自动回退规则引擎）
python scripts/_verify_syntax.py     # 语法 43/43
python scripts/_prefilter_test.py    # 预筛测试 25/25

# 2. 全量评测（配置 DEEPSEEK_API_KEY 时走真实 DeepSeek）
python -m security_agent.cli evaluate

# 3. 启动深色科技风 Web 大屏
python -m security_agent.cli serve --port 8080
# 打开 http://127.0.0.1:8080
```

> **零依赖模式**：无 API Key 时自动回退确定性规则引擎（fail-open），一切功能可用，仅无 LLM 推理。

## 🧠 架构

```
事件输入
   │
   ▼
① 确定性预筛（毫秒级）
   ├─ AUTO_CLOSE      → 误报自动关闭（不调 LLM）
   ├─ AUTO_ESCALATE   → 攻击直接定级（不调 LLM）
   └─ NEED_LLM        → LLM 深度研判
   │
   ▼
② LLM 研判（DeepSeek/Qwen）+ 置信度门控 + 误报记忆 + RAG 接地
   │
   ▼
③ 多 Agent 协作：Triage → Hunt → Respond → Report
   │
   ▼
④ 闭环与审计：Investigation Ledger + 误报记忆持久化 + MCP 暴露
```

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 🧪 评测

- **10 个标准案例**，真实 DeepSeek：通过率 **0.9**（风险 0.9 / 误报 1.0 / 类型 1.0 / 完整率 1.0）
- 三模式对比：`python -m security_agent.cli report --format md`（含混淆矩阵）
- 10 个测试脚本 **208/208 通过**（预筛/门控/Agent/知识/评测/记忆/MCP/Ledger/Web）

## 📁 仓库结构

```
security_agent/
├── ai/            # LLM 客户端（fail-open）+ 研判引擎 + 富化
├── prefilter/     # 确定性三态预筛 + 规则
├── agents/        # Triage/Hunt/Respond/Report + 编排器
├── memory/        # 误报记忆（写入/检索/清理）
├── ledger/        # 调查审计账本
├── mcp/           # MCP 服务器（stdio，零依赖）
├── evaluation/    # 评测服务（三模式对比）
├── web/           # 深色大屏 + 审计回放
└── data/          # 告警/资产/情报/知识/规则
docs/              # 15+ 篇技术文档（架构/AI 模块/评测...）
scripts/           # 测试与验证脚本
```

## 🔗 赛题覆盖

- **XH-202614** — AI+安全大模型平台的智能体研究（LLM 为核心决策引擎）
- **XH-202609** — 具备自主决策能力的通用网络安全智能体（预筛+多 Agent+HITL 闭环）

## 🤝 开源协议

[MIT](LICENSE) © 闽江学院团队
