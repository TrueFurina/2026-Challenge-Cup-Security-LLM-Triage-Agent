# 🏛️ 双赛题论证材料（ARGUMENT）

> **用途**：挑战杯答辩核心论证材料——逐条引用实际代码路径与评测数据，支撑两道赛题。
> **配合**：`docs/INNOVATION.md`（创新点）、`docs/BENCHMARK.md`（业界基准）、`docs/EVALUATION.md`（评测）

---

## 赛题 XH-202614：AI+安全大模型平台的智能体研究

> **论证主线**：**LLM 是核心决策引擎**（不是装饰品）——对比评测证明其决策价值，工具调用链展示其 Agent 属性。

### 论证点 1：LLM 承担核心研判决策

| 证据 | 代码/数据位置 |
|------|--------------|
| 研判入口由 LLM 推理产出（事件类型/风险/置信度/误报） | `security_agent/ai/triage.py` `triage_event()` |
| 系统 prompt 将模型定位为"15 年资深 SOC 专家" | `TRIAGE_SYSTEM_PROMPT` |
| 综合 5 项工具观测 + 知识库 + 计划做决策 | `_build_user_prompt()` |
| 输出结构化 JSON 契约（10 字段） | `JSON_CONTRACT` |

**论证**：升级前风险判定是"数标记"（硬编码 suspicious_markers 计数），LLM 只是总结装饰品；升级后 LLM 综合全部证据推理出裁决，规则引擎仅兜底。LLM 从"花瓶"变成"决策引擎"。

### 论证点 2：三模式对比证明 LLM 决策有效性

| 模式 | 通过率 | 成本 | LLM 调用 |
|------|--------|------|---------|
| 纯规则 | 低（~0.1 mock 实测） | 0 | 0 |
| 纯 LLM | 中（依赖模型） | 高 | 10/10 |
| 预筛+LLM 混合 | **0.9（真实 DeepSeek 实测）** | 低 | 3/10 |

**命令**：`python -m security_agent.cli evaluate`、`python -m security_agent.cli report --format md`
**论证**：混合模式通过率最高、成本最低——LLM 的决策能力在关键案例上被调用并产生正确结果，同时被预筛器精准分流（只处理灰色地带）。

### 论证点 3：工具调用链体现 Agent 属性

| 证据 | 位置 |
|------|------|
| 5 个上下文工具观测（资产/日志/情报/历史/误报）作为 LLM 输入 | `orchestrator._triage()` |
| LLM 可调用 10 个 MCP 工具（ioc_search/playbook/ticket 等） | `security_agent/mcp/server.py` |
| 工具调用链全链路审计（Ledger） | `security_agent/ledger/store.py` |

**论证**：智能体 ≠ 简单 API 调用——Agent 通过工具调用链获取上下文证据、执行处置动作，且全过程可审计。

---

## 赛题 XH-202609：具备自主决策能力的通用网络安全智能体

> **论证主线**：**自主决策闭环**——规则预筛、多 Agent 协作、置信门控、HITL、误报记忆、审计账本构成完整闭环。

### 论证点 1：确定性预筛 = 自主初判

| 证据 | 位置 |
|------|------|
| 三态分流：AUTO_CLOSE（误报自动关）/ AUTO_ESCALATE（直接定级）/ NEED_LLM（深判） | `security_agent/prefilter/engine.py` |
| 7 条攻击规则 + 4 条误报规则（可配置） | `data/prefilter_rules.json` |
| 实测：EVENT-001 攻击 0.2ms 直接定级、EVENT-002 误报 0.1ms 自动关闭 | `scripts/_prefilter_test.py` |
| LLM 调用节省率 70% | 评测输出 `prefilter.llm_call_savings_rate` |

**论证**：系统能自主判断"明确攻击/明确误报/需深判"，不是每事件盲目调 LLM——这是自主决策的第一步。

### 论证点 2：多 Agent 顺序协作

| 证据 | 位置 |
|------|------|
| Triage → Hunt → Respond → Report 四 Agent 顺序协作，前序输出作为后序输入 | `security_agent/agents/`（base/impl/coordinator） |
| 每 Agent 独立可测试、可 mock、失败降级 | `scripts/_agents_test.py` 22/22 |
| CLI `coordinate` 命令展示全链路 | `python -m security_agent.cli coordinate --event-id EVENT-001` |

**论证**：自主决策不是单点调用，而是多角色分工协作——初判、狩猎、处置、报告各司其职，任一步失败不中断整体链路。

### 论证点 3：置信门控 + HITL = 负责任的自主任

| 证据 | 位置 |
|------|------|
| 置信度数值化（high 0.9/medium 0.7/low 0.5） | `ai/triage.py` `CONFIDENCE_SCORES` |
| 低置信 → `needs_human_review=true`，不自动处置 | `orchestrator._triage()` |
| 低置信不生成 P 级工单（改"待复核记录"） | `tools/implementations.py` `TicketGeneratorTool` |
| Web 复核按钮 + 回写 `review_feedback.jsonl` | `web/server.py` `_handle_review` |

**论证**：自主 ≠ 失控——低置信结果不自动处置，人工复核回写形成闭环。这是"自主决策能力"的安全边界设计，也是负责任的智能体应有的行为。

### 论证点 4：误报记忆 = 持续学习

| 证据 | 位置 |
|------|------|
| 每次研判写入 `data/triage_history.jsonl` | `memory/store.py` `append()` |
| 研判前检索相似历史（同主机/同进程/同行为） | `memory/store.py` `search()` |
| 相似历史注入 prompt："该主机同类事件判定为误报" | `ai/triage.py` `_format_history()` |
| 记忆上限 200 条 + `clear-memory` 命令 | `memory/store.py` + `cli.py` |

**论证**：同类误报不重复出现——系统从历史研判中学习，是"持续学习"的闭环能力。

### 论证点 5：审计账本 = 可核查的自主任

| 证据 | 位置 |
|------|------|
| `data/ledger/{event_id}.json` 全证据链 | `ledger/store.py` |
| orchestrator 全流程埋点 + LLM prompt/response 记录 | `orchestrator._triage()` + `ai/client.py` `on_llm_call` |
| Web `/ledger` 审计回放页 + `/api/ledger` JSON 导出 | `web/server.py` |

**论证**：自主决策过程可回放、可审计、可导出——评审可逐条核查决策依据，这是"可信赖智能体"的关键。

---

## 双赛题交叉论证总结

| 能力 | XH-202614 论证 | XH-202609 论证 |
|------|---------------|---------------|
| LLM 决策引擎 | ⭐ 三模式对比 + JSON 契约 | — |
| 确定性预筛 | — | ⭐ 自主初判 + 节省 70% |
| 多 Agent 协作 | 工具调用链 | ⭐ 自主决策分工 |
| 置信门控 + HITL | — | ⭐ 负责任的自主任 |
| 误报记忆 | — | ⭐ 持续学习 |
| 审计账本 | ⭐ 可审计的 Agent | ⭐ 可核查的决策 |

**答辩话术**：本项目以 LLM 为核心决策引擎（XH-202614 论证主线），同时构建了预筛、多 Agent、HITL、记忆、审计构成的完整自主决策闭环（XH-202609 论证主线）——一套系统，双赛题覆盖。
