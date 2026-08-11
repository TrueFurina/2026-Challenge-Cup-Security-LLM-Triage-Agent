# 创新点清单（对照赛题论证）

> **用途**：答辩时逐条论证本项目创新点，对照 XH-202614 / XH-202609 赛题要求。
> **版本**：v2.0（2026-08-10，覆盖阶段 1-9 全部已实现创新点）
> **建议**：每条创新点配 1 句总结 + 证据（代码位置 / 评测数据 / 演示）。

---

## 创新点总览

| # | 创新点 | 状态 | 对应赛题 | 价值 |
|---|--------|------|---------|------|
| 1 | AI 优先研判 + 规则兜底（fail-open） | ✅ 已实现 | 202614 | 核心 |
| 2 | LLM 替代硬编码规则（决策引擎） | ✅ 已实现 | 202614/609 | 核心 |
| 3 | 防御性解析（LLM 输出可信化） | ✅ 已实现 | 202614 | 高 |
| 4 | 中文 rubric 评分（0-100） | ✅ 已实现 | 202614 | 高 |
| 5 | 五通道上下文（资产/日志/情报/历史/误报） | ✅ 已实现 | 202609 | 中 |
| 6 | 确定性预筛 + LLM 深度研判（三态分流） | ✅ 已实现（阶段1） | 202609 | 核心 |
| 7 | 置信度门控 + HITL 人工复核 | ✅ 已实现（阶段2） | 202614 | 高 |
| 8 | 多 Agent 顺序协作（Triage→Hunt→Respond→Report） | ✅ 已实现（阶段3） | 202609 | 核心 |
| 9 | RAG 知识库增强（ATT&CK/CVE grounding） | ✅ 已实现（阶段4） | 202614 | 高 |
| 10 | 多模式评测对比（规则 vs LLM vs 混合） | ✅ 已实现（阶段5） | 202614 | 核心 |
| 11 | 误报记忆与持续学习 | ✅ 已实现（阶段6） | 202609 | 高 |
| 12 | MCP 工具生态接入 | ✅ 已实现（阶段7） | 202614 | 加分 |
| 13 | Investigation Ledger 审计追踪 | ✅ 已实现（阶段8） | 202614 | 高 |
| 14 | Web 大屏化 + 对比可视化 | ✅ 已实现（阶段9） | 202609 | 加分 |

---

## 创新点详解

### 🎯 创新点 1：AI 优先研判 + 规则兜底（fail-open）

**一句话**：LLM 是决策核心，但任何失败都优雅降级到规则引擎，永不崩溃。

**证据**：
- `agent/orchestrator.py`：`ai_triage_event()` → 失败 → `analyzer_tool.run()`（规则兜底）
- `ai/triage.py`：`_heuristic_fallback()` 规则回退
- 实测：AI 超时 → 自动回退 → 全流程正常

**赛题价值**：体现工程可靠性，是"智能体研究"落地性的证明。

### 🎯 创新点 2：LLM 替代硬编码规则

**一句话**：从"数 15 个关键词"升级为"LLM 综合证据推理"。

**证据**：
- 旧版：`tools/implementations.py` 15 个 `suspicious_markers`
- 新版：`ai/triage.py` LLM 综合 5 项工具观测 + 知识库 + 计划推理

**赛题价值**：直接论证"AI+安全大模型平台的智能体研究"——LLM 是引擎不是花瓶。

### 🎯 创新点 3：防御性解析

**一句话**：LLM 输出不可信，每个字段都校验，非法值回退默认。

**证据**：`ai/triage.py` `_parse_llm_result()`：
- `risk_level` 非法 → 默认 medium
- `risk_score` 非法 → 由 risk_level 反推
- 空证据/建议 → 自动生成

**赛题价值**：解决 LLM 幻觉/格式漂移问题，是生产级设计。

### 🎯 创新点 4：中文 rubric 评分

**一句话**：用 0-100 评分标准 + few-shot 约束 LLM 输出确定性。

**证据**：`ai/triage.py` 评分标准（0-20 误报 → 81-100 严重）+ 3 个 few-shot 示例 + temperature=0.1。

**赛题价值**：把 LLM 输出从"开放文本"约束为"结构化裁决"，可评测、可对比。

### 🎯 创新点 5：五通道上下文

**一句话**：LLM 不是看单一告警，而是综合 5 类上下文做判断。

**证据**：资产画像 + 关联日志 + 威胁情报 + 历史告警 + 误报线索，全部注入 prompt。

**赛题价值**：体现"智能体能调用工具检索上下文"的核心能力。

### 🎯 创新点 6：确定性预筛 + LLM 深度研判（阶段 1）

**一句话**：规则先筛，明确误报自动关闭、明确攻击直接定级，只有不确定事件才给 LLM——快、省、准。

**证据**：
- `security_agent/prefilter/engine.py`：三态分流 AUTO_CLOSE / AUTO_ESCALATE / NEED_LLM
- `data/prefilter_rules.json`：7 攻击规则 + 4 误报规则（可配置）
- 实测：EVENT-001 攻击 0.2ms 直接定级、EVENT-002 误报 0.1ms 自动关闭，**LLM 调用节省率 70%**
- `scripts/_prefilter_test.py` 25/25 通过

**参考**：[SOC Triage Agent](https://github.com/AnshSaxena05/cyberSecurity_alert_triage)
**赛题价值**：自主初判——"明确攻击/明确误报/需深判"的自主分流，直接支撑 XH-202609 自主决策论证。

### 🎯 创新点 7：置信度门控 + HITL 人工复核（阶段 2）

**一句话**：低置信结果不直接输出为正式裁决，标记"待人工复核"，不自动处置——消除噪音、提升可信度。

**证据**：
- `ai/triage.py`：置信度数值化 high=0.9 / medium=0.7 / low=0.5
- `agent/orchestrator.py`：low 置信 → `needs_human_review=true`
- `tools/implementations.py`：低置信不生成 P 级工单（改"待复核记录"）
- `web/server.py`：Web 复核按钮 + `data/review_feedback.jsonl` 回写
- `scripts/_hittl_test.py` 23/23 通过

**参考**：[Claude-Skills-Security](https://github.com/S3DFX-CYBER/Claude-Skills-Security)
**赛题价值**：负责任的自主任——自主 ≠ 失控，人工兜底形成闭环。

### 🎯 创新点 8：多 Agent 顺序协作（阶段 3）

**一句话**：Triage → Hunt → Respond → Report 四 Agent 顺序协作，前序输出作为后序输入——真正的多 Agent 自主决策。

**证据**：
- `security_agent/agents/`：base.py（接口）/ impl.py（四 Agent）/ coordinator.py（编排）
- 每 Agent 独立可测试、可 mock、失败降级
- CLI `coordinate` 命令展示全链路
- `scripts/_agents_test.py` 22/22 通过（含失败降级用例）

**参考**：[AiSOC](https://github.com/beenuar/AiSOC)、[Vigil](https://github.com/Vigil-SOC/vigil)
**赛题价值**：自主决策分工协作，直接支撑 XH-202609"自主决策"论证。

### 🎯 创新点 9：RAG 知识库增强（阶段 4）

**一句话**：知识库 21 条（含 ATT&CK/CVE/预案），prompt 注入 grounding 依据，减少 LLM 幻觉。

**证据**：
- `data/knowledge.json`：21 条，每条含 category/tags/attck_ids/cve_ids
- `knowledge/store.py`：ATT&CK/CVE 编号强匹配加分
- `ai/triage.py`：prompt 注入"历史研判记忆"+"ATT&CK 引用引导"
- `knowledge_hits` 输出含命中依据
- `scripts/_knowledge_test.py` 16/16 通过

**参考**：[AI_SOC](https://github.com/zhadyz/AI_SOC)
**赛题价值**：用安全领域知识做 grounding，体现智能体对专业知识的利用。

### 🎯 创新点 10：多模式评测对比（阶段 5）

**一句话**：规则 vs LLM vs 混合 三模式同集评测，用数据证明架构价值。

**证据**：
- `evaluation/service.py`：`evaluate_modes()` 三模式对比
- 真实 DeepSeek 实测：混合模式通过率 0.9，纯规则低成本低准确，纯 LLM 高成本
- `report` 命令导出 HTML/Markdown（含混淆矩阵）
- 新增维度：误报关闭率 / 成本估算 / 置信度校准
- `scripts/_eval_test.py` 28/28 通过

**参考**：[CyberSOCEval](https://github.com/CrowdStrike/CyberSOCEval_data)
**赛题价值**：用数据证明"混合架构最优"——直接支撑 XH-202614 核心论证。

### 🎯 创新点 11：误报记忆与持续学习（阶段 6）

**一句话**：历史研判结果持久化并注入后续 prompt——同类误报不重复出现。

**证据**：
- `memory/store.py`：`append()`/`search()`（同主机/同进程/同行为加权）/`clear()`/上限 200
- `ai/triage.py`：`_format_history()` 注入"历史研判记忆"章节
- `cli.py`：`clear-memory` 命令
- `scripts/_memory_test.py` 15/15 通过

**参考**：[Skynet](https://github.com/LLAWLIGHT12/skynet)
**赛题价值**：持续学习闭环——系统从历史中学习，同类误报不重复。

### 🎯 创新点 12：MCP 工具生态接入（阶段 7）

**一句话**：10 个安全工具以 MCP 标准暴露，智能体可接入统一工具生态。

**证据**：
- `security_agent/mcp/server.py`：纯标准库 stdio + JSON-RPC 2.0，零依赖
- 动态注册 ToolRegistry 全部工具
- `serve-mcp` 命令 + `docs/MCP_GUIDE.md` 接入指南
- `scripts/_mcp_test.py` 15/15 通过

**参考**：[TriageMCP](https://github.com/alex-klinkovich/TriageMCP)
**赛题价值**：前沿技术加分——体现智能体的生态开放性。

### 🎯 创新点 13：Investigation Ledger 审计追踪（阶段 8）

**一句话**：全链路审计——每次研判的 prompt、LLM响应、工具调用、证据引用都可回放。

**证据**：
- `ledger/store.py`：`data/ledger/{event_id}.json` 全证据链
- `orchestrator._triage()` 全流程埋点 + `ai/client.py` `on_llm_call` 记录
- Web `/ledger` 审计回放页 + `/api/ledger` JSON 导出
- `scripts/_ledger_test.py` 18/18 通过

**参考**：[AiSOC](https://github.com/beenuar/AiSOC) 调查账本
**赛题价值**：可核查的自主任——评审可逐条验证决策依据。

### 🎯 创新点 14：Web 大屏化 + 对比可视化（阶段 9）

**一句话**：深色科技风大屏，AI 决策过程一眼看懂。

**证据**：
- 深蓝 #0a1128 + 荧光绿 #00ff9d 深色主题
- AI 决策可视化：risk_score 数值条 + 置信度徽章 + 研判路径标签
- 三模式对比柱状图（`/generate-modes` + 纯 CSS）
- 大屏指标卡 + 审计回放入口
- `scripts/_web_test.py` 11/11 通过

**参考**：[AiSOC](https://github.com/beenuar/AiSOC) 控制台
**赛题价值**：评委演示利器——决策过程透明化。

---

## 赛题对应论证

### XH-202614《AI+安全大模型平台的智能体研究》

| 赛题要求 | 本项目对应 | 证据 |
|---------|-----------|------|
| 在大模型平台上构建智能体 | DeepSeek/Qwen 统一客户端 + AI 研判引擎 | ai/client.py, ai/triage.py |
| 解决实际安全问题 | 安全事件研判 + 误报剔除 | 10 案例评测 |
| LLM 是核心能力 | 决策引擎而非事后总结 | 对比旧硬编码规则 + 三模式对比 |
| 工程可靠性 | fail-open + 防御性解析 | 实测超时回退 |
| 工具调用链 | 10 个 MCP 工具 + Ledger 审计 | mcp/, ledger/ |

### XH-202609《具备自主决策能力的通用网络安全智能体》

| 赛题要求 | 本项目对应 | 证据 |
|---------|-----------|------|
| 自主决策 | 预筛分流 + LLM 推理 + 多 Agent 协作 | prefilter/, agents/, ai/triage.py |
| 工具调用 | 10 个工具 + ToolRegistry | tools/ |
| 通用性 | 同一框架处理 10 类场景 | data/evaluation_cases.json |
| 闭环处置 | 预案 + 工单 + 隔离建议 + HITL 复核 | playbook/ticket/isolation + review |
| 持续学习 | 误报记忆注入 | memory/ |
| 可靠性 | fail-open + 规则兜底 | 全流程不崩溃 |
