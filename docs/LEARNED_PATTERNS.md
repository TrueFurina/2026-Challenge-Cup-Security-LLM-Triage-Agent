# 偷师模式库（Leaned Patterns）

> **用途**：记录从全网 / 本地项目学到的可复用设计模式，以及应用状态。
> **来源**：GitHub 顶级项目 + DBAPPSecurity 生产级项目 + 本地 hello-agents 等。

---

## 已应用的模式（✅）

### 模式 1：Fail-open 容错

**来源**：DBAPPSecurity `ai/client.py`

**内容**：任何 LLM 错误返回 `None`，绝不抛异常，由调用方回退。

**应用**：`ai/client.py` 全部 API 失败返回 None；`ai/triage.py` 失败回退规则引擎。

**已应用到**：✅

### 模式 2：防御性解析

**来源**：DBAPPSecurity `ai/risk_scorer.py`

**内容**：LLM 输出每个字段校验类型，非法值回退默认，从不信任模型格式。

**应用**：`ai/triage.py` `_parse_llm_result()`。

**已应用到**：✅

### 模式 3：中文 rubric 评分

**来源**：DBAPPSecurity `ai/risk_scorer.py`

**内容**：0-100 评分标准嵌入 prompt，LLM 按 rubric 输出分数。

**应用**：`ai/triage.py` 评分标准（0-20 误报 → 81-100 严重）。

**已应用到**：✅

### 模式 4：LLM 作为决策核心（非总结）

**来源**：DBAPPSecurity（域名推断/风险评分都用 LLM）；业界共识

**内容**：LLM 做核心推理，而非事后总结润色。

**应用**：`ai/triage.py` 替代硬编码 `suspicious_markers`。

**已应用到**：✅

### 模式 5：JSON fence-stripping

**来源**：DBAPPSecurity `ai/client.py`

**内容**：剥离 ```json 围栏 + 截取首尾花括号。

**应用**：`ai/client.py` `_extract_json_object()`。

**已应用到**：✅

### 模式 6：密钥多级查找

**来源**：DBAPPSecurity（env → 注册表回退）

**内容**：环境变量 → config.json → 注册表。

**应用**：`ai/client.py` 密钥解析。

**已应用到**：✅

---

## 待应用模式（📋 todo.md）

### 模式 7：确定性预筛 + LLM 深度研判

**来源**：[SOC Triage Agent](https://github.com/AnshSaxena05/cyberSecurity_alert_triage)

**内容**：规则引擎先筛（毫秒级），FP>80% 自动关闭，不确定才给 LLM。

**应用**：todo.md 阶段 1。

### 模式 8：置信度门控

**来源**：[Claude-Skills-Security](https://github.com/S3DFX-CYBER/Claude-Skills-Security)

**内容**：低置信度结果仅记录不输出，消除噪音。

**应用**：todo.md 阶段 2。

### 模式 9：误报记忆注入

**来源**：[Skynet](https://github.com/LLAWLIGHT12/skynet)

**内容**：历史研判结果注入后续 prompt，同类误报不重复。

**应用**：todo.md 阶段 6。

### 模式 10：多 Agent 顺序协作

**来源**：[AiSOC](https://github.com/beenuar/AiSOC)、[Vigil](https://github.com/Vigil-SOC/vigil)、[Microsoft Triangle](https://github.com/microsoft/Triangle)

**内容**：Triage → Hunt → Respond → Report，前序输出作为后序输入。

**应用**：todo.md 阶段 3。

### 模式 11：Investigation Ledger

**来源**：[AiSOC](https://github.com/beenuar/AiSOC)

**内容**：全链路审计（prompt/响应/工具/证据），可回放。

**应用**：todo.md 阶段 8。

### 模式 12：对抗验证（Critic Agent）

**来源**：[Agentic SOC Investigator](https://github.com/jwtsf/agentic-soc-investigator)

**内容**：Agent A 研判 → Agent B 反驳 → 置信度评分。

**应用**：todo.md 阶段 3.4。

### 模式 13：工具调用触发 prompt 切换

**来源**：本地 LangChain-ReAct-Agent（middleware）

**内容**：零参数哨兵工具调用翻转运行时上下文 → 动态切换 persona。

**应用**：多 Agent 场景时可借鉴。

### 模式 14：DB 状态注入 prompt

**来源**：本地 physics-scheduler-agent

**内容**：每次请求把当前 DB 统计注入 user prompt（grounding）。

**应用**：可注入"当前活跃告警数"等状态。

### 模式 15：小模型微调（备选）

**来源**：[pq-sift-defender](https://huggingface.co/CycleCoreTechnologies/pq-sift-defender-Q4_K_M)（Qwen2.5-1.5B 微调 → 96.3%）

**内容**：用 10 案例做种子，QLoRA 微调本地小模型，离线可跑。

**应用**：备选方案，无需 API Key。

---

## 参考项目清单

| 项目 | Stars | 偷了什么 | 状态 |
|------|-------|---------|------|
| [AiSOC](https://github.com/beenuar/AiSOC) | 1712 | 多Agent + 调查账本 | 待应用 |
| [SOC Triage Agent](https://github.com/AnshSaxena05/cyberSecurity_alert_triage) | — | 确定性预筛 | 待应用 |
| [Claude-Skills-Security](https://github.com/S3DFX-CYBER/Claude-Skills-Security) | — | 置信度门控 | 待应用 |
| [Skynet](https://github.com/LLAWLIGHT12/skynet) | — | 误报记忆 | 待应用 |
| [TriageMCP](https://github.com/alex-klinkovich/TriageMCP) | — | MCP + 结构化裁决 | 待应用 |
| [Vigil](https://github.com/Vigil-SOC/vigil) | — | 多Agent + MCP | 待应用 |
| [Microsoft Triangle](https://github.com/microsoft/Triangle) | — | 3 Agent 路由 | 参考 |
| DBAPPSecurity Passive Agent | 生产级 | fail-open/rubric/密钥 | ✅ 已用 |
| hello-agents (本地) | — | 工具文档化/流水线 | 部分应用 |
| LangChain-ReAct (本地) | — | prompt 切换/middleware | 参考 |
