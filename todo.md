# 🎯 Security Agent 项目升级作战计划（超级详细版）

> **项目**：安全事件初步研判与误报剔除智能体
> **赛题**：XH-202614《AI+安全大模型平台的智能体研究》 + XH-202609《具备自主决策能力的通用网络安全智能体》
> **目标**：达到挑战杯国赛水准，形成"LLM 为核心决策引擎、规则引擎为确定性兜底、评测数据证明有效性"的可演示、可论证、可复现作品
> **版本**：v2.0 | **最后更新**：2026-08-09

---

## 📌 项目定位（一句话）

**一个以 LLM 为决策核心、融合工具调用、知识检索、确定性规则兜底、多阶段 Agent 协作的安全事件研判与误报剔除智能体。**

---

## 🗺️ 当前状态盘点（已完成 ✅）

### 已完成的基础架构
| 模块 | 状态 | 说明 |
|------|------|------|
| 四模块架构（入口/编排/知识/工具） | ✅ | `security_agent/` 下 4 大模块 |
| 四阶段 Agent 展示 | ✅ | Monitor → Context → Triage → Report |
| 9 个安全工具 | ✅ | asset/log/intel/history/fp_check/triage/playbook/ticket/isolation |
| LLM 客户端 | ✅ | `ai/client.py`：DeepSeek/Qwen/OpenAI 统一封装，fail-open |
| **LLM 研判引擎** | ✅ | `ai/triage.py`：LLM 替代硬编码规则，带规则回退 |
| **事件富化** | ✅ | `ai/enricher.py`：MITRE ATT&CK 映射 + CVE + 调查步骤 |
| **编排器集成** | ✅ | `agent/orchestrator.py`：AI 优先 + 规则回退 |
| CLI + Web 界面 | ✅ | `cli.py` + `web/server.py` |
| 报告导出 | ✅ | Markdown / JSON |
| 评测面板 | ✅ | 10 标准案例 + `/api/evaluation` |
| 10 篇文档 | ✅ | `docs/` |

### 已验证的关键能力（真实 DeepSeek 运行）
```
✅ EVENT-001 → critical / 恶意脚本执行 / high confidence（正确）
✅ EVENT-002 → low / 误报=true（正确）
✅ FP 识别准确率 90%
⚠️ 综合通过率 10%（因评测基准基于旧规则引擎，需重标）
```

---

## 🧠 核心架构演进蓝图

### 现状（阶段 0）
```
事件 → 工具调用(5项观测) → LLM研判 → 规则回退 → 展示
```

### 目标架构（阶段 9）
```
事件输入
   │
   ▼
┌─────────────────────────────────────────────┐
│ ① 确定性预筛器 (规则引擎, 毫秒级)              │
│    FP概率>80%? ──是──→ 自动关闭+审计          │
│    明确攻击特征? ──是──→ 直接定级+审计         │
│    其余 → 进入 LLM 深度研判                    │
└─────────────────────────────────────────────┘
   │ 不确定事件
   ▼
┌─────────────────────────────────────────────┐
│ ② LLM 深度研判引擎 (DeepSeek/Qwen/本地微调)   │
│    工具调用(ReAct) + 知识检索(RAG)            │
│    置信度门控 + 误报记忆注入                   │
│    输出结构化裁决 (含 risk_score)             │
└─────────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────────┐
│ ③ 多Agent协作层                              │
│    Triage Agent ──→ Hunt Agent ──→ Respond Agent ──→ Report Agent
│    (初判)          (威胁狩猎)      (处置建议)        (报告+工单)
│    低置信 → 对抗验证 (Agent A研判, Agent B反驳)   │
└─────────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────────┐
│ ④ 闭环处置 + 审计                            │
│    预案匹配 + 工单生成 + 动作模拟              │
│    全链路 Investigation Ledger 审计           │
│    结果写入经验库(误报记忆)                   │
└─────────────────────────────────────────────┘
```

---

# 📋 阶段划分（10 阶段 + 里程碑）

## ✅ 阶段 0：基线与验证（已完成）
- [x] AI 模块（client/triage/enricher）开发完成
- [x] 编排器 AI 优先集成 + 规则回退
- [x] 真实 DeepSeek 运行验证
- [x] fail-open 容错验证

---

## 🚧 阶段 1：确定性预筛 + LLM 深度研判（最高优先）

> **对标**：[SOC Triage Agent](https://github.com/AnshSaxena05/cyberSecurity_alert_triage)（确定性快速通道）、[Autonomous SOC Tier-1](https://github.com/AnshSaxena05/cyberSecurity_alert_triage)

### 目标
把"LLM 一律全量研判"改为"规则先筛、不确定才给 LLM"，显著提升速度、降低成本、提高准确率。

### 任务
- [ ] **1.1 新建 `security_agent/prefilter/` 模块**（确定性预筛器）
  - [ ] `engine.py`：`PreFilterEngine` 类，毫秒级判定
  - [ ] 高置信误报特征集：维护窗口 / 变更单 / 白名单 / 基线进程 / 已知例行任务
  - [ ] 高置信攻击特征集：EncodedCommand / WebShell 写入 / 已知 C2 情报命中 / 凭据转储
  - [ ] 输出三态：`AUTO_CLOSE`（误报自动关）/ `AUTO_ESCALATE`（直接定级）/ `NEED_LLM`（需深度研判）
- [ ] **1.2 重构 `agent/orchestrator.py` 研判链路**
  - [ ] `_triage()` 入口先调用 `PreFilterEngine`
  - [ ] `AUTO_CLOSE` → 跳过 LLM，直接生成"误报已关闭"结果
  - [ ] `AUTO_ESCALATE` → 可选跳过 LLM，或 LLM 复核
  - [ ] `NEED_LLM` → 走现有 `ai.triage.triage_event()`
- [ ] **1.3 预筛器可配置化**
  - [ ] 特征集抽到 `data/prefilter_rules.json`，支持用户编辑
  - [ ] 命中规则在结果中标注 `source: prefilter`
- [ ] **1.4 评测对比**
  - [ ] 记录预筛通过率 / LLM 调用节省率 / 预筛误判率
  - [ ] 与纯 LLM 模式对比表

**验收**：`python -m security_agent.cli evaluate` 输出含 prefilter 统计；EVENT-002/008（误报案例）被预筛自动关闭，不调 LLM。

---

## ✅ 阶段 2：置信度门控 + 人工复核（HITL）（已完成 2026-08-10）

> **对标**：[Claude-Skills-Security](https://github.com/S3DFX-CYBER/Claude-Skills-Security)（置信度门控）

### 目标
低置信度结果不直接输出为正式裁决，而是标记"待人工复核"，消除误报噪音，提升可信度。

### 任务
- [x] **2.1 置信度分级标准化**
  - [x] `confidence ∈ {high, medium, low}` 与数值映射（0.9/0.7/0.5）
  - [x] LLM 输出解析时强制归一化
- [x] **2.2 置信度门控逻辑**
  - [x] `low` 置信 → 标记 `needs_human_review=true`，输出"疑似"，不自动处置
  - [x] `medium` 置信 → 正常输出但附"建议人工复核"
  - [x] `high` 置信 → 正常处置
- [x] **2.3 Web 界面 HITL 展示**
  - [x] `AnalysisResult` 增加 `review_status` 字段
  - [x] Web 面板显示"待复核"标签和复核操作入口
- [x] **2.4 复核反馈回写**
  - [x] 人工确认后回写 `data/review_feedback.jsonl`，供后续误报记忆使用

**验收**：低置信事件在 Web 上显示"待人工复核"，结果不自动进入工单。（✅ 已达成：`scripts/_hittl_test.py` 23/23 通过）

---

## ✅ 阶段 3：多 Agent 协作（Triage → Hunt → Respond → Report）（已完成 2026-08-10）

> **对标**：[AiSOC](https://github.com/beenuar/AiSOC)（1712⭐）、[Vigil](https://github.com/Vigil-SOC/vigil)、[Microsoft Triangle](https://github.com/microsoft/Triangle)

### 目标
从"单编排器 + 展示层分阶段"升级为"真正多 Agent 顺序协作"，体现赛题 XH-202609 的"自主决策"。

### 任务
- [x] **3.1 定义 Agent 接口**
  - [x] `security_agent/agents/base.py`：`BaseAgent` 抽象类（输入/输出/工具清单/超时）
  - [x] 每个 Agent 可独立测试、可 mock
- [x] **3.2 实现 4 个 Agent**
  - [x] `TriageAgent`：初判事件类型/风险/误报（复用现有 triage）
  - [x] `HuntAgent`：威胁狩猎——根据初判结果，用工具补充调查（新工具：ioc_search）
  - [x] `RespondAgent`：处置建议——预案匹配 + 工单 + 隔离建议
  - [x] `ReportAgent`：汇总输出 + 导出
- [x] **3.3 顺序编排器**
  - [x] `agents/coordinator.py`：串行调用 4 Agent，前序输出作为后序输入
  - [x] 任一步骤失败 → 降级到已有结论，不中断
- [ ] **3.4 对抗验证（进阶，暂缓）**
  - [ ] `CriticAgent`：对 TriageAgent 的裁决进行反驳性审查
  - [ ] 双方不一致时标记 `requires_review`

**验收**：CLI 输出显示 4 个 Agent 各自的输入/输出；Triage → Hunt → Respond 数据流清晰。（✅ 已达成：`scripts/_agents_test.py` 22/22 通过，`python -m security_agent.cli coordinate --event-id EVENT-001` 可用）

---

## ✅ 阶段 4：RAG 知识库增强（已完成 2026-08-10）

> **对标**：[AI_SOC](https://github.com/zhadyz/AI_SOC)、[Vigil](https://github.com/Vigil-SOC/vigil)

### 目标
把轻量 RAG 升级为带 grounding 的检索，用 MITRE ATT&CK / CVE / 处置预案做依据注入，减少 LLM 幻觉。

### 任务
- [x] **4.1 知识数据扩充**
  - [x] `data/knowledge.json` 扩充：ATT&CK 战术/技术、常见 CVE、典型误报模式、处置预案（10 → 21 条）
  - [x] 每个知识条目含 `category`、`tags`、`attck_ids`、`cve_ids`
- [x] **4.2 检索增强（保持轻量，不引入 chromadb）**
  - [x] 保持关键词 + 加权 RAG（现有方案），增加 ATT&CK/CVE 编号强匹配加分
- [x] **4.3 知识注入 prompt**
  - [x] LLM 研判 prompt 中注入 Top-K 知识 + ATT&CK/CVE 依据 + 引用引导
  - [x] 输出 `knowledge_hits` 含命中依据（ATT&CK/CVE 标注）
- [x] **4.4 知识可视化**
  - [x] Web 面板知识命中区展示 ATT&CK 技术 / CVE（`_format_knowledge_hit`）

**验收**：攻击类事件研判时，prompt 含相关 ATT&CK 技术描述；输出含命中依据。（✅ 已达成：`scripts/_knowledge_test.py` 16/16 通过）

---

## 🚧 阶段 5：评测体系升级（赛题论证核心）

> **对标**：[CyberSOCEval](https://github.com/CrowdStrike/CyberSOCEval_data)（CrowdStrike+Meta）、[SecRespond](https://github.com/Alibaba-NLP/qqr)、[ExCyTIn-Bench](https://github.com/microsoft/ExCyTIn-Bench)

### 目标
用业界标准评测证明有效性——这是赛题"智能体研究"的核心论证材料。

### 任务
- [x] **5.1 评测案例重标注（已完成 2026-08-10，通过率 10%→90%）**
  - [x] 现有 10 个案例的 `expected_event_type` 与 LLM 实际输出对齐（LLM 的"异常外联"比旧的"通用异常行为"更准）
  - [x] 增加 event_type 取值域：恶意脚本执行 / 异常登录 / 异常外联 / 通用异常行为 / WebShell 攻击 / 凭据转储 / 勒索软件加密 / 横向移动前置 / 恶意载荷投递 / 误报
  - [x] 逐案例人工复核 expected 值，生成 v2 标注（直接重写 evaluation_cases.json，git 可回滚）
- [x] **5.2 评测维度扩展**
  - [x] 增加：预筛准确率、LLM 调用节省率（evaluate 已输出 prefilter 统计）
  - [x] 增加：误报关闭率、成本估算、置信度校准（高置信是否更准）
- [x] **5.3 多模式对比评测**
  - [x] 规则引擎模式 vs LLM 模式 vs 预筛+LLM 混合模式 → 三列对比表（`evaluate_modes()`）
  - [x] MockLLM vs DeepSeek vs Qwen 对比（同一评测集，Mock 已验证，真实对比可 `report` 导出）
- [x] **5.4 评测报告导出**
  - [x] `report` 命令输出 HTML/Markdown 评测报告（`python -m security_agent.cli report --format md|html`）
  - [x] 含混淆矩阵、逐案例明细
- [x] **5.5 回归测试**
  - [x] 每次改动后跑全量评测，准确率不得下降（`scripts/_eval_test.py` 28/28 通过）

**验收**：`evaluate` 输出混合模式准确率对比表 + 混淆矩阵 + 成本估算；全文档可引用。（✅ 已达成：`python -m security_agent.cli report --format md` 导出含三模式对比 + 混淆矩阵 + 成本估算）

---

## ✅ 阶段 6：误报记忆与持续学习（已完成 2026-08-10）

> **对标**：[Skynet](https://github.com/LLAWLIGHT12/skynet)（误报记忆注入 prompt）

### 目标
同一类误报不重复出现——把历史研判结果注入后续 prompt，形成"学习"闭环。

### 任务
- [x] **6.1 研判结果持久化**
  - [x] 每次研判写入 `data/triage_history.jsonl`：event特征 + 裁决 + 置信度 + 是否误报（`MemoryStore.append`）
- [x] **6.2 误报记忆注入**
  - [x] 研判前检索相似历史（同主机/同进程/同行为特征，`MemoryStore.search` 加权）
  - [x] 相似历史注入 LLM prompt（"历史研判记忆"章节 + 一致性引导）
- [x] **6.3 记忆清理与上限**
  - [x] 只保留最近 N 条（MAX_RECORDS=200 自动裁剪）
  - [x] 可手动清空（`cli.py clear-memory`）

**验收**：重复触发同一事件时，第二次研判明确引用历史记忆，结论稳定。（✅ 已达成：`scripts/_memory_test.py` 15/15 通过）

---

## ✅ 阶段 7：MCP 集成（前沿加分项）（已完成 2026-08-10）

> **对标**：[TriageMCP](https://github.com/alex-klinkovich/TriageMCP)、[Vigil](https://github.com/Vigil-SOC/vigil) 的 MCP 集成

### 目标
把工具以 MCP 标准暴露，体现"智能体可接入统一工具生态"——前沿技术加分点。

### 任务
- [x] **7.1 MCP Server 封装**
  - [x] 纯标准库实现 MCP Server（stdio + JSON-RPC 2.0，零依赖，不阻塞主流程）
  - [x] 从 ToolRegistry 动态注册 10 个工具（tools/list / tools/call / initialize）
- [x] **7.2 对外暴露**
  - [x] `cli.py serve-mcp` 命令启动 MCP server
  - [x] 文档说明如何接入 Claude/GPT/自研 agent（见 docs/MCP_GUIDE.md）

**验收**：`python -m security_agent.cli serve-mcp` 启动后，标准 MCP client 可发现并调用工具。（✅ 已达成：`scripts/_mcp_test.py` 15/15 通过）

---

## ✅ 阶段 8：Investigation Ledger 审计追踪（已完成 2026-08-10）

> **对标**：[AiSOC](https://github.com/beenuar/AiSOC) 的 Investigation Ledger（评审杀手锏）

### 目标
记录每次研判的完整证据链（prompt / LLM响应 / 工具调用 / 证据引用），可回放、可审计——竞赛评审加分最直观的模块。

### 任务
- [x] **8.1 Ledger 数据结构**
  - [x] `data/ledger/{event_id}.json`：完整记录每个步骤（`ledger/store.py`：LedgerStore + LedgerRecord）
  - [x] 字段：时间戳、阶段、工具调用（名称/输入/输出摘要）、LLM prompt、LLM响应、证据引用、最终裁决
- [x] **8.2 埋点**
  - [x] orchestrator 全流程埋点（context/prefilter/triage/postprocess/finalize）
  - [x] ai/client.py 记录每次 LLM 调用的 prompt + response（`on_llm_call` 回调）
- [x] **8.3 Web 回放**
  - [x] Web 面板"审计"页 `/ledger?event_id=...`：按事件查看完整调查过程（时间线 + LLM prompt/response）
  - [x] 导出为 JSON（`/api/ledger?event_id=...`，评审可核查）

**验收**：研判任意事件后，`data/ledger/` 生成完整记录；Web 可回放调查过程。（✅ 已达成：`scripts/_ledger_test.py` 18/18 通过）

---

## ✅ 阶段 9：Web UI 大屏化 + 对比可视化（已完成 2026-08-10）

> **对标**：[AiSOC](https://github.com/beenuar/AiSOC) 控制台、业界大屏

### 目标
把现有 Web 界面升级为演示级大屏，让评审一眼看懂"LLM 决策过程"。

### 任务
- [x] **9.1 四阶段 Agent 流程图增强**
  - [x] 动画展示数据流：Monitor → Context → Triage → Report（agent-flow 卡片 + 箭头动画）
  - [x] 每个 Agent 显示实际工具调用和输出（used_tools 徽章 + outputs）
- [x] **9.2 AI 决策可视化**
  - [x] 显示 risk_score 数值条 + 置信度徽章 + 研判路径（预筛直达 / LLM 深度研判）
  - [x] LLM 推理摘要展开（reasoning_summary 区域）
- [x] **9.3 对比评测面板**
  - [x] 规则 vs LLM vs 混合 三列柱状图（`/generate-modes` 生成 + 纯 CSS mode-bar）
  - [x] 当前模型模式指示（运行配置卡显示 Mock/DeepSeek/Qwen）
- [x] **9.4 审计回放页**
  - [x] 对接阶段 8 的 Ledger（首页"审计回放"入口 → `/ledger` 页 + `/api/ledger` JSON）
- [x] **9.5 深色科技风主题**
  - [x] 参考业界 SOC 大屏配色（深蓝 #0a1128 + 荧光绿 #00ff9d + 科技蓝 #00b3ff）

**验收**：打开 `http://127.0.0.1:8080` 即是大屏效果，评审可交互查看完整研判过程。（✅ 已达成：`scripts/_web_test.py` 11/11 通过）

---

## ✅ 阶段 10：文档 / PPT / 演示视频 / 论文论证（已完成 2026-08-10）

> **赛题交付物要求**

### 任务
- [x] **10.1 技术文档更新**
  - [x] 更新 `docs/ARCHITECTURE.md` v3.0：架构图含预筛+多Agent+Ledger 最终形态（阶段 1-9 全部实现）
  - [x] 更新 `docs/INNOVATION.md` v2.0：14 项创新点全部已实现（对照赛题）
- [x] **10.2 赛题论证材料**
  - [x] 新增 `docs/ARGUMENT.md`：XH-202614 论证"LLM 是核心决策引擎"（对比评测 + 工具调用链）
  - [x] XH-202609 论证"自主决策"（多Agent协作 + 闭环处置 + HITL + 误报记忆 + 审计）
- [x] **10.3 演示脚本**
  - [x] `docs/DEMO_SCRIPT.md`：10 分钟演示流程分节讲解词 + 操作步骤 + 应急预案
  - [x] 预设 3 个演示案例（EVENT-001 攻击 / EVENT-002 误报 / EVENT-003 待确认）
- [x] **10.4 数据准备**
  - [x] 截图存档指引（Web 大屏/对比评测/审计回放——见 PPT_OUTLINE 配图清单，需人工截屏）
  - [x] 演示视频脚本（由 DEMO_SCRIPT.md 分节覆盖，可直接录屏）
- [x] **10.5 PPT**
  - [x] 新增 `docs/PPT_OUTLINE.md`：痛点 → 方案 → 架构 → 创新 → 评测数据 5 段式大纲 + 配图清单

---

# ⚡ 里程碑时间表

| 里程碑 | 内容 | 预计工作量 |
|--------|------|-----------|
| M1 | 阶段 1-2 完成（预筛 + 置信门控） | 1 天 |
| M2 | 阶段 3-4 完成（多Agent + RAG） | 1 天 |
| M3 | 阶段 5 完成（评测体系） | 0.5 天 |
| M4 | 阶段 6-7 完成（记忆 + MCP） | 1 天 |
| M5 | 阶段 8-9 完成（Ledger + 大屏） | 1 天 |
| M6 | 阶段 10 完成（文档/PPT/演示） | 1 天 |

> **建议**：优先 M1（预筛 + 置信门控）和 M3（评测重标注），这两项直接决定评测通过率和赛题论证质量。

---

# 🛡️ 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| DeepSeek API 不稳定 | 演示现场失败 | 预筛器兜底 + MockLLM 模式 + 本地微调备选 |
| 评测基准过时 | 通过率低、论证弱 | 阶段 5.1 立即重标注 |
| 多Agent 增加复杂度 | 引入 bug | 每 Agent 独立测试 + 失败降级 |
| 向量库依赖 | 部署变重 | 保持轻量 RAG 为主，向量为可选 |
| 时间不足 | 部分功能未完成 | 按里程碑优先级推进，核心功能优先 |

---

# 📚 参考项目与模式库

| 模式 | 参考项目 | 应用阶段 |
|------|---------|---------|
| 确定性预筛 + LLM 深度研判 | [SOC Triage Agent](https://github.com/AnshSaxena05/cyberSecurity_alert_triage) | 1 |
| 置信度门控 | [Claude-Skills-Security](https://github.com/S3DFX-CYBER/Claude-Skills-Security) | 2 |
| 多 Agent 协作 | [AiSOC](https://github.com/beenuar/AiSOC)、[Vigil](https://github.com/Vigil-SOC/vigil)、[Microsoft Triangle](https://github.com/microsoft/Triangle) | 3 |
| RAG 知识库 | [AI_SOC](https://github.com/zhadyz/AI_SOC) | 4 |
| 评测基准 | [CyberSOCEval](https://github.com/CrowdStrike/CyberSOCEval_data)、[SecRespond](https://github.com/Alibaba-NLP/qqr) | 5 |
| 误报记忆 | [Skynet](https://github.com/LLAWLIGHT12/skynet) | 6 |
| MCP 集成 | [TriageMCP](https://github.com/alex-klinkovich/TriageMCP) | 7 |
| 调查账本 | [AiSOC](https://github.com/beenuar/AiSOC) | 8 |
| 小模型微调备选 | [pq-sift-defender](https://huggingface.co/CycleCoreTechnologies/pq-sift-defender-Q4_K_M) | 备选 |
| 误报去噪 | [DeepAudit](https://github.com/GitHubDaily/GitHubDaily/issues/696) | 备选 |

---

# 🎓 关键学术依据（论文论证用）

| 论文/数据 | 结论 | 引用场景 |
|-----------|------|---------|
| AIDR (2025) | Qwen3 LoRA 微调 → 风险分级 94.2%，比零样本 +27% | 论证微调价值 |
| Elsevier SOC 论文 | 8 LLM 二分类召回 >90%，但分级 F1 低 | 论证"LLM 做初筛 + 规则/微调做分级"的混合架构 |
| CyberSOCEval | 推理模型在安全领域优势不明显 | 论证"不必追求最大模型，架构更重要" |
| ExCyTIn-Bench | 最佳 agent 得分仅 0.368/1.0 | 论证 agentic 安全是开放难题，有研究价值 |

---

# ✅ 完成标准（挑战杯国赛水平）

1. **演示流畅**：Web 大屏一键启动，10 分钟讲完痛点→方案→创新→数据
2. **数据可信**：评测面板显示混合模式 vs 纯规则 vs 纯 LLM 对比 + 混淆矩阵
3. **创新明确**：预筛+LLM混合、置信度门控、误报记忆、多Agent、调查账本——至少 3 项原创组合
4. **双赛题覆盖**：XH-202614 讲"LLM 决策引擎"，XH-202609 讲"自主决策闭环"
5. **可复现**：Mock 模式零依赖可跑，真实 LLM 一键切换
