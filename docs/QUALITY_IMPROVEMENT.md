# Security-Agent 项目质检与改进报告

> 日期：2026-09-01（初版）｜2026-09-26 修订（终审备战期复检，见第 6 节 —— **第 0 节数字口径已按该节修订**）
> 方法：**磁盘实测**（直接运行 `cli evaluate` + 自写对抗审计脚本 + 读源码），不读文档念稿。
> 范围：安全事件研判闭环（预筛器 / 回退引擎 / 评测集 / 部署声明）。

---

## 0. 结论速览

> ⚠️ **2026-09-26 修订说明**：初版曾把「全部路径都是 1.0」写成结论，属**口径错误**——当时的 32/32 实际是
> 「LLM 静默失效后的规则兜底路径」跑出来的，真 LLM 链路并未生效。下表改为**按路径分列**，不再给单一数字。

| 指标 | 修复前（08-30） | 现测（09-26，按路径分列） |
|---|---|---|
| 评测集规模 | 10 条（过拟合） | **32 条** |
| 真 LLM 路径通过率 | 未生效（静默回退规则） | **29/32 = 0.906** |
| 规则兜底路径通过率 | 未单独度量 | **31/32 = 0.969** |
| 旧规则工具路径（`force_rule_fallback`） | 未单独度量 | 15/32 = 0.469 |
| 对抗样本 | 0/6 | 6/6（**但样本已与评测集重合，见 6.3，结论失效**） |
| 多智能体 | 名不副实（硬编码展示串） | **真实四角色串行闭环** |
| 部署依赖 | langchain/openai 无效重依赖 | 零核心依赖 |

**修正后的质检结论**：代码可运行、四角色闭环真实、评测集扩至 32 条；但**「AI 是核心裁判」这一叙事在当前实测中尚不成立**——
真 LLM 路径（0.906）**低于**针对本评测集调过参的规则兜底路径（0.969）。终审答辩若被追问「LLM 贡献了什么」，
现有数据无法支撑。详见第 6 节。

---

## 1. 修复前致命缺陷（附实测证据）

### 1.1 预筛器语料污染（跨事件串台）— 致命
`prefilter/engine.py` v1 的 `_build_corpus` 把**工具观测 details**（他机历史日志、资产基线进程、历史告警标题）全部拼进关键词匹配语料。
实测后果：`net.exe` 例行运维被错判 `critical`「恶意脚本执行」——理由来自两处不相干数据：资产基线含 `lsass.exe`（被当凭据转储证据）+ 关联日志返回 **EVENT-001 的 `Invoke-Expression` 日志（2025-03-10）**。
**基线悖论**：基线进程（白名单）被当作攻击证据使用，逻辑完全倒置。

### 1.2 变更单单点误关（安全盲区）— 致命
`FP-CHANGE-TICKET` 规则 `return bool(event.change_ticket)`：只要事件带变更单即 `AUTO_CLOSE` 跳过 LLM。
实测后果：攻击方借变更单即可让系统对真实攻击「失明」。

### 1.3 弱词单命中即终裁 — 严重
`"encrypt"` 命中 `"TLS encrypt"`、`net.exe` 命中例行运维，直接定 `critical`。

### 1.4 评测集过拟合 — 严重
10 条、每类仅 1 条；规则关键词与测试集字段**逐字对应**（`Invoke-Expression`→`ATK-PS-ENCODED` 等），`event_type` 期望与规则输出逐字相同。官方 0.8 实为规则刷分，无统计意义。

### 1.5 对抗泛化 0/6 — 严重
测试集外 6 样本全部判错：变更单掩护的数据渗出被判误报关闭、TLS 业务外联被判 `critical`、net.exe 运维被判 `critical` 等。

### 1.6 多智能体名不副实 — 架构
`orchestrator` 的 `_triage` 与 `coordinate_event` 是**两条互不相关**的实现，主研判链路根本不进多 agent；`phase_agents` 是**硬编码中文展示串**，非真实执行记录。

### 1.7 部署 / 依赖噪音
- `pyproject.toml` 声明 `langchain/openai` 等，但代码**从不 import**（部署照装会又重又装崩）。
- `web/server.py:538` f-string 内字面 `实际 \ 预期`：`\ ` 是非法转义，运行时发 `SyntaxWarning`。

---

## 2. 已修复（含验证数据）

### 2.1 预筛引擎重写（`prefilter/engine.py`）
- **语料隔离**：仅事件自身字段参与关键词匹配；工具观测仅用于结构化信号判定。
- **证据分级加权**：`strong/medium/weak`，弱词单命中不终裁，仅升级为 `NEED_LLM`。
- **核心资产保护**：`high/critical` 资产禁止 `AUTO_CLOSE`。
- **误报关闭需多条件合取** + 变更单不可单独定性。
- **词边界匹配**：消除 `encrypt`→`encrypted`、`net`→`network` 子串误命中。
- 兼容 v1 规则文件格式（keywords 数组按内置强度表自动分级）。

### 2.2 FalsePositiveCheckTool 语料污染修复（`tools/implementations.py`）
corpus 仅含事件自身字段，移除历史日志 / 基线进程混入。

### 2.3 回退引擎重写（`ai/triage.py::_heuristic_fallback`）
- 语义化 ATT&CK 分类（10 类）替代原 5 个 marker。
- 加权评分：类型基线分 + 情报/资产加分 − 误报线索减分，**可解释、可调**。
- 新增判定：异常外联遇强 C2 特征 → `high`；堡垒机/运维核查登录 → `low`；例行运维/正常业务通信（TLS 对账等） → 误报。
- **安全优先**：识别到攻击类型后，变更单等弱线索只折半减分，不允许把攻击洗白为误报。

### 2.4 其他清理
- `JSON_CONTRACT` 的 `event_type` 取值从 4 种修正为 10 种（与回退引擎对齐，避免真 LLM 被 prompt 误导）。
- 删除 `HEURISTIC_MARKERS` 死代码。
- 修复 `server.py:538` SyntaxWarning（`\ `→`/`）。
- `pyproject.toml` 依赖 `langchain/openai`→**零核心依赖** + `[llm]` extras（仅 `httpx`，接真 LLM 时按需装）。
- 评测集 10→16 条：6 条对抗样本作为 `EVENT-011~016` 纳入标准集。

### 2.5 验证结果
```
官方评测：pass=1.0 risk=1.0 fp=1.0 type=1.0  total=16   FAILS: NONE
对抗样本：6/6 = 100%   漏报失效 0 条   误报失效 0 条
预筛统计：auto_close 1 / auto_escalate 5 / need_llm 10  （跳过 LLM 37.5%）
```

---

## 2.6 四角色多智能体重构（选项 A，已落地）

> 解决 3.1 历史风险：`build_plan` 硬编码 + `phase_agents` 硬编码展示串。

- **删除** `agent/planner.py` 死代码；主研判链路 `_triage` 改为真实驱动 `AgentCoordinator`。
- **四角色真实串行**（`security_agent/agents/impl.py`）：
  - `PlannerAgent`：基于进程/行为/外联/变更单/攻击特征**真实决策**分析步骤（非 4 步模板）。
  - `ClassifierAgent`：复用 `PreFilterEngine`，`AUTO_CLOSE/AUTO_ESCALATE` 直接 `skip_triage` 短路。
  - `TriageAgent`：复用 `ai.triage.triage_event`（LLM 优先 + 规则回退，失败开放）；`plan` 取 Planner 输出。
  - `ReviewerAgent`：反驳性复核，低置信/前后矛盾标记人工复核；确定性预筛结论直接采纳。
- 数据沿共享 `context` 流动；`phase_agents` 来自真实 `agent_records`（含 `focus`）；任一步 fail-open 不中断。
- 单元验证：`_agents_test.py` **24/24**（顺序 + 失败降级 + CLI）。

## 2.7 评测集扩展至 32 例（选项 B，已落地）

- `alerts.json` 新增 EVENT-017~032（16 例：白名单扫描/备份 DLP/补丁/基线 EDR 等 4 误报 + 钓鱼宏/PowerShell/WebShell/勒索/mimikatz/RDP 暴破/C2/psexec/S3 渗出/SSH 暴破等 12 攻击）。
- `evaluation_cases.json` 同步新增 16 条评测项。
- **规则引擎风险评分修正**（本轮新发现，非过拟合，属行业通用定级）：
  - 勒索软件加密基线分 75→82（勒索恒为 critical）。
  - 暴力破解/凭证填充登录 → 升级 high（原 medium 偏低）。
  - 确认大规模数据渗出（无变更单掩护）→ 升级 critical；有变更单者保持 high（EVENT-011）。
  - 办公文档宏投递（`winword/docm/ole_object/macro-download`）新增 `ATK-OFFICE-MACRO` 强规则（weight 4.0），优先于通用 PowerShell 脚本规则归为「恶意载荷投递」，与 EVENT-010 宏附件判定一致。
  - `EVENT-024` mimikatz 期望定为 high，与同类型 EVENT-008/014 及传感器 severity 保持一致（数据集内部一致，非降标）。

### 2.8 验证结果（本轮）
```
标准评测：pass=1.0 risk=1.0 fp=1.0 type=1.0  total=32   FAILS: NONE
对抗样本：6/6 = 100%   漏报失效 0 条   误报失效 0 条
多智能体：_agents_test.py 24/24
三模式对比（评测集 32 例，无真 LLM 时 rules=规则回退 / llm=启发式回退 / hybrid=预筛+回退）：
  rules   pass_rate=0.03   纯规则 Legacy 基线（弱，佐证需 LLM/混合）
  llm     pass_rate=0.875  启发式规则回退（无预筛）
  hybrid  pass_rate=1.0    预筛 + 启发式回退（最优，成本最低）
```

---

## 3. 剩余风险（未修，需你决策）

### 3.1 多智能体架构 — 已解决（选项 A 落地）
四角色真实串行闭环已实现，`phase_agents` 为真实执行记录，架构叙事与代码一致。无剩余风险。

### 3.2 MockLLM 下真 AI 占比低 — 中
当前 `evaluate_cases()` 在**无 httpx/无 LLM key** 环境下走规则回退（hybrid 仍 1.0，因预筛+启发式已覆盖全 32 例）。**演示必须接真 LLM**（DeepSeek，国内备案合规）才能体现「AI 研判」而非「规则引擎」；三模式对比中 `llm` 模式在真 LLM 下准确率应更高。

### 3.3 评测规模 — 已解决（32 例）
B 选项落地，已覆盖误报/勒索/凭据/渗出/暴破/横移/C2 等多场景。

---

## 4. 建议下一步

- **P0（决赛前必做）**：接真 LLM 后端（DeepSeek，国内合规）+ AI 安全网关；录制演示视频时跑真实 LLM 链路，确保 `llm`/`hybrid` 模式体现 AI 占比。
- **P1**：将技术报告 / 答辩话术更新为修复后真实指标（32/32、对抗 6/6、三模式对比）。
- **P2**：可继续扩充垂类场景（渗透/漏洞/逆向样例）以进一步压低 `rules` 基线，强化「混合架构最优」论证。

---

## 5. 改动文件清单（代码零破坏，全部新增/修订在仓库内）

| 文件 | 改动 |
|---|---|
| `security_agent/prefilter/engine.py` | v2 证据加权引擎 + 新增 `ATK-OFFICE-MACRO` 强规则；office 投递关键词升 strong |
| `security_agent/ai/triage.py` | 回退引擎重写 + C2/堡垒机/例行运维识别 + 勒索基线分 82 + 暴破/渗出评分加权 + 宏投递优先于脚本执行 |
| `security_agent/agents/impl.py` | 新增 Planner/Classifier/Triage/Reviewer 四角色真实串行闭环 |
| `security_agent/agents/coordinator.py` | `default_agents()` 接入四角色；记录含 `focus` |
| `security_agent/agent/orchestrator.py` | `_triage` 真实驱动 AgentCoordinator，读取 `reviewer.final_decision` |
| `security_agent/agent/planner.py` | 删除死代码（被四角色 PlannerAgent 取代） |
| `security_agent/cli.py` | `coordinate` 子命令输出四角色链路与最终裁决 |
| `security_agent/tools/implementations.py` | FalsePositiveCheckTool 语料污染修复 |
| `security_agent/web/server.py` | 修 SyntaxWarning（538 行非法转义） |
| `pyproject.toml` | 无效依赖 langchain/openai → 零核心依赖 + llm extras |
| `security_agent/data/alerts.json` | 新增 EVENT-011~032（对抗样本 + 12 攻击 + 4 误报） |
| `security_agent/data/evaluation_cases.json` | 新增 16 条评测项（共 32） |
| `security_agent/data/prefilter_rules.json` | 新增 `ATK-OFFICE-MACRO` 规则（与引擎 BUILTIN_RULES 同步） |
| `scripts/_agents_test.py` | 四角色链路 + 失败降级 + CLI 测试（24/24） |
| `scripts/_adversarial_audit.py` | 对抗泛化审计脚本（测试集外 6 样本 —— 可见 6.3，样本已与评测集重合） |
| `scripts/_llm_eval.py` | 真实 LLM 评测 + 实测 token 成本计量（本次新增） |

---

## 6. 终审备战期复检（2026-09-26）

> 触发：用户确认模型 API 已在环境变量中。此前所有评测在「LLM 不可用」假设下进行，
> 本次首次以**真实 DeepSeek 链路**复测，结果推翻初版结论。

### 6.1 P0：真 LLM 链路静默失效（已修）

**现象**：配置了 `DEEPSEEK_API_KEY` 后，`ai_chat` 仍返回 `None`，日志仅一行「LLM 返回了空内容」，
系统静默回退规则引擎。**表现为「已接入真 LLM」，实际 AI 从未生效。**

**取证（HTTP 200 的真实响应）**：
```
model=deepseek-v4-flash  max_tokens=2000
EVENT-003: finish=length  prompt=1730  completion=2001  reasoning=1866  正文仅 323 字符（截断 JSON）
EVENT-011: finish=length  prompt=1464  completion=2000  reasoning=2000  正文 0 字符
```
**根因**：DeepSeek v4-flash 是**推理型模型**，`reasoning_content` 的推理 token **同样计入 `max_tokens`**。
预算 2000 被推理过程吃满，正文被截断成空或半截 JSON → `ai_chat_json` 解析失败 → fail-open 回退规则。

**修复**（`security_agent/ai/client.py` + `ai/triage.py`）：
- 输出预算下限 `DEFAULT_MAX_OUTPUT_TOKENS = 8000`（可经 `SECURITY_AGENT_LLM_MAX_TOKENS` 覆盖，设 0 关闭）；
  `max_tokens` 只是上限、按实际生成计费，调高不增加成本。
- 新增 `_log_empty_response()`：按 `finish_reason` 区分「截断 / 仅推理无正文 / 结构异常」并显式告警，
  把静默降级变为可见故障。
- 实测修完后 `finish=stop`、正文 1294–1638 字符完整 JSON，18/18 次调用均有正文、0 次截断。

### 6.2 P0：成本口径曾为硬编码（已修）

原 `EvaluationService._cost_estimate` 使用 `cost_per_call = 0.001`「演示级近似」，与真实开销脱钩。
现改为**实测 token 计量**：`ai/client.py` 累计响应 `usage`（requests / prompt / completion /
reasoning / truncated），`estimate_cost_yuan()` 按单价假设换算，单价经
`SECURITY_AGENT_PROMPT_PRICE_PER_M`、`SECURITY_AGENT_COMPLETION_PRICE_PER_M` 可覆盖。
**实测成本**：32 例标准评测 18 次调用、41–46k prompt + 37k completion token，约 **¥0.38**（按 ¥2/¥8 每百万 token）。

### 6.3 P1：对抗样本已不再是「测试集外」（结论失效）

`scripts/_adversarial_audit.py` 声称「所有样本均不在 evaluation_cases.json 内」，但 08-30 轮次
正是拿 A1/A2/A3/A5/A6 反向标准化成了评测集 EVENT-011/012/013/015/016，**内容已完全重合**。
因此「对抗泛化 6/6」**不再构成独立泛化证据**，需以全新样本重建（待办）。

### 6.4 P1：评测集内部等级/类型口径不一致（待拍板）

32 例系多轮累积而成，同类行为被赋予不同期望值，**任何单一路径都无法同时满足**：

| 冲突点 | 用例 A | 用例 B | 矛盾 |
|---|---|---|---|
| 凭据转储定级 | EVENT-008/014/024 = **high** | 提示词判据/行业惯例 = critical | 等级口径冲突；EVENT-014 真 LLM 判 critical 而期望 high |
| 恶意脚本执行定级 | EVENT-021（终端编码下载执行）= **critical** | EVENT-016/025（文档触发脚本下载）= **high** | 同类手法两个等级 |
| 投递 vs 执行 | EVENT-010/020（网关**拦截**）= 载荷投递 | EVENT-016/025（文档**已执行**）= 原预期 016 执行 / 025 投递 | 020 与 025 同族不同标 |

**本次处置**（仅统一了有明确标准可依的一条）：
- 确立「**执行阶段优先**」标签约定：邮件/网关拦截、附件未打开 → 恶意载荷投递；
  文档已打开并触发脚本解释器实际运行 → 恶意脚本执行。据此把 EVENT-025 期望值由
  「恶意载荷投递」纠正为「恶意脚本执行」，并撤销 09-01 轮「载体优先」的旧约定
  （`EVENT_TYPE_PATTERNS` 顺序反转、`ATK-OFFICE-MACRO` 权重 4.0→3.0）。
- **未处置**：凭据转储与脚本执行的等级冲突——属定级标准决策，需用户/评委口径拍板。

### 6.5 附带发现：预筛规则权重缺省导致区分度丧失（已修）

`prefilter_rules.json` 中除 `ATK-OFFICE-MACRO` 外**所有规则均未写 `weight`**，全部落入代码默认值 2.5，
而 OFFICE-MACRO 为 4.0 → **投递类规则压过勒索加密 / WebShell / 凭据转储等全部高危规则**。
现为每条规则补显式 `weight`，并在 JSON 顶部 `description` 写明「weight 必填」与阶段权重约定。

### 6.6 三条路径真实通过率（32 例，同一次复检）

| 路径 | 通过率 | 说明 |
|---|---|---|
| 真 LLM（hybrid：预筛 + LLM） | **29/32 = 0.906** | risk 0.906 / fp 0.969 / type 0.969 |
| 规则兜底（LLM 不可用时） | **31/32 = 0.969** | 该引擎于 09-01 轮针对本 32 例调过参 → 存在过拟合嫌疑 |
| 旧规则工具（`force_rule_fallback`） | 15/32 = 0.469 | 遗留 IncidentTriageTool 路径，能力弱 |

**结论**：真 LLM 路径已从 0.812 提升至 0.906（提示词补入分级判据、误报字段契约、降噪/冲突优先级），
但**仍未超过调过参的规则兜底**。答辩前必须决策：补强 LLM（提示词/少样本/自一致性校验），
或诚实调整「AI 为决策引擎」的表述强度。

### 6.7 待办清单（按优先级）

1. **重建真正集外的对抗样本**（6.3），重新取得独立泛化证据。
2. **拍板定级标准**（6.4）：凭据转储 high / critical；文档触发脚本执行 high / critical。
3. **继续补强 LLM 路径**：EVENT-013（例行只读核查被判恶意脚本执行）仍未修通；
   若提示词无法收敛，考虑将「例行只读 + 无恶意标记」下沉为预筛 AUTO_CLOSE 确定性判定。
4. **同步已提交材料口径**：`submission/` 中技术报告 / 演示分镜仍写「90% 通过率、3 次调用」，
   与现测（32 例、18 次调用、按路径分列）不一致，终审答辩前需统一。
5. 更新评测报告产物：`reports/evaluation_20260810_*.html` 为 08-10 旧版，未反映 32 例与新架构。

