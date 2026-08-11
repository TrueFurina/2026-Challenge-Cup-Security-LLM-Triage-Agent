# 🤖 AI 模块技术详解（阶段 0 交付）

> 本次升级的核心交付：把安全事件研判从「硬编码规则」升级为「LLM 决策核心 + 规则兜底」。

## 1. 为什么做这个升级

**升级前**（硬编码规则）：
```python
# tools/implementations.py
suspicious_markers = ["encodedcommand", "downloadstring", "powershell", ...]
suspicious_score = sum(1 for marker in suspicious_markers if marker in corpus)
# → 风险判定是"数标记"，LLM 只做最后总结润色（装饰品）
```

**升级后**（LLM 决策核心）：
```python
# agent/orchestrator.py → 调用 ai/triage.py
analysis = ai_triage_event(event, asset_obs, log_obs, intel_obs, history_obs, fp_obs, knowledge_items, plan)
# → LLM 综合全部证据推理出风险等级/误报判断，规则引擎只在 LLM 不可用时兜底
```

## 2. 模块结构（4 文件，976 行）

### 2.1 `ai/client.py` — 统一 LLM 客户端（251 行）
- **多提供商**：DeepSeek（主用）/ Qwen / 任意 OpenAI 兼容端点
- **核心 API**：
  - `ai_chat(messages, system=None, temperature=0.3)` → `str|None`
  - `ai_chat_json(messages, system=None, temperature=0.1)` → `dict|None`
- **fail-open 原则**：任何错误返回 `None`，绝不抛异常
- **密钥解析优先级**：`DEEPSEEK_API_KEY` 环境变量 → `SECURITY_AGENT_LLM_API_KEY` → `AppConfig`
- **JSON 提取**：剥离 ```json fence → 尝试截取首尾花括号
- 依赖：`httpx`（可选，缺失时 AI 能力自动降级）

### 2.2 `ai/triage.py` — LLM 研判引擎（566 行）⭐核心
- **入口**：`triage_event(event, 5个工具观测, knowledge_items, plan) → dict`
- **Prompt 设计**：
  - 中文 system prompt：15 年资深 SOC 专家
  - 事件详情 + 5 项工具观测 + 知识库 + 研判计划 + 评分标准（0-100）+ JSON 契约 + 3 个 few-shot 示例
- **评分标准**：0-20 误报 / 21-40 低 / 41-60 中 / 61-80 高 / 81-100 严重
- **温度**：0.1（确定性优先）
- **防御性解析**：每个字段校验类型，非法值回退默认（risk_level→medium，event_type→通用异常行为，非法 risk_score 由 risk_level 反推）
- **规则回退**：LLM 不可用时用 5 个最关键的恶意标记（encodedcommand/downloadstring/webshell/beacon/rundll32）做轻量判定，标记 `confidence=low`
- **输出 10 字段**：与 `IncidentTriageTool` 完全一致

### 2.3 `ai/enricher.py` — 事件富化（137 行）
- **入口**：`enrich_event(event) → dict`
- 输出：`mitre_techniques`（ATT&CK 映射）/ `related_cves` / `investigation_steps`
- fail-open：失败返回空结构

### 2.4 `ai/__init__.py` — 模块导出
```python
from security_agent.ai.client import ai_chat, ai_chat_json
from security_agent.ai.enricher import enrich_event
from security_agent.ai.triage import triage_event
```

## 3. 编排器集成方式

`agent/orchestrator.py` 第 59-76 行：
```python
# AI 优先研判：LLM 推理 → 回退硬编码规则
analysis = ai_triage_event(...)
if analysis is None:
    analysis = analyzer_tool.run(...)  # 旧规则引擎兜底
```
- 主路径：LLM 研判
- 回退路径：硬编码规则（不删除，作为保险）

`tools/implementations.py` 的 `IncidentTriageTool` 也委托给 AI 模块，外层套 try/except。

## 4. 关键设计决策

| 决策 | 原因 |
|------|------|
| LLM 做核心决策 | 赛题 XH-202614 要求"智能体研究"，LLM 必须是引擎不是花瓶 |
| 规则引擎保留做兜底 | fail-open：无 API Key / 超时 / 解析失败都不崩溃 |
| 温度 0.1 | 研判需要一致性，不能用发散输出 |
| 防御性解析 | LLM 输出不可信，每个字段都要验证 |
| 中文 prompt | 安全领域中文知识更准确，且评审是中文 |
| httpx 而非 SDK | 轻量、无版本冲突、可控 |

## 5. 已验证结果（真实 DeepSeek）

```
EVENT-001 (PowerShell攻击) → critical / 恶意脚本执行 / high confidence ✓
EVENT-002 (维护误报)       → low / 误报=true ✓
FP 识别准确率 90%
LLM 单次研判约 11 秒（含 API 延迟）
```

## 6. 已知限制 → 下一步（对应 todo.md）

| 限制 | 对应阶段 |
|------|---------|
| 每事件都调 LLM，成本高、慢 | 阶段 1：确定性预筛器（规则先筛，不确定才给 LLM） |
| 评测基准过时（expected 值基于旧规则） | 阶段 5.1：评测案例重标注 |
| 无置信度门控 | 阶段 2 |
| 无多 Agent 协作 | 阶段 3 |
