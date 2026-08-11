# 常见问题

> **版本**：v2.0（加入 AI 模块相关问答）

## 1. 这个项目的主题是什么？

**安全事件初步研判 + 误报剔除**

完整表达：

**基于 AI+安全大模型平台的安全事件初步研判与误报剔除智能体**

## 2. 默认 LLM 是什么？

两种模式：

- **AI 研判引擎**（新增）：读取 `DEEPSEEK_API_KEY`，DeepSeek 主用
- **MockLLM**（兜底）：无 API Key 时使用

## 3. 现在是多 Agent 吗？

严格说不是"真正独立协作执行的多 Agent 系统"，而是：

- 单编排执行链路
- 分阶段 Agent 展示（Monitor → Context → Triage → Report）

规划：todo.md 阶段 3 将升级为真多 Agent 协作。

## 4. ★ AI 研判引擎是什么？

新增的 `security_agent/ai/` 模块：

- **client.py**：统一 LLM 客户端（DeepSeek/Qwen/OpenAI）
- **triage.py**：LLM 研判引擎（替代硬编码规则）
- **enricher.py**：事件富化（ATT&CK/CVE）

核心变化：风险判定从"数 15 个关键词"升级为"LLM 综合证据推理"。

## 5. LLM 不可用怎么办？

**fail-open**：自动回退规则引擎（5 个关键恶意标记兜底），置信度标记为 `low`，不崩溃。

体现工程可靠性——这是生产级智能体的要求。

## 6. 它会自动检查安全吗？

它会自动做**事件触发后的安全初步分析**，但不会主动巡检整个网络。有事件输入后自动查上下文并判断。

## 7. 现在的输入方式符合真实应用吗？

部分符合，偏原型和比赛演示。当前：选择样例事件 / 上传 JSON / 上传日志文本。

真实生产环境后续更适合：SIEM/XDR/EDR 自动推送、接口调用、事件流接入。

## 8. 项目现在完整吗？

已是一个**可演示、可论证的原型**，具备：

- AI 研判引擎 + 规则兜底
- 多工具上下文
- 分阶段 Agent 展示
- 报告导出 + 评测面板

还需：预筛器（阶段1）、置信度门控（阶段2）、真多Agent（阶段3）、评测重标（阶段5.1）。

## 9. 演示案例在哪里看？

`security_agent/data/alerts.json`。推荐顺序：EVENT-001（攻击）、EVENT-002（误报）、EVENT-003（待确认）。

## 10. 如何启用 AI 研判？

```powershell
# PowerShell
$env:DEEPSEEK_API_KEY="your_key"
python -m security_agent.cli analyze --event-id EVENT-001
```

## 11. 如何切换 LLM？

```powershell
$env:SECURITY_AGENT_LLM_PROVIDER="qwen"  # 或 deepseek / generic
$env:SECURITY_AGENT_LLM_API_KEY="your_key"
```

## 12. 当前 Prompt 模板在哪里？

- `security_agent/ai/triage.py`（★ AI 研判引擎 prompt）
- `security_agent/ai/enricher.py`（富化 prompt）
- `security_agent/prompts/templates.py`（分阶段 Agent prompt）
- 文档：`docs/PROMPT_TEMPLATES.md`

## 13. 导出报告支持什么格式？

`Markdown` 和 `JSON`。

## 14. 评测为什么通过率低？

因为 `evaluation_cases.json` 的 `expected_event_type` 基于旧规则引擎标注，LLM 输出往往更准（如 EVENT-002 判"通用异常"而非"异常登录"）。**需重标**（见 `docs/EVALUATION.md` 和 `todo.md` 阶段 5.1）。
