# 功能说明

> **版本**：v2.0（加入 AI 研判引擎 / fail-open / 规则回退 / 事件富化）

## 核心功能

### 1. 安全事件初步研判（★ AI 驱动）

系统对安全事件进行初步分析，输出：

- 事件类型
- 风险等级
- 风险评分（0-100）
- 置信度
- 研判结论

**升级**：风险判定由 LLM 综合全部证据推理，替代旧版的硬编码 `suspicious_markers` 计数。

### 2. 误报剔除（★ AI + 规则双通道）

系统自动结合白名单、维护窗口、变更单、历史告警和上下文线索，判断事件是否更接近误报。

- **AI 通道**：LLM 综合误报线索推理
- **规则兜底**：AI 不可用时用 `maintenance/whitelist/change_ticket/baseline/例行/scheduled` 等特征判定

### 3. RAG 风格知识检索

- 基于事件语料和知识条目做打分
- 返回 Top-K 高相关知识
- 显示命中依据和相关分数
- 未命中时回退到通用研判建议

### 4. 上传内容分析

Web 页面支持两类输入：

- 事件 JSON
- 日志文本

上传内容会转换为临时事件进行分析，不会覆盖内置样例数据。

### 5. 分阶段 Agent 展示

4 个阶段 Agent：`Monitor Agent` → `Context Agent` → `Triage Agent` → `Report Agent`

每个 Agent 展示：角色、关注点、使用工具、阶段输出。

### 6. 四模块结构

- 任务入口模块
- 智能体编排模块
- 知识与数据模块
- 工具执行模块

### 7. 运营闭环工具

- `playbook_matcher`：匹配处置预案
- `ticket_generator`：生成模拟工单
- `host_isolation_simulator`：生成模拟隔离动作

### 8. 评测面板

内置 10 个标准案例，自动统计：

- 风险分级准确率
- 误报识别准确率
- 事件类型准确率
- 输出完整率
- 平均分析耗时

### 9. 报告导出

分析结果支持导出为：

- `Markdown`
- `JSON`

---

## ★ 新增功能（本次升级）

### 10. LLM 统一客户端（ai/client.py）

- 支持 **DeepSeek（主用）/ Qwen / 任意 OpenAI 兼容端点**
- `ai_chat()` 通用对话（temperature 0.3）
- `ai_chat_json()` 结构化 JSON 输出（temperature 0.1）
- **fail-open**：任何错误返回 `None`，绝不抛异常
- JSON fence-stripping + 首尾花括号提取

### 11. LLM 研判引擎（ai/triage.py）

- 中文 SOC 专家系统提示词
- 综合 5 项工具观测 + 知识库 + 计划 + 评分标准 + few-shot
- 输出 10 字段（与旧 IncidentTriageTool 完全一致）
- **防御性解析**：每个字段校验，非法值回退默认
- **规则回退**：LLM 不可用时用 5 个关键恶意标记兜底，标记 `confidence=low`

### 12. 事件富化（ai/enricher.py）

- MITRE ATT&CK 技术映射
- 相关 CVE 关联
- 调查步骤建议
- 失败开放：返回空结构不影响主流程

### 13. 编排器 AI 优先集成

```
agent/orchestrator.py:
  分析 = ai_triage_event(...)   # LLM 优先
  if 分析 is None:             # AI 不可用
      分析 = 规则引擎.run(...)   # 兜底
```

---

## 已实现工具

- `asset_lookup`
- `log_lookup`
- `intel_lookup`
- `history_alert_lookup`
- `false_positive_check`
- `incident_triage`（★ 委托给 AI 模块）
- `playbook_matcher`
- `ticket_generator`
- `host_isolation_simulator`

## 模型模式

| 模式 | 说明 | 使用场景 |
|------|------|---------|
| `MockLLM` | 零依赖模拟 | 无 API Key 演示 |
| `DeepSeek` | 默认主用 | 生产演示 |
| `Qwen` | 通义千问 | 备选 |
| `generic` | OpenAI 兼容 | 自定义端点 |

## 能力矩阵（对照赛题）

| 赛题要求 | 当前实现 | 状态 |
|---------|---------|------|
| LLM 智能体推理 | ai/triage.py LLM 研判 | ✅ |
| 工具调用 | 9 个工具 + ToolRegistry | ✅ |
| 多 Agent 协作 | 展示层 4 阶段 | ⚠️ 需升级为真多Agent |
| 误报剔除 | AI + 规则双通道 | ✅ |
| 自主决策 | 编排器动态计划 | ⚠️ 需增强 |
| 评测论证 | 10 案例评测面板 | ⚠️ 需重标 |
