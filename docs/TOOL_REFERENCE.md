# 工具参考

> **版本**：v2.0（标注 AI 委托 + 预筛器规划）

本文档说明当前项目中已实现工具的职责、输入、输出和适合展示的重点。

## 工具总览

当前内置工具包括：

| 工具 | 类型 | 说明 |
|------|------|------|
| `asset_lookup` | 上下文 | 资产画像查询 |
| `log_lookup` | 上下文 | 日志查询 |
| `intel_lookup` | 上下文 | IP/域名情报查询 |
| `history_alert_lookup` | 上下文 | 历史告警查询 |
| `false_positive_check` | 研判 | 误报线索检查 |
| `incident_triage` | 研判 | ★ 主分析（委托给 AI 模块） |
| `playbook_matcher` | 闭环 | 处置预案匹配 |
| `ticket_generator` | 闭环 | 模拟工单生成 |
| `host_isolation_simulator` | 闭环 | 模拟隔离动作 |
| `command_executor` | 扩展 | 命令执行（可选） |

## 1. `asset_lookup`

作用：查询主机资产画像，补充研判上下文。

典型输入：`host`

典型输出：
- 资产负责人
- 所属部门
- 资产重要性
- 基线进程
- 维护窗口

项目价值：判断资产是否关键、行为是否偏离基线、是否与维护窗口有关。

## 2. `log_lookup`

作用：查询与当前事件相关的日志片段。

典型输入：`host`、`user`

典型输出：最近几条与主机或账号相关的日志摘要。

项目价值：补充事件时间线，帮助确认进程链或外联行为。

## 3. `intel_lookup`

作用：查询事件涉及的 `IP / 域名` 情报。

典型输入：`destination_ip`、`destination_domain`

典型输出：指标类型、信誉等级、风险说明。

项目价值：判断外联目标是否高危，提高风险定级可信度。

## 4. `history_alert_lookup`

作用：查询与当前主机或用户相关的历史告警。

典型输入：`host`、`user`

典型输出：历史事件标题、历史风险等级、历史处置结论、时间戳。

项目价值：判断历史相似事件，区分重复攻击和重复误报。

## 5. `false_positive_check`

作用：检查当前事件是否存在误报线索。

重点检查：
- 白名单
- 维护窗口
- 变更单
- 基线运维特征

典型输出：是否发现误报线索、命中的误报依据列表。

项目价值：降低误报处理成本，为是否升级处置提供依据。

## 6. `incident_triage` ★（AI 委托）

作用：主分析工具，综合上下文形成初步研判结果。

输入来源：
- 事件本身
- 资产 / 日志 / 情报 / 历史 / 误报检查结果
- 知识库命中
- 研判计划

**★ 升级**：该工具已委托给 `ai.triage.triage_event()`，由 LLM 完成研判：
- LLM 综合全部证据推理 → 输出结构化裁决
- LLM 不可用 → 自动回退规则引擎（5 个关键恶意标记）

典型输出：
- 事件类型
- 风险等级
- 风险评分（0-100）
- 置信度
- 是否疑似误报
- 推理摘要
- 证据链
- 处置建议

项目价值：统一汇总所有上下文，AI 输出结构化研判结论。

## 7. `playbook_matcher`

作用：根据风险等级和误报判断，匹配处置预案。

典型输出：预案名称、核心处置步骤。

项目价值：让结果更接近真实 SOC 流程，将"分析"延伸到"按什么流程处置"。

## 8. `ticket_generator`

作用：为当前事件生成模拟工单。

典型输出：工单编号、优先级、处理队列、事件摘要。

项目价值：演示分析结果如何进入运营闭环。

## 9. `host_isolation_simulator`

作用：根据风险等级生成模拟处置动作。

典型输出：是否建议隔离、建议动作、执行模式（模拟执行/待审批）。

项目价值：将结果从"建议"推进到"动作"。

## 10. `command_executor`

作用：预留命令执行接口，仅在开启配置后加入工具集。

启用方式：

```powershell
$env:SECURITY_AGENT_ENABLE_COMMAND_TOOL="1"
```

当前状态：不是主流程核心工具，更适合作为后续接真实平台的扩展点。

---

## ★ 新增：AI 核心模块（非工具，但承担研判职责）

| 模块 | 职责 |
|------|------|
| `ai/client.py` | 统一 LLM 客户端（DeepSeek/Qwen/OpenAI） |
| `ai/triage.py` | LLM 研判引擎 + 规则回退 |
| `ai/enricher.py` | 事件富化（ATT&CK/CVE/调查步骤） |

## 📋 规划中工具（todo.md）

| 阶段 | 工具 | 用途 |
|------|------|------|
| 阶段 1 | `prefilter_engine` | 确定性预筛器：规则先筛，FP>80% 自动关闭 |
| 阶段 3 | `ioc_search` | Hunt Agent 的 IOC 搜索 |
| 阶段 3 | `process_tree` | Hunt Agent 的进程树分析 |
| 阶段 6 | `memory_retriever` | 误报记忆检索（注入 prompt） |

## 建议展示顺序

答辩时推荐按下面顺序介绍：

1. `asset_lookup`
2. `intel_lookup`
3. `history_alert_lookup`
4. `false_positive_check`
5. `incident_triage`（★ 说明已升级为 AI 研判）
6. `playbook_matcher`
7. `ticket_generator`
8. `host_isolation_simulator`

这个顺序能体现：

- 先补上下文
- 再做 AI 风险判断
- 最后进入预案、工单和动作闭环
