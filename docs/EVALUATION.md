# 评估说明

> **版本**：v2.1（评测基准已重标完成，基于真实 DeepSeek 输出 + 人工复核）

## 当前评测能力

项目已内置标准评测集：

- 数据文件：`security_agent/data/evaluation_cases.json`
- 评测逻辑：`security_agent/evaluation/service.py`
- CLI 命令：`python -m security_agent.cli evaluate`
- Web 接口：`/api/evaluation`

## 评测维度

| 指标 | 含义 |
|------|------|
| 风险分级准确率 | 判定风险等级与预期一致的比例 |
| 误报识别准确率 | 判定误报/非误报与预期一致的比例 |
| 事件类型准确率 | 判定事件类型与预期一致的比例 |
| 输出完整率 | 必需输出字段非空的比例 |
| 平均分析耗时 | 平均单事件分析毫秒数 |
| 综合通过率 | 风险+误报+类型三项全对的比例 |
| 预筛分流统计 | AUTO_CLOSE / AUTO_ESCALATE / NEED_LLM 数量 |
| LLM 调用节省率 | 预筛直接裁决（不调 LLM）的案例占比 |

## 评测案例（重标后，v2）

当前评测集覆盖 10 个场景（已与 `alerts.json` 真实告警内容对齐）：

| 案例 | 场景 | 预期风险 | 预期类型 | 预期误报 |
|------|------|---------|---------|---------|
| EVENT-001 | 域控 PowerShell 编码命令执行 | critical | 恶意脚本执行 | false |
| EVENT-002 | 打印机白名单扫描（误报） | low | 误报 | true |
| EVENT-003 | OA 异常外联疑似 C2 | high | 异常外联 | false |
| EVENT-004 | 研发服务器管理共享访问 | high | 横向移动前置 | false |
| EVENT-005 | 财务服务器异常 SSH 登录 | medium | 异常登录 | false |
| EVENT-006 | Web 服务器 WebShell 上传 | critical | WebShell 攻击 | false |
| EVENT-007 | 文件服务器勒索加密 | critical | 勒索软件加密 | false |
| EVENT-008 | 终端设备凭据转储 | high | 凭据转储 | false |
| EVENT-009 | 堡垒机跳转运维核查 | low | 异常登录 | false |
| EVENT-010 | 邮件网关恶意宏附件 | high | 恶意载荷投递 | false |

## ✅ 评测基准重标注已完成（2026-08-10，todo.md 阶段 5.1）

### 背景与根因

`evaluation_cases.json` 的旧 expected 值基于旧硬编码规则引擎标注，且**部分案例与 `alerts.json` 真实告警内容完全错位**（不只是"过时"）：

- EVENT-007 实际是「文件服务器勒索加密」，旧标注却写「夜间异常登录」
- EVENT-008 实际是「终端凭据转储」（rundll32 EnumerateCredentials），旧标注却写「备份服务器误报，FP=true」
- EVENT-009 实际是「堡垒机跳转」，旧标注写「DNS 信标回连」
- EVENT-010 实际是「邮件恶意宏附件」，旧标注写「堡垒机账户枚举」

旧基准错位导致评测通过率被系统性低估（此前 pass_rate 仅 0.1）。

### 重标依据（三步）

1. **纯 LLM 模式基准**：临时禁用预筛器，用真实 DeepSeek 跑全部 10 案例，得到 LLM 原始输出
2. **人工复核**：结合 `alerts.json` 真实告警内容 + `knowledge.json` 知识库，逐案例判定 expected 三字段（风险等级 / 事件类型 / 是否误报）
3. **直接重写** `evaluation_cases.json`（git 可回滚，无需另存 v2 备份文件）

### 修正原则

- **LLM 类型具体且准确** → 跟随 LLM（EVENT-001/003/005/009）
- **LLM 输出泛化**（把 WebShell/勒索/凭据转储等一律归为"通用异常行为"或"恶意脚本执行"）→ 以预筛规则的专业类型修正（EVENT-002/004/006/007/008/010）

### 新旧 expected 对比

| 案例 | 旧：风险/类型/误报 | 新：风险/类型/误报 | 变化 |
|------|-------------------|-------------------|------|
| EVENT-001 | critical/恶意脚本执行/false | critical/恶意脚本执行/false | 无 |
| EVENT-002 | low/异常登录/true | low/误报/true | 类型修正 |
| EVENT-003 | medium/通用异常行为/false | high/异常外联/false | 风险+类型 |
| EVENT-004 | critical/通用异常行为/false | high/横向移动前置/false | 风险+类型 |
| EVENT-005 | high/通用异常行为/false | medium/异常登录/false | 风险+类型 |
| EVENT-006 | critical/通用异常行为/false | critical/WebShell 攻击/false | 类型 |
| EVENT-007 | medium/异常登录/false | critical/勒索软件加密/false | 风险+类型 |
| EVENT-008 | low/通用异常行为/**true** | high/凭据转储/**false** | 全部 |
| EVENT-009 | high/通用异常行为/false | low/异常登录/false | 风险 |
| EVENT-010 | high/通用异常行为/false | high/恶意载荷投递/false | 类型 |

## 预筛器分流统计（阶段 1 交付）

`evaluate` 输出含预筛统计（由 `evaluation/service.py` 汇总）：

```json
"prefilter": {
  "auto_close": 1,
  "auto_escalate": 6,
  "need_llm": 3,
  "prefilter_pass_rate": 0.7,
  "llm_call_savings_rate": 0.7
}
```

- `AUTO_CLOSE`：EVENT-002（白名单误报，0.1ms 关闭，不调 LLM）
- `AUTO_ESCALATE`：EVENT-001/004/006/007/008/010（毫秒级直接定级）
- `NEED_LLM`：EVENT-003/005/009（证据不足，走 DeepSeek 深度研判）

## 混合模式对比评测（todo.md 阶段 5.3，待做）

目标：对比三种模式的准确率与成本：

| 模式 | 逻辑 | 预期准确率 | 成本 |
|------|------|-----------|------|
| 纯规则引擎 | 硬编码标记计数 | 低 | 零 |
| 纯 LLM | 每事件都调 LLM | 高但慢 | 高 |
| 预筛 + LLM 混合 | 规则先筛，不确定才给 LLM | 最高且快 | 中 |

评测输出三列对比表 + 混淆矩阵。

## 如何运行

### CLI

```bash
python -m security_agent.cli evaluate
```

### Web

```bash
python -m security_agent.cli serve --port 8080
```

首页会直接显示评测面板。

## 输出结构

评测结果包含三部分：

- `summary`：总体指标汇总（含 prefilter 统计）
- `category_breakdown`：按场景类别统计
- `cases`：每个事件的逐条结果（含 `prefilter_decision`）

## 业界基准参考（todo.md 阶段 5）

| 基准 | 来源 | 内容 |
|------|------|------|
| [CyberSOCEval](https://github.com/CrowdStrike/CyberSOCEval_data) | CrowdStrike + Meta | 恶意软件分析 + 威胁情报推理 |
| [SecRespond](https://github.com/Alibaba-NLP/qqr) | 阿里巴巴 | Agent 级事件响应全流程 |
| [ExCyTIn-Bench](https://github.com/microsoft/ExCyTIn-Bench) | 微软 | 多步 SOC 调查 |
| [DFIR-Metric](https://github.com/DFIR-Metric) | 学术界 | 700 MCQ + 150 CTF + 500 取证 |

## 后续增强方向

- [x] 评测基准重标注（v2，已完成）
- [ ] 增加更多案例（扩到 20+）
- [ ] 多模式对比（规则 vs LLM vs 混合，阶段 5.3）
- [ ] 多 LLM 对比（DeepSeek vs Qwen）
- [ ] 评测报告导出（HTML/Markdown，阶段 5.4）
- [ ] 回归测试（改动后准确率不得下降，阶段 5.5）
