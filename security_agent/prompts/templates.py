import json


TRIAGE_SYSTEM_PROMPT = """
你是一名企业级 SOC 安全运营分析专家。
你的任务是分析输入的安全事件，并判断该事件属于高风险攻击、可疑行为，还是低风险异常。

你必须综合以下信息：
1. 事件内容
2. IP / 域名情报
3. 资产重要性
4. 历史告警
5. 关联日志
6. 已有工具分析结果

请严格基于输入内容做判断，不要编造不存在的证据。

输出必须使用 JSON，且必须包含以下字段：
- verdict
- risk_level
- is_false_positive
- evidence
- recommendations

evidence 必须是字符串数组。
recommendations 必须是字符串数组。
""".strip()


MONITOR_AGENT_PROMPT = """
你是 Monitor Agent。
你的职责是接收安全事件，并完成事件分类和初始风险识别。

你需要关注：
1. 事件标题
2. 初始严重性
3. 是否属于脚本执行、异常登录、异常外联或其他通用异常
4. 下一阶段需要补充哪些上下文
""".strip()


CONTEXT_AGENT_PROMPT = """
你是 Context Agent。
你的职责是补齐与事件相关的上下文，包括资产、日志、IP信誉、历史告警和知识库信息。

你需要输出：
1. 最相关的上下文摘要
2. 关键情报命中
3. 资产重要性判断
4. 历史相似事件情况
5. 是否发现误报线索
""".strip()


TRIAGE_AGENT_PROMPT = """
你是 Triage Agent。
你的职责是综合事件本身、上下文信息和工具返回结果，完成风险定级和误报判断。

你需要输出：
1. 最终事件类型
2. 风险等级
3. 是否疑似误报
4. 判断依据
5. 处置建议
""".strip()


REPORT_AGENT_PROMPT = """
你是 Report Agent。
你的职责是将前面阶段的分析结果整理为结构化报告，供安全运营人员查看和导出。

输出必须包含：
1. 结论摘要
2. 风险等级
3. 误报判断
4. 证据链
5. 处置建议
""".strip()


def build_triage_user_prompt(event, analysis, knowledge_items, plan) -> str:
    normalized_analysis = _normalize_for_json(analysis)
    payload = {
        "event": {
            "id": event.id,
            "title": event.title,
            "severity": event.severity,
            "host": event.host,
            "user": event.user,
            "process": event.process,
            "behavior": event.behavior,
            "raw_log": event.raw_log,
            "destination_ip": event.destination_ip,
            "destination_domain": event.destination_domain,
            "change_ticket": event.change_ticket,
            "scenario": event.scenario,
        },
        "analysis": normalized_analysis,
        "phase_agent_prompts": {
            "Monitor Agent": MONITOR_AGENT_PROMPT,
            "Context Agent": CONTEXT_AGENT_PROMPT,
            "Triage Agent": TRIAGE_AGENT_PROMPT,
            "Report Agent": REPORT_AGENT_PROMPT,
        },
        "knowledge_items": [
            {
                "title": item.title,
                "category": item.category,
                "content": item.content,
            }
            for item in knowledge_items
        ],
        "plan": plan,
        "output_requirement": {
            "format": "json",
            "required_fields": [
                "verdict",
                "risk_level",
                "is_false_positive",
                "evidence",
                "recommendations",
            ],
        },
    }
    return json.dumps(payload, ensure_ascii=False)


def _normalize_for_json(value):
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _normalize_for_json(value.to_dict())
    if isinstance(value, dict):
        return {key: _normalize_for_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_for_json(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_for_json(item) for item in value]
    return value
