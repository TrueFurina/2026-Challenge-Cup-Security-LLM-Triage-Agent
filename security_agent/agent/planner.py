from security_agent.agent.models import SecurityEvent


def build_plan(event: SecurityEvent) -> list[str]:
    plan = [
        "Monitor Agent 接收安全事件并完成场景识别",
        "Context Agent 关联知识、资产、日志和情报上下文",
        "Triage Agent 聚合工具观测并执行初步研判",
        "Report Agent 输出结构化结论、误报判断和处置建议",
    ]
    corpus = " ".join([event.process, event.behavior, event.raw_log]).lower()
    if "powershell" in corpus or "encodedcommand" in corpus:
        plan.insert(2, "Context Agent 补充高风险脚本执行痕迹识别")
    if event.change_ticket:
        plan.insert(3, "Triage Agent 校验变更单和维护窗口是否支持误报判断")
    return plan
