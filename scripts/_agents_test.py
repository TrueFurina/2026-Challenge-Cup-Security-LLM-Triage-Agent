"""阶段 3 多 Agent 协作测试。

用法: python scripts/_agents_test.py
验证：
1. 每个 Agent 独立可跑（TriageAgent / HuntAgent / RespondAgent / ReportAgent）
2. coordinator 全链路：Triage → Hunt → Respond → Report 数据流清晰
3. 失败降级：mock 一个 Agent 抛异常，链路不中断
4. CLI coordinate 命令可用
"""
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.agents.base import AgentInput, BaseAgent  # noqa: E402
from security_agent.agents.coordinator import AgentCoordinator  # noqa: E402
from security_agent.agents.impl import HuntAgent, ReportAgent, RespondAgent, TriageAgent  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def build_context(app):
    """构建与 coordinate_event 相同的工具观测上下文。"""
    event = app.intake_service.get_event("EVENT-001")
    knowledge_items, _ = app.knowledge_hub.retrieve_knowledge(event)
    context = {
        "knowledge_hub": app.knowledge_hub,
        "tool_registry": app.tool_registry,
    }
    asset_tool = app.tool_registry.get("asset_lookup")
    log_tool = app.tool_registry.get("log_lookup")
    intel_tool = app.tool_registry.get("intel_lookup")
    history_tool = app.tool_registry.get("history_alert_lookup")
    fp_tool = app.tool_registry.get("false_positive_check")
    context["asset_observation"] = asset_tool.run(event=event, knowledge_hub=app.knowledge_hub)
    context["log_observation"] = log_tool.run(event=event, knowledge_hub=app.knowledge_hub)
    context["intel_observation"] = intel_tool.run(event=event, knowledge_hub=app.knowledge_hub)
    context["history_observation"] = history_tool.run(event=event, knowledge_hub=app.knowledge_hub)
    context["false_positive_observation"] = fp_tool.run(
        event=event,
        knowledge_hub=app.knowledge_hub,
        asset_observation=context["asset_observation"],
        log_observation=context["log_observation"],
    )
    context["playbook_matcher"] = app.tool_registry.get("playbook_matcher")
    context["ticket_generator"] = app.tool_registry.get("ticket_generator")
    context["host_isolation_simulator"] = app.tool_registry.get("host_isolation_simulator")
    context["ioc_search"] = app.tool_registry.get("ioc_search")
    return event, knowledge_items, context


def single_agent_tests(app):
    print("== 1. 每个 Agent 独立可跑 ==")
    event, knowledge_items, context = build_context(app)
    plan = ["Monitor Agent 接收安全事件", "Context Agent 关联上下文", "Triage Agent 初步研判", "Report Agent 输出结论"]

    ai = AgentInput(event=event, context=context, knowledge_items=knowledge_items, plan=plan, llm=app.llm)
    out = TriageAgent().run(ai)
    check("TriageAgent 无 error", out.error == "", True)
    check("TriageAgent 有裁决数据", "risk_level" in out.data, True)

    # 将 Triage 输出注入 context，测 Hunt
    ctx2 = dict(context)
    ctx2["triage"] = out.data
    ai2 = AgentInput(event=event, context=ctx2, knowledge_items=knowledge_items, plan=plan, llm=app.llm)
    out2 = HuntAgent().run(ai2)
    check("HuntAgent 无 error", out2.error == "", True)
    check("HuntAgent 输出狩猎发现", isinstance(out2.data.get("hunt_findings"), list), True)

    # Respond
    ctx3 = dict(ctx2)
    ctx3["hunt"] = out2.data
    ai3 = AgentInput(event=event, context=ctx3, knowledge_items=knowledge_items, plan=plan, llm=app.llm)
    out3 = RespondAgent().run(ai3)
    check("RespondAgent 无 error", out3.error == "", True)
    check("RespondAgent 输出预案", bool(out3.data.get("playbook")), True)

    # Report
    ctx4 = dict(ctx3)
    ctx4["respond"] = out3.data
    ai4 = AgentInput(event=event, context=ctx4, knowledge_items=knowledge_items, plan=plan, llm=app.llm)
    out4 = ReportAgent().run(ai4)
    check("ReportAgent 无 error", out4.error == "", True)
    check("ReportAgent 输出报告", "report" in out4.data, True)
    check("报告含最终裁决", bool(out4.data["report"].get("verdict")), True)


def coordinator_tests(app):
    print("== 2. coordinator 全链路 ==")
    event, knowledge_items, context = build_context(app)
    from security_agent.agent.planner import build_plan

    ai = AgentInput(
        event=event,
        context=context,
        knowledge_items=knowledge_items,
        plan=build_plan(event),
        llm=app.llm,
    )
    result = AgentCoordinator().coordinate(ai)
    check("4 个 Agent 记录", len(result["agent_records"]), 4)
    check("链路顺序正确", [r["name"] for r in result["agent_records"]][0], "Triage Agent")
    check("全部 Agent 正常", result["agents_ok"], True)
    check("最终报告有事件类型", bool(result["final_report"].get("event_type")), True)
    check("总耗时 > 0", result["total_duration_ms"] > 0, True)


class _BrokenAgent(BaseAgent):
    name = "Broken Agent"
    role = "测试降级用"

    def run(self, agent_input):
        raise RuntimeError("模拟 Agent 故障")


def degradation_tests(app):
    print("== 3. 失败降级（fail-open） ==")
    event, knowledge_items, context = build_context(app)
    from security_agent.agent.planner import build_plan

    ai = AgentInput(
        event=event,
        context=context,
        knowledge_items=knowledge_items,
        plan=build_plan(event),
        llm=app.llm,
    )
    # 用 BrokenAgent 替换第一个 Agent，验证链路不中断
    result = AgentCoordinator(agents=[_BrokenAgent(), HuntAgent(), RespondAgent(), ReportAgent()]).coordinate(ai)
    check("链路不中断（有记录）", len(result["agent_records"]), 4)
    check("Broken Agent 标记 error", result["agent_records"][0]["error"] != "", True)
    check("后续 Agent 仍执行", result["agent_records"][1]["name"], "Hunt Agent")
    check("最终报告仍生成", bool(result["final_report"]), True)


def cli_tests():
    print("== 4. CLI coordinate 命令 ==")
    import subprocess

    r = subprocess.run(
        [sys.executable, "-m", "security_agent.cli", "coordinate", "--event-id", "EVENT-001"],
        capture_output=True, text=True, timeout=60, cwd=PROJECT_DIR,
    )
    check("CLI 退出码 0", r.returncode, 0)
    check("CLI 显示多 Agent 链路", "多 Agent 协作链路" in r.stdout, True)
    check("CLI 显示 Triage Agent", "Triage Agent" in r.stdout, True)
    check("CLI 显示最终报告", "最终报告" in r.stdout, True)


def main() -> int:
    from security_agent.app import build_app
    from security_agent.llm.mock import MockLLM

    app = build_app()
    app.llm = MockLLM()  # 强制 Mock，避免真实 API 依赖

    single_agent_tests(app)
    coordinator_tests(app)
    degradation_tests(app)
    cli_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
