"""阶段 3 多 Agent 协作测试（四角色决策闭环）。

用法: python scripts/_agents_test.py
验证：
1. 每个 Agent 独立可跑（Planner / Classifier / Triage / Reviewer）
2. coordinator 全链路：Planner → Classifier → Triage → Reviewer 数据流清晰
3. 失败降级：mock 一个 Agent 抛异常，链路不中断且 Reviewer 仍产出裁决
4. CLI coordinate 命令可用且展示四角色
"""
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from security_agent.console import use_utf8_stdio  # noqa: E402
use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩
os.chdir(PROJECT_DIR)

from security_agent.agents.base import AgentInput, BaseAgent  # noqa: E402
from security_agent.agents.coordinator import AgentCoordinator  # noqa: E402
from security_agent.agents.impl import (  # noqa: E402
    ClassifierAgent,
    PlannerAgent,
    ReviewerAgent,
    TriageAgent,
)

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def build_context(app, event_id="EVENT-001"):
    """构建与 _triage 相同的工具观测上下文。"""
    event = app.intake_service.get_event(event_id)
    knowledge_items, _ = app.knowledge_hub.retrieve_knowledge(event)
    kh = app.knowledge_hub
    ao = app.tool_registry.get("asset_lookup").run(event=event, knowledge_hub=kh)
    lo = app.tool_registry.get("log_lookup").run(event=event, knowledge_hub=kh)
    io = app.tool_registry.get("intel_lookup").run(event=event, knowledge_hub=kh)
    ho = app.tool_registry.get("history_alert_lookup").run(event=event, knowledge_hub=kh)
    fo = app.tool_registry.get("false_positive_check").run(
        event=event, knowledge_hub=kh, asset_observation=ao, log_observation=lo
    )
    pf = app.prefilter_engine.prefilter(
        event=event, asset_observation=ao, intel_observation=io,
        false_positive_observation=fo, log_observation=lo, history_observation=ho,
    )
    context = {
        "knowledge_hub": kh,
        "tool_registry": app.tool_registry,
        "asset_observation": ao,
        "log_observation": lo,
        "intel_observation": io,
        "history_observation": ho,
        "false_positive_observation": fo,
        "tool_observations": [ao, lo, io, ho, fo],
        "prefilter_result": pf,
        "force_rule_fallback": False,
    }
    return event, knowledge_items, context


def single_agent_tests(app):
    print("== 1. 每个 Agent 独立可跑 ==")
    event, knowledge_items, context = build_context(app)

    # Planner
    out_p = PlannerAgent().run(AgentInput(event=event, context=context, knowledge_items=knowledge_items, plan=[], llm=app.llm))
    check("PlannerAgent 无 error", out_p.error == "", True)
    check("PlannerAgent 产出 plan 列表", isinstance(out_p.data.get("plan"), list) and len(out_p.data["plan"]) > 0, True)

    # Classifier（依赖 prefilter_result）
    ctx_c = dict(context)
    ctx_c["planner"] = out_p.data
    out_c = ClassifierAgent().run(AgentInput(event=event, context=ctx_c, knowledge_items=knowledge_items, plan=[], llm=app.llm))
    check("ClassifierAgent 无 error", out_c.error == "", True)
    check("ClassifierAgent 产出 decision", bool(out_c.data.get("decision")), True)

    # Triage（依赖 planner plan）
    ctx_t = dict(ctx_c)
    ctx_t["classifier"] = out_c.data
    out_t = TriageAgent().run(AgentInput(event=event, context=ctx_t, knowledge_items=knowledge_items, plan=[], llm=app.llm))
    check("TriageAgent 无 error", out_t.error == "", True)
    check("TriageAgent 有裁决数据", "risk_level" in out_t.data, True)

    # Reviewer（依赖 classifier + triage）
    ctx_r = dict(ctx_t)
    ctx_r["triage"] = out_t.data
    out_r = ReviewerAgent().run(AgentInput(event=event, context=ctx_r, knowledge_items=knowledge_items, plan=[], llm=app.llm))
    check("ReviewerAgent 无 error", out_r.error == "", True)
    check("ReviewerAgent 产出 final_decision", isinstance(out_r.data.get("final_decision"), dict), True)
    check("final_decision 含 event_type", bool(out_r.data["final_decision"].get("event_type")), True)
    check("final_decision 含 review_status", bool(out_r.data["final_decision"].get("review_status")), True)
    # 防回归：final_decision 的 plan 由 Reviewer 从 Planner 产出继承。该行曾在一次
    # 「并入 HITL 门控」的编辑里被连带删掉，而当时无任何断言覆盖——下令
    # AnalysisResult.plan_steps 静默变空。此处锁死「Reviewer 必须继承 Planner 的 plan」。
    check("final_decision 继承 planner plan（非空）",
          bool(out_r.data["final_decision"].get("plan")), True)


def coordinator_tests(app):
    print("== 2. coordinator 全链路 ==")
    event, knowledge_items, context = build_context(app)
    ai = AgentInput(event=event, context=context, knowledge_items=knowledge_items, plan=[], llm=app.llm)
    result = AgentCoordinator().coordinate(ai)
    names = [r["name"] for r in result["agent_records"]]
    check("4 个 Agent 记录", len(result["agent_records"]), 4)
    check("链路顺序为 Planner→Classifier→Triage→Reviewer", names, ["Planner Agent", "Classifier Agent", "Triage Agent", "Reviewer Agent"])
    check("全部 Agent 正常", result["agents_ok"], True)
    final = result["context"].get("reviewer", {}).get("final_decision", {})
    check("最终裁决含事件类型", bool(final.get("event_type")), True)
    check("总耗时 > 0", result["total_duration_ms"] > 0, True)


class _BrokenAgent(BaseAgent):
    name = "Broken Agent"
    role = "测试降级用"

    def run(self, agent_input):
        raise RuntimeError("模拟 Agent 故障")


def degradation_tests(app):
    print("== 3. 失败降级（fail-open） ==")
    event, knowledge_items, context = build_context(app)
    ai = AgentInput(event=event, context=context, knowledge_items=knowledge_items, plan=[], llm=app.llm)
    result = AgentCoordinator(agents=[_BrokenAgent(), ClassifierAgent(), TriageAgent(), ReviewerAgent()]).coordinate(ai)
    check("链路不中断（有 4 记录）", len(result["agent_records"]), 4)
    check("Broken Agent 标记 error", result["agent_records"][0]["error"] != "", True)
    check("后续 Agent 仍执行", result["agent_records"][1]["name"], "Classifier Agent")
    final = result["context"].get("reviewer", {}).get("final_decision", {})
    check("Reviewer 仍产出最终裁决", bool(final.get("event_type")), True)


def cli_tests():
    print("== 4. CLI coordinate 命令 ==")
    import subprocess

    r = subprocess.run(
        [sys.executable, "-m", "security_agent.cli", "coordinate", "--event-id", "EVENT-001"],
        capture_output=True, text=True, timeout=60, cwd=PROJECT_DIR,
        # 子进程 stdout 是管道 ⇒ security_agent.console 会把它固定成 UTF-8。
        # 这里必须按键 UTF-8 解，否则在英文 Windows（cp1252）上会把中文解成乱码，
        # 下面几条「输出含中文」的断言全部假红。
        encoding="utf-8", errors="replace",
    )
    check("CLI 退出码 0", r.returncode, 0)
    check("CLI 显示四角色链路", "多 Agent 协作链路" in r.stdout, True)
    check("CLI 显示 Planner Agent", "Planner Agent" in r.stdout, True)
    check("CLI 显示 Reviewer Agent", "Reviewer Agent" in r.stdout, True)
    check("CLI 显示最终裁决", "最终裁决" in r.stdout, True)


def main() -> int:
    from security_agent.app import build_app

    app = build_app()

    single_agent_tests(app)
    coordinator_tests(app)
    degradation_tests(app)
    cli_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
