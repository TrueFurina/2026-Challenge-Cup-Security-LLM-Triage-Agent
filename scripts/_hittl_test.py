"""阶段 2 置信度门控 + HITL 测试。

用法: python scripts/_hittl_test.py
验证：
1. 置信度数值映射（CONFIDENCE_SCORES: high=0.9/medium=0.7/low=0.5）
2. LLM 输出置信度归一化（_parse_llm_result：非法值回退 medium，合法值保留）
3. 工单门控：低置信 → 待复核记录（REVIEW-），高置信 → P 级工单（TICKET-）
4. 端到端（Mock）：EVENT-002 预筛 AUTO_CLOSE → confidence high → auto_reviewed
5. 复核回写文件 review_feedback.jsonl 存在且 JSON 可解析
"""
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.ai.triage import CONFIDENCE_SCORES, _parse_llm_result  # noqa: E402
from security_agent.agent.models import SecurityEvent, ToolObservation  # noqa: E402
from security_agent.tools.implementations import TicketGeneratorTool  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def make_event(**kwargs) -> SecurityEvent:
    base = dict(
        id="EVENT-TEST",
        title="测试事件",
        severity="medium",
        source_ip="10.0.0.1",
        host="HOST-01",
        user="user1",
        process="unknown.exe",
        behavior="待研判行为",
        raw_log="no suspicious markers",
    )
    base.update(kwargs)
    return SecurityEvent(**base)


def conf_parse(payload: dict):
    """构造最小观测对象后调用 _parse_llm_result。"""
    event = make_event()
    empty_obs = ToolObservation(tool_name="t", summary="s", details=[])
    return _parse_llm_result(
        payload=payload,
        event=event,
        intel_observation=empty_obs,
        false_positive_observation=empty_obs,
        knowledge_items=[],
        plan=[],
    )


def mapping_tests():
    print("== 1. 置信度数值映射 ==")
    check("high=0.9", CONFIDENCE_SCORES.get("high"), 0.9)
    check("medium=0.7", CONFIDENCE_SCORES.get("medium"), 0.7)
    check("low=0.5", CONFIDENCE_SCORES.get("low"), 0.5)


def normalize_tests():
    print("== 2. LLM 置信度归一化（_parse_llm_result） ==")
    core = conf_parse({"confidence": "HIGH", "risk_level": "medium"})
    check("大写 HIGH → high", core["confidence"], "high")
    check("HIGH → score 0.9", core["confidence_score"], 0.9)

    core = conf_parse({"confidence": "weird", "risk_level": "medium"})
    check("非法值 → medium", core["confidence"], "medium")
    check("非法值 → score 0.7", core["confidence_score"], 0.7)

    core = conf_parse({"confidence": "low", "risk_level": "medium"})
    check("low 保留", core["confidence"], "low")
    check("low → score 0.5", core["confidence_score"], 0.5)


def ticket_gate_tests():
    print("== 3. 工单门控（TicketGeneratorTool） ==")
    tool = TicketGeneratorTool()
    event = make_event()

    low = tool.run(event=event, analysis={"confidence": "low", "risk_level": "high", "event_type": "测试", "verdict": "v"})
    check("低置信 → REVIEW- 记录", low.summary.startswith("已生成待复核记录 REVIEW-"), True)
    check("低置信 → 无 P 级工单", "TICKET-" not in low.summary, True)
    check("低置信 → 提示人工复核", any("人工复核" in d for d in low.details), True)

    review_flag = tool.run(event=event, analysis={"needs_human_review": True, "risk_level": "critical", "event_type": "测试", "verdict": "v"})
    check("needs_human_review=True → 待复核", review_flag.summary.startswith("已生成待复核记录"), True)

    high = tool.run(event=event, analysis={"confidence": "high", "risk_level": "critical", "event_type": "测试", "verdict": "v"})
    check("高置信 → TICKET- 工单", high.summary.startswith("已生成模拟工单 TICKET-"), True)
    check("高置信 → P1 优先级", any("优先级: P1" in d for d in high.details), True)


def e2e_tests():
    print("== 4. 端到端（Mock 模式，EVENT-002 预筛 AUTO_CLOSE） ==")
    from security_agent.app import build_app
    from security_agent.llm.mock import MockLLM

    app = build_app()
    app.llm = MockLLM()
    result = app.triage_event("EVENT-002")
    check("预筛决策 AUTO_CLOSE", result.prefilter_decision, "AUTO_CLOSE")
    check("置信度 high", result.confidence, "high")
    check("confidence_score 0.9", result.confidence_score, 0.9)
    check("review_status auto_reviewed", result.review_status, "auto_reviewed")
    check("needs_human_review False", result.needs_human_review, False)


def feedback_file_tests():
    print("== 5. 复核回写文件 ==")
    path = os.path.join(PROJECT_DIR, "security_agent", "data", "review_feedback.jsonl")
    check("review_feedback.jsonl 存在", os.path.exists(path), True)
    if os.path.exists(path):
        import json
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        check("文件可解析且非空", len(records) > 0, True)
        check("记录含 event_id/decision", {"event_id", "decision"} <= set(records[0]), True)


def main() -> int:
    mapping_tests()
    normalize_tests()
    ticket_gate_tests()
    e2e_tests()
    feedback_file_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
