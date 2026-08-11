"""阶段 5 评测体系测试（5.2-5.5）。

用法: python scripts/_eval_test.py
验证：
1. 新评测维度存在：误报关闭率 / 成本估算 / 置信度校准
2. 三模式对比结构：evaluate_modes 返回 rules/llm/hybrid 三模式
3. 纯规则模式 LLM 调用为 0（成本归零）
4. 混淆矩阵计算正确（构造已知结果验证 2×2 计数）
5. report 导出 md/html 文件可读且含关键章节
"""
import json
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

import security_agent.ai.triage as triage_mod  # noqa: E402
from security_agent.reporting.render import (  # noqa: E402
    _confusion_markdown,
    render_evaluation_report,
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


def fake_ai_chat_json(messages, system=None, temperature=0.1, max_tokens=2000):
    """模拟 AI 返回固定 JSON（避免真实 API，保证可复现）。"""
    text = messages[0]["content"] if messages else ""
    has_mal = any(m in text.lower() for m in ("encodedcommand", "webshell", "beacon", "cred"))
    return {
        "event_type": "恶意脚本执行" if has_mal else "通用异常行为",
        "risk_level": "critical" if has_mal else "medium",
        "confidence": "high",
        "risk_score": 85 if has_mal else 45,
        "is_false_positive": False,
        "verdict": "mock 研判",
        "reasoning_summary": ["mock 依据"],
        "evidence": ["mock 证据"],
        "recommendations": ["mock 建议"],
    }


def dimension_tests(app):
    print("== 1. 新评测维度存在 ==")
    report = app.evaluation_service.evaluate(app)
    s = report["summary"]
    check("summary 含误报关闭率", "false_positive_closure_rate" in s, True)
    check("summary 含成本估算", "cost_estimate" in s, True)
    check("summary 含置信度校准", "confidence_calibration" in s, True)
    check("误报关闭率为数值", isinstance(s["false_positive_closure_rate"], float), True)
    check("成本估算为数值", isinstance(s["cost_estimate"], float), True)
    check("置信度校准为 dict", isinstance(s["confidence_calibration"], dict), True)
    check("case 含 actual_confidence", "actual_confidence" in report["cases"][0], True)


def mode_comparison_tests(app):
    print("== 2. 三模式对比 ==")
    result = app.evaluation_service.evaluate_modes(app)
    modes = result["comparison"]
    check("包含 rules 模式", "rules" in modes, True)
    check("包含 llm 模式", "llm" in modes, True)
    check("包含 hybrid 模式", "hybrid" in modes, True)
    for name in ("rules", "llm", "hybrid"):
        check(f"{name} 有 pass_rate", "pass_rate" in modes[name], True)
        check(f"{name} 有 cost_estimate", "cost_estimate" in modes[name], True)
    check("纯规则 LLM 调用为 0", modes["rules"]["llm_calls"], 0)
    check("纯规则成本为 0", modes["rules"]["cost_estimate"], 0.0)
    check("混合模式 LLM 调用 < 10", modes["hybrid"]["llm_calls"] < 10, True)
    check("顶层透出 cases", "cases" in result and len(result["cases"]) > 0, True)


def confusion_tests():
    print("== 3. 混淆矩阵计算 ==")
    cases = [
        {"expected_false_positive": True, "actual_false_positive": True},
        {"expected_false_positive": True, "actual_false_positive": True},
        {"expected_false_positive": True, "actual_false_positive": False},
        {"expected_false_positive": False, "actual_false_positive": True},
        {"expected_false_positive": False, "actual_false_positive": False},
    ]
    md = _confusion_markdown(cases)
    check("矩阵含 2 行", md.count("| 判定"), 2)
    check("TP=2 命中", "| 2 |" in md, True)
    check("FN=1 命中", "| 1 |" in md, True)


def report_export_tests(app):
    print("== 4. report 导出 ==")
    import glob

    result = app.evaluation_service.evaluate_modes(app)
    md = render_evaluation_report(result, "md")
    html = render_evaluation_report(result, "html")
    check("md 含三模式对比", "三模式对比" in md, True)
    check("md 含混淆矩阵", "混淆矩阵" in md, True)
    check("md 含逐案例明细", "逐案例明细" in md, True)
    check("html 含 table", "<table>" in html, True)
    check("html 含混淆矩阵", "混淆矩阵" in html, True)


def main() -> int:
    triage_mod.ai_chat_json = fake_ai_chat_json
    from security_agent.app import build_app
    from security_agent.llm.mock import MockLLM

    app = build_app()
    app.llm = MockLLM()

    dimension_tests(app)
    mode_comparison_tests(app)
    confusion_tests()
    report_export_tests(app)
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
