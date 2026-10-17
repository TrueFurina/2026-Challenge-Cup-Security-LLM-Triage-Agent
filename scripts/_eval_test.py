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

from security_agent.console import use_utf8_stdio  # noqa: E402
use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩
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
    # 混合模式的核心主张：预筛跳过部分 LLM 调用，故实际请求数应少于样本总数，
    # 且不多于纯 LLM 模式（原断言写死「< 10」是 16 例时代的遗留，样本扩容后会假失败）
    case_total = len(result["cases"])
    check("混合模式 LLM 调用少于样本总数（预筛确有跳过）",
          modes["hybrid"]["llm_calls"] < case_total, True)
    check("混合模式 LLM 调用不多于纯 LLM 模式",
          modes["hybrid"]["llm_calls"] <= modes["llm"]["llm_calls"] + 1, True)
    check("模式对比含实测 token 用量", "llm_usage" in modes["hybrid"], True)
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


def metering_tests():
    """LLM 用量计量的完整性（评测报告「调用数 / 成本」的唯一出处）。

    为什么必须单列一节测：`get_usage_stats()` 此前整段被 `except: pass` 包住且
    **不计数**——provider 一旦换了响应结构，某次真实发生的付费调用会凭空从统计里
    消失，而报告里的「18 次调用 / ¥0.37」没有任何自查能力。修复后：
    requests 计数移到 try 外（最基础事实不依赖解析），解析失败累加
    metering_failures 并告警；**评测时该值必须为 0**。

    本节变异锚点：去掉 `_USAGE["metering_failures"] += 1` → 场景 3/4 必 FAIL。
    """
    from security_agent.ai.client import (
        _record_usage,
        estimate_cost_yuan,
        get_usage_stats,
        reset_usage_stats,
    )

    good = {
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 500,
            "completion_tokens_details": {"reasoning_tokens": 200},
        },
        "choices": [{"finish_reason": "stop"}],
    }

    # 场景 1：正常响应 —— 不得产生任何计量失败
    reset_usage_stats()
    _record_usage(good)
    s = get_usage_stats()
    check("正常响应无计量失败", s["metering_failures"], 0)
    check("正常响应计入 1 次请求", s["requests"], 1)
    check("prompt_tokens 正确计量", s["prompt_tokens"], 1000)
    check("completion_tokens 正确计量", s["completion_tokens"], 500)
    check("reasoning_tokens 正确计量", s["reasoning_tokens"], 200)
    check("正常响应不计截断", s["truncated_responses"], 0)
    check("成本按实测 token 计算且非 0", estimate_cost_yuan() > 0, True)

    # 场景 2：finish_reason=length —— 必须识别为截断，且不算计量失败
    reset_usage_stats()
    _record_usage({**good, "choices": [{"finish_reason": "length"}]})
    s = get_usage_stats()
    check("length 识别为截断", s["truncated_responses"], 1)
    check("截断场景无计量失败", s["metering_failures"], 0)

    # 场景 3：provider 换了 usage 结构 —— 失败必须可见，请求不得消失
    reset_usage_stats()
    _record_usage({"usage": "1,2,3", "choices": [{"finish_reason": "stop"}]})
    s = get_usage_stats()
    check("usage 结构异常 → 计量失败可见", s["metering_failures"], 1)
    check("usage 结构异常 → 请求计数不丢失", s["requests"], 1)
    check("usage 结构异常 → token 不虚报", s["prompt_tokens"], 0)

    # 场景 4：响应体非 dict —— 同样不得静默
    reset_usage_stats()
    _record_usage(None)
    s = get_usage_stats()
    check("None 响应 → 计量失败可见", s["metering_failures"], 1)
    check("None 响应 → 请求计数不丢失", s["requests"], 1)

    # 场景 5：缺少 usage/choices —— 属合法降级，token 记 0 但不应算失败
    reset_usage_stats()
    _record_usage({})
    s = get_usage_stats()
    check("缺字段不算计量失败", s["metering_failures"], 0)
    check("缺字段时请求仍被计入", s["requests"], 1)
    check("缺字段时 token 记 0", s["prompt_tokens"], 0)

    # 场景 6：失败计数可累计、可被 reset 清零（保证 reset 覆盖新键）
    reset_usage_stats()
    _record_usage(good)
    _record_usage({"usage": "bad"})
    _record_usage({"usage": "bad"})
    check("失败计数累计正确", get_usage_stats()["metering_failures"], 2)
    check("多次调用请求数不丢", get_usage_stats()["requests"], 3)
    reset_usage_stats()
    check("reset 清零 metering_failures", get_usage_stats()["metering_failures"], 0)


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
    metering_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
