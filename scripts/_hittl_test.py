"""阶段 2 置信度门控 + HITL 测试。

用法: python scripts/_hittl_test.py
验证：
1. 置信度数值映射（CONFIDENCE_SCORES: high=0.9/medium=0.7/low=0.5）
2. LLM 输出置信度归一化（_parse_llm_result：非法值回退 medium，合法值保留）
3. 工单门控：低置信 → 待复核记录（REVIEW-），高置信 → P 级工单（TICKET-）
4. 端到端（Mock）：EVENT-002 预筛 AUTO_CLOSE → confidence high → auto_reviewed
5. 复核回写文件 review_feedback.jsonl 存在且 JSON 可解析
6. HumanFeedbackStore：写入校验 / latest / 摘要匹配 / 旧格式与脏数据容错
7. 读回闭环（集成）：确认 → human_confirmed；驳回相同结论 → human_rejected
   + 强制挂起 + 被驳回裁决不写入误报记忆
8. 评测沙箱对 feedback 的读隔离（与 memory 同口径）
"""
import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.ai.triage import CONFIDENCE_SCORES, _parse_llm_result  # noqa: E402
from security_agent.agent.models import SecurityEvent, ToolObservation  # noqa: E402
from security_agent.hitl import HumanFeedbackStore  # noqa: E402
from security_agent.memory import MemoryStore  # noqa: E402
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
    # 复用评测沙箱：本测试的 triage 裁决不应写入真实记忆 / ledger
    with app.evaluation_sandbox():
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


VERDICT = dict(event_type="恶意脚本执行", risk_level="critical", is_false_positive=False)


def feedback_store_tests(tmp: Path):
    print("== 6. HumanFeedbackStore 读写 ==")
    path = tmp / "feedback.jsonl"
    store = HumanFeedbackStore(path=path)
    check("初始为空", store.count(), 0)
    check("无记录 → latest 为 None", store.latest("EVENT-001"), None)

    check("合法写入返回 True", store.append("EVENT-001", "confirm", **VERDICT), True)
    check("非法 decision 被拒", store.append("EVENT-001", "approve"), False)
    check("缺 event_id 被拒", store.append("", "confirm"), False)
    check("非法写入未落盘", store.count(), 1)

    store.append("EVENT-001", "reject", note="证据不足，应为误报", **VERDICT)
    latest = store.latest("EVENT-001")
    check("latest 取最近一条", latest.decision, "reject")
    check("latest 保留复核意见", latest.note, "证据不足，应为误报")
    check("history 累计 2 条", len(store.history("EVENT-001")), 2)
    check("reject_count", store.reject_count("EVENT-001"), 1)
    check("带裁决摘要", latest.has_verdict(), True)
    check("摘要匹配同一结论", latest.matches_verdict(**VERDICT), True)
    check("摘要不匹配另一结论", latest.matches_verdict("误报", "low", True), False)


def dirty_data_tests(tmp: Path):
    """旧格式（无摘要）与脏数据必须容错，且脏数据不得污染门控。"""
    print("== 6b. 旧格式与脏数据容错 ==")
    path = tmp / "dirty.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "EVENT-OLD", "decision": "confirm", "note": "旧记录", "timestamp": "2026-08-10T00:00:00Z"}),
                "{not json}",
                json.dumps({"event_id": "EVENT-BAD", "decision": "maybe", "note": "非法决定值"}),
                # 可解析但不是对象——曾是一条「修了却没用例覆盖」的分支（变异后 rc=0）
                "[1, 2, 3]",
                json.dumps({"event_id": "EVENT-NEW", "decision": "reject", "event_type": "误报", "risk_level": "low", "is_false_positive": True}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    store = HumanFeedbackStore(path=path)
    check("有效记录计数 2（旧+新）", store.count(), 2)
    check("坏行未致异常且被跳过", store.latest("EVENT-BAD"), None)
    old = store.latest("EVENT-OLD")
    check("旧格式可读", old.decision, "confirm")
    check("旧格式无摘要 → has_verdict=False", old.has_verdict(), False)
    check("旧格式摘要恒不匹配（不误配门控）", old.matches_verdict("确认什么", "low", True), False)
    check("新格式摘要可读", store.latest("EVENT-NEW").matches_verdict("误报", "low", True), True)

    # 坏行 / 非法 decision 必须**可见**：此前全是静默 `continue`，操作员的"驳回"
    # 在界面上写进去了、链路里却被 `latest()` 当成不存在 → Reviewer 保持自动裁决，
    # 全过程无任何报错。这是 HITL 闭环最难自查的一种失效。
    check("跳过行数被记录（坏行 + 非对象 + 非法 decision）", store.skipped_lines, 3)
    check("驳回结论仍可读回（未被坏行吞掉）", store.latest("EVENT-NEW").decision, "reject")
    clean = tmp / "clean_fb.jsonl"
    clean.write_text(
        json.dumps({"event_id": "EVENT-OK", "decision": "confirm"}) + "\n",
        encoding="utf-8",
    )
    clean_store = HumanFeedbackStore(path=clean)
    clean_store.count()  # 必须先真正触发一次加载，否则 skipped_lines 恒为初始值 0
    check("完好文件不误报跳过", clean_store.skipped_lines, 0)


def readback_integration_tests(tmp: Path):
    """== 7. HITL 读回闭环（集成）==

    单测覆盖不到的是接线：`review_feedback.jsonl` 过去被 Web 只写不读，人工点下
    「驳回」对该事件的再次研判毫无影响——面板显示「已人工驳回」，Agent 侧却照旧
    给出同一结论并标 auto_reviewed。本测试从 `app._triage` 入口出发锁死读回。

    隔离说明：**刻意不用 `app.evaluation_sandbox()`**——沙箱会把 `record_history`
    一并关掉，而本测试的断言恰恰是「写不写记忆」（`首次研判写入记忆: count == 1`），
    实测套上沙箱后 3 条断言立刻 FAIL。故此处手动隔离：memory / feedback 指向
    临时库 + **关闭 ledger 写**。ledger 不参与本测试任何断言，但 `app._triage`
    会覆写生产审计台账（实测 `ledger/EVENT-003.json` 的 mtime 被改写）——
    这正是此前漏掉、也是"每处调用方各自记得关"漂移的又一实例。
    """
    print("== 7. 读回闭环（集成）==")
    import security_agent.ai.triage as triage_mod
    from security_agent.app import build_app

    captured: dict = {}

    def fake_chat(messages, **kwargs):
        captured["prompt"] = messages[0]["content"]
        return None  # 触发规则回退：结论确定可复现，且本测试零网络零成本

    original = triage_mod.ai_chat_json
    triage_mod.ai_chat_json = fake_chat
    try:
        app = build_app()
        # 临时记忆 + 临时反馈库：断言「写不写记忆」时不能碰真实运行时数据
        app.feedback = HumanFeedbackStore(path=tmp / "it_feedback.jsonl")
        app.memory = MemoryStore(path=tmp / "it_history.jsonl")
        # ledger 不参与本测试断言，但 _triage 会写它 → 关掉真实证据的写入
        app.record_ledger = False

        event = app.intake_service.get_event("EVENT-003")

        # ① 无人复核：常规门控，不得出现 human_* 状态
        baseline = app._triage(event)
        check("无反馈 → review_status 非人工态",
              baseline.review_status in ("auto_reviewed", "pending_review"), True)
        check("无反馈 → human_feedback 为空", baseline.human_feedback, {})
        check("首次研判写入记忆", app.memory.count(), 1)
        memory_after_first = app.memory.count()

        verdict = dict(
            event_type=baseline.event_type,
            risk_level=baseline.risk_level,
            is_false_positive=baseline.is_false_positive,
        )

        # ② 人工确认该裁决 → human_confirmed 并解除复核挂起
        app.feedback.append(event.id, "confirm", note="采纳", **verdict)
        app._triage(event)  # 记忆会再写一条（无驳回），先只关心状态
        result_confirm = app._triage(event)
        check("确认后 → human_confirmed", result_confirm.review_status, "human_confirmed")
        check("确认后 → 解除复核挂起", result_confirm.needs_human_review, False)
        # 用 .get 而非下标：读回一旦失效，这里必须**报 FAIL**而不是抛 KeyError
        # 把剩余断言整段跳过（变异验证时这个问题掩盖了 4 条本该失败的断言）。
        check("确认后 → human_feedback 透出 decision", result_confirm.human_feedback.get("decision"), "confirm")

        # ③ 人工驳回同一裁决 → human_rejected + 强制挂起
        app.feedback.append(event.id, "reject", note="结论有误", **verdict)
        result_reject = app._triage(event)
        check("驳回同一结论 → human_rejected", result_reject.review_status, "human_rejected")
        check("驳回同一结论 → 强制挂起待仲裁", result_reject.needs_human_review, True)
        check("驳回理由写入 reasoning",
              any("重复了被否定的裁决" in item for item in result_reject.reasoning_summary), True)
        check("被驳回 → 本次裁决不写入误报记忆（污染防线）",
              app.memory.count(), memory_after_first + 2)
        check("驳回说明写入 reasoning（不写记忆的原因）",
              any("未写入误报记忆" in item for item in result_reject.reasoning_summary), True)

        # ④ 反馈已注入提示词（"人说了什么"必须真的进到模型输入）
        prompt = captured.get("prompt", "")
        check("提示词含人工复核反馈章节", "人工复核反馈" in prompt, True)
        check("提示词含驳回动作", "驳回该裁决" in prompt, True)
        check("提示词含复核意见", "结论有误" in prompt, True)

        # ⑤ 摘要不匹配（人复核的是另一版结论）→ 不套用上次结论的状态
        app.feedback.append(event.id, "confirm", note=",", event_type="误报", risk_level="low", is_false_positive=True)
        result_other = app._triage(event)
        check("摘要不符 → 状态回落为 Agent 自判",
              result_other.review_status in ("auto_reviewed", "pending_review", "human_confirmed"), True)
        check("摘要不符 → 不等于 human_rejected", result_other.review_status, "pending_review")
    finally:
        triage_mod.ai_chat_json = original


def sandbox_isolation_tests():
    """== 8. 评测沙箱运行时不变量（feedback / ledger / 研判历史）==

    同 memory：本机运营产生的 `review_feedback.jsonl` 属生产数据。若评测期仍被
    读取，「同一份代码」会因机器复盘历史不同而给出不同数字，冻结集成绩不可复现。

    2026-10-14 扩展：只断言 feedback 是一项**盲区**——沙箱真正的契约是「运行时产物
    字节级零变化」，而 §7 那条漏关 ledger 的路径恰好从这条盲区里溜了过去。
    现改为对整个运行时产物集合做快照比对（共用 `scripts/_runtime_isolation.py`）。
    """
    print("== 8. 评测沙箱运行时不变量（feedback / ledger / 研判历史）==")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _runtime_isolation import RUNTIME_PATHS, drift, snapshot

    from security_agent.app import build_app

    app = build_app()
    real_path = app.feedback.path
    before = snapshot()
    before_bytes = real_path.read_bytes() if real_path.exists() else b""
    before_count = app.feedback.count()
    with app.evaluation_sandbox():
        check("沙箱内 feedback 指向临时库", app.feedback.count(), 0)
        check("沙箱内读不到真实反馈", app.feedback.latest("EVENT-002"), None)
    check("沙箱外恢复真实 feedback 库", app.feedback.count(), before_count)
    # 真实库字节级未变动（沙箱内的一切读写都不得落到生产数据文件）
    check(
        "真实 review_feedback.jsonl 字节未变动",
        (real_path.read_bytes() if real_path.exists() else b"") == before_bytes,
        True,
    )
    check(
        f"全部 {len(RUNTIME_PATHS)} 类运行时产物字节未变动（含 ledger 与研判历史）",
        drift(before, snapshot()),
        [],
    )


def main() -> int:
    global FAIL
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _runtime_isolation import format_report, isolated_runtime

    # 整体防护：脚本**全程**（不只沙箱区间）都不得改写运行时产物。
    # 只测沙箱自身不够——§7 那条漏关 ledger 的路径在沙箱之外，
    # 靠"单独测沙箱"永远照不出来。这里用前后快照比对兜底，且一旦漂移
    # **自动还原**：即使本脚本将来再退回污染状态，也不会留下脏数据。
    with isolated_runtime(disable_writes=False) as report:
        mapping_tests()
        normalize_tests()
        ticket_gate_tests()
        e2e_tests()
        feedback_file_tests()
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            feedback_store_tests(tmp)
            dirty_data_tests(tmp)
            readback_integration_tests(tmp)
        sandbox_isolation_tests()

    print(f"\n[运行时产物] {format_report(report)}")
    if report.drift:
        FAIL += 1

    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
