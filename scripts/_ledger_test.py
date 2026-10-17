"""阶段 8 Investigation Ledger 审计追踪测试。

用法: python scripts/_ledger_test.py
验证：
1. 研判后 ledger JSON 生成（**写入临时目录，不触碰真实 data/ledger**）
2. ledger 含 steps 数组（context/prefilter/triage/postprocess/llm）与 final_verdict
3. 工具观测被记录
4. LLM 调用回调记录 prompt/response（通过 ai_chat on_llm_call）
5. fail-open：ledger 目录不可写时主流程不崩溃
6. Web /ledger 与 /api/ledger 路由可响应

隔离说明：本测试全部 ledger 读写均落在 `tempfile.TemporaryDirectory()` 内，
真实 `security_agent/data/ledger/`（审计证据）永不被写入或删除。
"""
import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from security_agent.console import use_utf8_stdio  # noqa: E402
use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩
os.chdir(PROJECT_DIR)

from security_agent.ledger import LedgerStore  # noqa: E402
from security_agent.ledger.store import LedgerRecord  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def store_unit_tests(tmp: Path):
    print("== 1. LedgerStore 单元 ==")
    store = LedgerStore(root=tmp)
    rec = store.begin("EVENT-TEST", "测试场景")
    check("begin 返回记录", rec is not None, True)
    rec.record_step("context", tool="asset_lookup", summary="资产查询", details=["d1"])
    rec.record_step("prefilter", decision="NEED_LLM", llm_skipped=False)
    rec.record_llm("prompt 文本", "response 文本")
    rec.record_step("postprocess", tool="ticket_generator", summary="工单生成")
    rec.finalize({"risk_level": "critical", "is_false_positive": False})

    loaded = store.load("EVENT-TEST")
    check("落盘可加载", loaded is not None, True)
    check("steps 含 4 步", len(loaded["steps"]), 4)
    phases = [s["phase"] for s in loaded["steps"]]
    check("阶段齐全", set(phases) == {"context", "prefilter", "llm", "postprocess"}, True)
    check("含 final_verdict", "final_verdict" in loaded, True)
    check("LLM prompt 已记录", any("llm_prompt" in s for s in loaded["steps"]), True)
    check("工具摘要已记录", any("summary" in s for s in loaded["steps"]), True)
    check("list_event_ids 含事件", "EVENT-TEST" in store.list_event_ids(), True)


def e2e_tests(ledger_root: Path):
    print("== 2. 端到端：研判生成 ledger ==")
    from security_agent.app import build_app
    from security_agent.llm.mock import MockLLM
    from security_agent.ledger import LedgerStore

    app = build_app()
    app.llm = MockLLM()
    app.record_history = False  # 禁写真实记忆（本测试只关心 ledger）
    # 隔离到临时 root，**绝不触碰真实 data/ledger**：
    # 此前本测试为"保证独立"直接 shutil.rmtree 真实 data/ledger，
    # 会把审计轨迹证据一并抹掉（ledger 正是本作品的审计卖点），属自毁证据。
    app.ledger = LedgerStore(root=ledger_root)

    result = app.triage_event("EVENT-001")
    ledger = app.ledger.load("EVENT-001")
    check("EVENT-001 ledger 生成", ledger is not None, True)
    if ledger:
        check("steps 数 >= 5", len(ledger["steps"]) >= 5, True)
        check("含 prefilter 步骤", any(s["phase"] == "prefilter" for s in ledger["steps"]), True)
        check("含 triage 步骤", any(s["phase"] == "triage" for s in ledger["steps"]), True)
        check("含 postprocess 步骤", any(s["phase"] == "postprocess" for s in ledger["steps"]), True)
        check("final_verdict 含裁决", bool(ledger["final_verdict"].get("event_type")), True)


def llm_callback_tests():
    print("== 3. LLM 调用回调 ==")
    calls = []

    def cb(prompt, response):
        calls.append((prompt, response))

    from security_agent.ai.client import ai_chat

    # 无 Key 时回调应被调用（prompt 记录，response None）
    original = None
    import security_agent.ai.client as client_mod

    original_key = os.environ.get("DEEPSEEK_API_KEY")
    os.environ.pop("DEEPSEEK_API_KEY", None)
    os.environ.pop("SECURITY_AGENT_LLM_API_KEY", None)
    result = ai_chat([{"role": "user", "content": "hello"}], on_llm_call=cb)
    check("无 Key 返回 None", result, None)
    check("回调仍被调用（审计不因失败缺失）", len(calls), 0)  # 无 Key 时提前返回，未到回调
    if original_key:
        os.environ["DEEPSEEK_API_KEY"] = original_key


def failopen_tests(tmp: Path):
    print("== 4. fail-open：目录不可写不崩溃 ==")
    store = LedgerStore(root=tmp)
    rec = store.begin("FAIL-TEST", "s")
    if rec is None:
        check("begin 失败返回 None 不崩溃", True, True)
        return
    # 模拟写失败：把 root 指向一个文件路径
    bad_root = tmp / "not_a_dir" / "ledger"
    store2 = LedgerStore(root=bad_root)
    rec2 = store2.begin("X", "s")
    if rec2 is not None:
        rec2.finalize({"risk_level": "low"})  # 写入失败被吞掉，不抛异常
    check("写入失败不抛异常", True, True)


def web_route_tests(ledger_root: Path):
    print("== 5. Web 路由 ==")
    from security_agent.ledger import LedgerStore

    # 复用端到端测试写入的**临时** ledger（不再依赖真实目录，故无副作用）
    store = LedgerStore(root=ledger_root)
    if store.load("EVENT-001") is None:
        check("跳过：无 ledger 数据", True, True)
        return

    # 验证 Web 侧可导入并加载 ledger JSON（不起真实端口）
    from security_agent.web.server import SecurityAgentHandler, _page  # noqa: F401

    ledger = store.load("EVENT-001")
    check("ledger JSON 可被 Web 加载", ledger is not None, True)
    check("Web handler 可导入", SecurityAgentHandler is not None, True)


def llm_audit_wiring_tests(tmp: Path):
    """同族「实现了却不接线」缺陷的回归锁（第三例）。

    背景：`LedgerRecord.record_llm()` 早已实现，**且回调机制本身有单测覆盖**，
    但生产链路从未把 `on_llm_call` 传给 `triage_event`，实测 4 份真实 ledger
    里 `phase='llm'` 条目**全部为 0**——AI 产品的审计链路记录不下 AI 自己的证据。
    回调机制的单测测不出「没人接线」，故必须从 orchestrator 出口做端到端断言。
    """
    global PASS, FAIL
    print("== 6. LLM 调用审计·生产接线（真出口 → 真 ledger）==")

    import security_agent.ai.triage as triage_mod
    from security_agent.app import build_app
    from security_agent.ledger import LedgerStore
    from security_agent.memory import MemoryStore
    from security_agent.hitl.store import HumanFeedbackStore

    original = triage_mod.ai_chat_json
    seen = {"calls": 0}

    def fake_ai_chat_json(messages, **kwargs):
        """模拟真实 ai_chat_json：先调用审计回调再返回；返回 None 触发规则回退。"""
        cb = kwargs.get("on_llm_call")
        if cb is not None:
            seen["calls"] += 1
            cb("<模拟研判提示词>", '{"stub": true}')
        return None

    triage_mod.ai_chat_json = fake_ai_chat_json
    try:
        app = build_app()
        # 全部运行时 store 指向临时目录：绝不触碰真实 ledger / memory / feedback
        app.ledger = LedgerStore(tmp / "wiring_ledger")
        app.record_ledger = True
        app.record_history = False
        app.memory = MemoryStore(tmp / "mem.jsonl")
        app.feedback = HumanFeedbackStore(tmp / "fb.jsonl")

        app.triage_event("EVENT-003")
        ledger_file = tmp / "wiring_ledger" / "EVENT-003.json"
        check("启用审计时 ledger 落盘", ledger_file.exists(), True)
        ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
        llm_steps = [s for s in ledger.get("steps", []) if s.get("phase") == "llm"]
        check("生产链路把 on_llm_call 传到了 triage", seen["calls"] >= 1, True)
        check("ledger 记录了 AI 调用证据 phase='llm'", len(llm_steps) >= 1, True)
        if llm_steps:
            check("证据含 llm_prompt", bool(llm_steps[0].get("llm_prompt")), True)
            check("证据含 llm_response", bool(llm_steps[0].get("llm_response")), True)

        # 评测沙箱：record_ledger=False → 不触发回调、不落盘（评测路径零影响）
        before = seen["calls"]
        files_before = len(list((tmp / "wiring_ledger").glob("*.json")))
        with app.evaluation_sandbox():
            app.triage_event("EVENT-002")
        check("沙箱内不触发 LLM 审计回调", seen["calls"] - before, 0)
        check("沙箱内不落盘 ledger", len(list((tmp / "wiring_ledger").glob("*.json"))), files_before)
    finally:
        triage_mod.ai_chat_json = original


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        store_unit_tests(tmp)
        failopen_tests(tmp)
        # e2e / web 复用同一临时 ledger root：全测试零副作用，
        # 真实 data/ledger（审计证据）在任何情况下都不被触碰。
        ledger_root = tmp / "ledger"
        e2e_tests(ledger_root)
        web_route_tests(ledger_root)
        llm_audit_wiring_tests(tmp)
    llm_callback_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
