"""阶段 6 误报记忆与持续学习测试。

用法: python scripts/_memory_test.py
验证：
1. MemoryStore 写入：append 后文件有记录、字段完整
2. 检索：同 host 命中加分、同 process 命中、排除自身
3. 记忆上限：超过 MAX_RECORDS 自动裁剪（保留最近 N 条）
4. clear：清空返回条数
5. prompt 注入：_build_user_prompt 含"历史研判记忆"章节
6. 注入接线（集成）：从 app._triage 入口验证 memory → 提示词的接线真实存在
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

from security_agent.ai.triage import _build_user_prompt  # noqa: E402
from security_agent.agent.models import SecurityEvent, ToolObservation  # noqa: E402
from security_agent.memory import MemoryStore  # noqa: E402

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
        process="powershell.exe",
        behavior="执行了可疑的 PowerShell 编码命令",
        raw_log="EncodedCommand 执行",
    )
    base.update(kwargs)
    return SecurityEvent(**base)


def write_tests(tmp: Path):
    print("== 1. 写入持久化 ==")
    store = MemoryStore(path=tmp / "triage_history.jsonl")
    store.append(
        {
            "event_id": "EVENT-001",
            "host": "DC-01",
            "process": "powershell.exe",
            "behavior": "PowerShell 编码命令",
            "event_type": "恶意脚本执行",
            "risk_level": "critical",
            "confidence": "high",
            "is_false_positive": False,
        }
    )
    check("写入后文件存在", (tmp / "triage_history.jsonl").exists(), True)
    check("count=1", store.count(), 1)
    lines = (tmp / "triage_history.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    check("字段完整", {"event_id", "host", "process", "is_false_positive", "timestamp"} <= set(record), True)
    check("时间戳存在", bool(record.get("timestamp")), True)


def search_tests(tmp: Path):
    print("== 2. 相似记忆检索 ==")
    store = MemoryStore(path=tmp / "triage_history.jsonl")
    store.append(
        {
            "event_id": "HIST-1",
            "host": "DC-01",
            "process": "powershell.exe",
            "behavior": "PowerShell 编码命令下载执行",
            "event_type": "恶意脚本执行",
            "risk_level": "critical",
            "confidence": "high",
            "is_false_positive": False,
        }
    )
    store.append(
        {
            "event_id": "HIST-2",
            "host": "OTHER-99",
            "process": "scanner.exe",
            "behavior": "白名单扫描",
            "event_type": "误报",
            "risk_level": "low",
            "confidence": "high",
            "is_false_positive": True,
        }
    )
    # 同 host + 同 process 的事件
    event = make_event(host="DC-01", process="powershell.exe")
    hits = store.search(event, top_k=3)
    check("检索到相似历史", len(hits) >= 1, True)
    check("同 host/process 命中 HIST-1", any(h.get("event_id") == "HIST-1" for h in hits), True)
    # 排除自身：搜索与 HIST-1 相同 event_id 不返回自身
    self_event = make_event(id="HIST-1", host="DC-01", process="powershell.exe")
    hits2 = store.search(self_event, top_k=3)
    check("排除自身（HIST-1 不返回自身）", all(h.get("event_id") != "HIST-1" for h in hits2), True)
    # 无相似：不同 host/process 且行为完全无关
    diff = make_event(host="WEB-01", process="nginx.exe", behavior="处理 HTTP 请求", raw_log="GET /index.html 200")
    check("无相似历史返回空", store.search(diff, top_k=3), [])


def limit_tests(tmp: Path):
    print("== 3. 记忆上限裁剪 ==")
    store = MemoryStore(path=tmp / "triage_history.jsonl")
    store.MAX_RECORDS = 5
    for i in range(10):
        store.append(
            {
                "event_id": f"EVT-{i}",
                "host": "H-01",
                "process": "p.exe",
                "behavior": f"行为{i}",
                "event_type": "通用异常行为",
                "risk_level": "medium",
                "confidence": "high",
                "is_false_positive": False,
            }
        )
    check("裁剪后 count=5", store.count(), 5)
    records = store._load()
    check("保留最近 5 条", records[0]["event_id"] == "EVT-5", True)


def clear_tests(tmp: Path):
    print("== 4. 清空 ==")
    store = MemoryStore(path=tmp / "triage_history.jsonl")
    store.clear()  # 先清掉前面用例残留，保证隔离
    store.append({"event_id": "A", "host": "H", "process": "P", "behavior": "B", "event_type": "T", "risk_level": "low", "confidence": "high", "is_false_positive": True})
    removed = store.clear()
    check("clear 返回条数", removed, 1)
    check("清空后 count=0", store.count(), 0)


def prompt_injection_tests():
    print("== 5. prompt 历史记忆注入 ==")
    event = make_event()
    empty = ToolObservation(tool_name="t", summary="s", details=[])
    history = [
        {
            "event_id": "HIST-X",
            "host": "HOST-01",
            "process": "powershell.exe",
            "behavior": "同类",
            "event_type": "误报",
            "risk_level": "low",
            "confidence": "high",
            "is_false_positive": True,
            "timestamp": "2026-08-01T00:00:00Z",
        }
    ]
    prompt = _build_user_prompt(
        event=event,
        asset_observation=empty,
        log_observation=empty,
        intel_observation=empty,
        history_observation=empty,
        false_positive_observation=empty,
        knowledge_items=[],
        plan=["step"],
        history_items=history,
    )
    check("prompt 含历史章节标题", "历史研判记忆" in prompt, True)
    check("prompt 含误报判定", "误报" in prompt, True)
    check("prompt 含一致性引导", "供一致性参考" in prompt, True)


def wiring_integration_tests():
    """== 6. 注入接线（集成）——memory → orchestrator → 提示词 ==

    为什么单测不够：`prompt_injection_tests` 直接调 `_build_user_prompt(history_items=...)`，
    参数本身没问题；但生产链路曾**从未**给 `history_items` 传值
    （`MemoryStore.search` 零调用），于是该功能"只写不读"完全失效，
    而单测依旧全绿——典型的「函数被覆盖、集成没接上」。

    本测试从 `app._triage` 入口出发、捕获真实提示词，锁死这条接线。
    """
    print("== 6. 注入接线（集成）==")
    import security_agent.ai.triage as triage_mod
    from security_agent.app import build_app

    captured: dict = {}

    def fake_chat(messages, **kwargs):
        captured["prompt"] = messages[0]["content"]
        return None  # 触发规则回退，避免真实 LLM 调用（本测试零成本零网络）

    original = triage_mod.ai_chat_json
    triage_mod.ai_chat_json = fake_chat
    try:
        # 复用评测沙箱：记忆读写双向隔离 + ledger 写隔离。
        # 此前本测试直接 `app.memory.clear()` 清掉**真实** triage_history.jsonl
        # （实测 -13KB），且 `_triage` 会把 ledger 写进真实 data/ledger，属测试污染运行时数据。
        app = build_app()
        with app.evaluation_sandbox():
            event = app.intake_service.get_event("EVENT-003")

            app._triage(event)
            # 若该事件改为确定性预筛短路，就取不到提示词——让测试显式失败而非静默跳过
            check("EVENT-003 走 LLM 深度研判（提示词已捕获）",
                  bool(captured.get("prompt")), True)
            check("空记忆 → 提示词标注「无相似历史研判记忆」",
                  "- 无相似历史研判记忆" in captured.get("prompt", ""), True)

            app.memory.append({
                "event_id": "MEM-WIRE-SEED",
                "host": event.host,
                "process": event.process,
                "behavior": event.behavior,
                "event_type": "误报",
                "risk_level": "low",
                "confidence": "high",
                "is_false_positive": True,
            })
            app._triage(event)
            prompt = captured.get("prompt", "")
            section = prompt.split("历史研判记忆", 1)[-1][:240]
            check("同主机历史记忆被检索并注入", event.host in section, True)
            check("注入内容含历史判定结论", "判定: 误报" in section, True)
    finally:
        triage_mod.ai_chat_json = original


def bad_line_tests(tmp: Path):
    """坏行必须留下痕迹，不得静默丢弃。

    为什么单列一节：坏行被静默 `continue` 时，调用方无法分辨「库里本来就没有记忆」
    与「记忆在读取时被吃掉了」。后者意味着 Triage 少了一条误报证据，而链路看上去
    一切正常——与「LLM 静默回退规则」同质，是最难自查的一类失效。

    本节变异锚点：把 `self.skipped_lines += 1` 改回单纯 continue → 本节必 FAIL。
    """
    print("== 6. 坏行可见性 ==")
    path = tmp / "bad_history.jsonl"
    lines = [
        '{"event_id": "GOOD-1", "host": "DC-01", "process": "powershell.exe", '
        '"behavior": "PowerShell 编码命令", "event_type": "恶意脚本执行", '
        '"risk_level": "critical", "confidence": "high", "is_false_positive": false}',
        '{"event_id": "TRUNCATED-2", "host": "DC-01", "proc',  # 半行（写入被截断）
        "这不是 JSON",  # 完全非 JSON
        '{"event_id": "GOOD-3", "host": "DC-01", "process": "powershell.exe", '
        '"behavior": "可疑下载", "event_type": "恶意脚本执行", '
        '"risk_level": "high", "confidence": "medium", "is_false_positive": false}',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    store = MemoryStore(path=path)
    event = make_event(host="DC-01", process="powershell.exe")
    hits = store.search(event, top_k=5)

    check("跳过行数被记录", store.skipped_lines, 2)
    check("坏行不计入检索结果", len(hits), 2)
    check("保留下来的都是完好记录", sorted(h.get("event_id") for h in hits), ["GOOD-1", "GOOD-3"])
    check("加载总数等于完好行数", len(store._load()), 2)

    # skipped_lines 每次加载重置，避免跨次读取累积成假数字
    store._load()
    check("二次加载后计数重置为实际坏行数", store.skipped_lines, 2)

    # 纯净文件 → 计数为 0（不得误报）
    clean = tmp / "clean_history.jsonl"
    clean.write_text(lines[0] + "\n", encoding="utf-8")
    store2 = MemoryStore(path=clean)
    store2.search(make_event(host="DC-01", process="powershell.exe"))
    check("完好文件 no skipped", store2.skipped_lines, 0)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        write_tests(tmp)
        search_tests(tmp)
        limit_tests(tmp)
        clear_tests(tmp)
        bad_line_tests(tmp)
    prompt_injection_tests()
    wiring_integration_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
