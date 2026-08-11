"""阶段 6 误报记忆与持续学习测试。

用法: python scripts/_memory_test.py
验证：
1. MemoryStore 写入：append 后文件有记录、字段完整
2. 检索：同 host 命中加分、同 process 命中、排除自身
3. 记忆上限：超过 MAX_RECORDS 自动裁剪（保留最近 N 条）
4. clear：清空返回条数
5. prompt 注入：_build_user_prompt 含"历史研判记忆"章节
"""
import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
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


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        write_tests(tmp)
        search_tests(tmp)
        limit_tests(tmp)
        clear_tests(tmp)
    prompt_injection_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
