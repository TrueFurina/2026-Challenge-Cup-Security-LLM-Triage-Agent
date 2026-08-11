"""阶段 4 RAG 知识库测试。

用法: python scripts/_knowledge_test.py
验证：
1. knowledge.json 全部条目字段完整（title/content/tags/category/attck_ids/cve_ids）
2. 攻击事件（EVENT-006 WebShell）检索返回含 ATT&CK 技术的条目
3. retrieve 详情含 ATT&CK/CVE 标注（_format_detail）
4. prompt 注入：_build_user_prompt 输出含 ATT&CK 技术引用
5. knowledge_hits 格式化含 ATT&CK/CVE 依据
"""
import json
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.ai.triage import _build_user_prompt  # noqa: E402
from security_agent.agent.models import ToolObservation  # noqa: E402
from security_agent.knowledge.store import KnowledgeHub  # noqa: E402
from security_agent.intake.service import EventIntakeService  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def data_integrity_tests():
    print("== 1. knowledge.json 字段完整性 ==")
    path = os.path.join(PROJECT_DIR, "security_agent", "data", "knowledge.json")
    rows = json.loads(open(path, encoding="utf-8").read())
    check("知识条目数 >= 20", len(rows) >= 20, True)
    missing = [
        r["title"] for r in rows
        if not all(k in r for k in ("title", "content", "tags", "category", "attck_ids", "cve_ids"))
    ]
    check("无缺字段条目", missing, [])
    type_ok = all(
        isinstance(r.get("attck_ids"), list) and isinstance(r.get("cve_ids"), list)
        for r in rows
    )
    check("attck_ids/cve_ids 为列表", type_ok, True)
    check("含 ATT&CK 条目 >= 10", sum(1 for r in rows if r.get("attck_ids")) >= 10, True)
    check("含 CVE 条目 >= 3", sum(1 for r in rows if r.get("cve_ids")) >= 3, True)


def retrieval_tests():
    print("== 2. 检索返回含 ATT&CK/CVE 依据 ==")
    hub = KnowledgeHub.default()
    intake = EventIntakeService.default()

    ev_webshell = intake.get_event("EVENT-006")
    items, obs = hub.retrieve_knowledge(ev_webshell, top_k=3)
    check("WebShell 事件返回 3 条", len(items), 3)
    check("含 WebShell 检测规则", any("webshell" in it.title.lower() for it in items), True)
    check("至少一条含 attck_ids", any(getattr(it, "attck_ids", []) for it in items), True)
    detail_text = " ".join(obs.details)
    check("详情含 ATT&CK 标注", "ATT&CK:" in detail_text, True)
    check("详情含 CVE 标注", "CVE:" in detail_text, True)

    ev_pwsh = intake.get_event("EVENT-001")
    items2, obs2 = hub.retrieve_knowledge(ev_pwsh, top_k=3)
    check("PowerShell 事件命中 ATT&CK T1059 条目", any(
        "T1059" in "/".join(getattr(it, "attck_ids", [])) for it in items2
    ), True)


def prompt_injection_tests():
    print("== 3. prompt 注入 ATT&CK 依据 ==")
    hub = KnowledgeHub.default()
    intake = EventIntakeService.default()
    ev = intake.get_event("EVENT-006")
    knowledge_items, _ = hub.retrieve_knowledge(ev, top_k=3)
    empty = ToolObservation(tool_name="t", summary="s", details=[])
    prompt = _build_user_prompt(
        event=ev,
        asset_observation=empty,
        log_observation=empty,
        intel_observation=empty,
        history_observation=empty,
        false_positive_observation=empty,
        knowledge_items=knowledge_items,
        plan=["step1"],
    )
    check("prompt 含 ATT&CK 技术映射标题", "ATT&CK" in prompt, True)
    check("prompt 含 T1505（WebShell 技术）", "T1505" in prompt, True)
    check("prompt 含引用引导语", "请结合上述知识条目" in prompt, True)


def orchestrator_hit_tests():
    print("== 4. knowledge_hits 格式化含依据 ==")
    from security_agent.app import build_app
    from security_agent.llm.mock import MockLLM

    app = build_app()
    app.llm = MockLLM()
    result = app.triage_event("EVENT-006").to_dict()
    hits = result.get("knowledge_hits", [])
    check("knowledge_hits 非空", len(hits) > 0, True)
    check("命中含 ATT&CK 标注", any("ATT&CK:" in h for h in hits), True)


def main() -> int:
    data_integrity_tests()
    retrieval_tests()
    prompt_injection_tests()
    orchestrator_hit_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
