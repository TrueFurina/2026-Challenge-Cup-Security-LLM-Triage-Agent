"""阶段 1 预筛器测试：三类事件（攻击/误报/不确定）的确定性判定。

用法: python scripts/_prefilter_test.py
- 直接引擎级测试（构造 SecurityEvent，不依赖 LLM / 不依赖真实数据）
- 端到端测试（真实 alerts.json 10 个案例，MockLLM 模式，验证预筛分流与不调 LLM）
"""
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.agent.models import SecurityEvent  # noqa: E402
from security_agent.prefilter import (  # noqa: E402
    AUTO_CLOSE,
    AUTO_ESCALATE,
    NEED_LLM,
    PreFilterEngine,
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


def make_event(**kwargs) -> SecurityEvent:
    base = dict(
        id="TEST-001",
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


def engine_tests():
    print("== 引擎级测试（构造事件，不依赖 LLM） ==")
    engine = PreFilterEngine.default()

    # 1. 攻击类：PowerShell 编码命令
    ev_attack = make_event(
        raw_log="Invoke-Expression -EncodedCommand AAAA",
        process="powershell.exe",
    )
    r = engine.prefilter(ev_attack)
    check("攻击-EncodedCommand -> AUTO_ESCALATE", r.decision, AUTO_ESCALATE)
    check("攻击-风险等级 critical", r.risk_level, "critical")
    check("攻击-事件类型 恶意脚本执行", r.event_type, "恶意脚本执行")
    check("攻击-跳过 LLM", r.llm_skipped, True)

    # 2. 攻击类：WebShell
    ev_webshell = make_event(
        raw_log="GET /uploads/shell.jsp?cmd=whoami HTTP/1.1 200",
        host="WEB-01",
    )
    r = engine.prefilter(ev_webshell)
    check("攻击-WebShell -> AUTO_ESCALATE", r.decision, AUTO_ESCALATE)
    check("攻击-WebShell 风险等级 critical", r.risk_level, "critical")

    # 3. 攻击类：凭据转储
    ev_cred = make_event(
        raw_log="rundll32.exe C:\\temp\\cred.dll,EnumerateCredentials",
        process="rundll32.exe",
    )
    r = engine.prefilter(ev_cred)
    check("攻击-凭据转储 -> AUTO_ESCALATE", r.decision, AUTO_ESCALATE)

    # 4. 误报类：白名单 + 变更单
    ev_fp = make_event(
        title="PRINT-02 whitelist 扫描活动",
        behavior="已被标记为白名单资产",
        raw_log="Event 5156 ... tag=whitelist",
        change_ticket="CHG-20240301",
        tags=["whitelist", "maintenance"],
    )
    r = engine.prefilter(ev_fp)
    check("误报-白名单/变更单 -> AUTO_CLOSE", r.decision, AUTO_CLOSE)
    check("误报-标记为 false positive", r.is_false_positive, True)
    check("误报-跳过 LLM", r.llm_skipped, True)

    # 5. 误报类：仅变更单
    ev_ticket = make_event(change_ticket="CHG-0001")
    r = engine.prefilter(ev_ticket)
    check("误报-仅变更单 -> AUTO_CLOSE", r.decision, AUTO_CLOSE)

    # 6. 不确定类：普通外联，无特征
    ev_unknown = make_event(
        title="OA 服务器异常外联",
        behavior="发起了异常出站连接",
        raw_log="Event 5156 ... dst=203.0.113.5; port=443",
    )
    r = engine.prefilter(ev_unknown)
    check("不确定-无特征 -> NEED_LLM", r.decision, NEED_LLM)
    check("不确定-不跳过 LLM", r.llm_skipped, False)

    # 7. 攻击优先于误报：攻击特征 + 变更单同时存在 → 攻击胜出
    ev_conflict = make_event(
        raw_log="Invoke-Expression -EncodedCommand AAAA",
        change_ticket="CHG-0002",
        tags=["whitelist"],
    )
    r = engine.prefilter(ev_conflict)
    check("优先级-攻击覆盖误报上下文 -> AUTO_ESCALATE", r.decision, AUTO_ESCALATE)

    # 8. fail-open：异常输入不崩溃，回退 NEED_LLM
    r = engine.prefilter(None)
    check("fail-open-空事件回退 NEED_LLM", r.decision, NEED_LLM)


def e2e_tests():
    print("== 端到端测试（alerts.json 10 案例, MockLLM 模式） ==")
    from security_agent.app import build_app
    from security_agent.config import AppConfig
    from security_agent.llm.mock import MockLLM

    config = AppConfig.from_env()
    config.use_real_llm = False
    app = build_app()
    app.llm = MockLLM()  # 强制 Mock，避免真实 API 依赖

    events = app.list_events()
    expected = {
        # 按真实 alerts.json 内容标注
        "EVENT-001": AUTO_ESCALATE,  # EncodedCommand 攻击
        "EVENT-002": AUTO_CLOSE,     # 白名单+变更单 误报
        "EVENT-003": NEED_LLM,       # 待确认外联
        "EVENT-004": AUTO_ESCALATE,  # admin$ 横向移动
        "EVENT-005": NEED_LLM,       # 登录尝试
        "EVENT-006": AUTO_ESCALATE,  # WebShell
        "EVENT-007": AUTO_ESCALATE,  # 勒索加密 .encrypted
        "EVENT-008": AUTO_ESCALATE,  # 凭据转储 EnumerateCredentials
        "EVENT-009": NEED_LLM,       # 堡垒机跳转
        "EVENT-010": AUTO_ESCALATE,  # 恶意宏投递
    }
    for event in events:
        result = app.triage_event(event.id)
        decision = result.prefilter_decision
        check(f"{event.id} {event.title[:18]}... 预筛决策", decision, expected[event.id])

    # 统计
    stats = app.prefilter_stats
    total = sum(stats.values())
    savings = (stats["auto_close"] + stats["auto_escalate"]) / total if total else 0.0
    print(f"  预筛统计: {stats}")
    print(f"  LLM 调用节省率: {savings:.0%}")


def main() -> int:
    engine_tests()
    e2e_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
