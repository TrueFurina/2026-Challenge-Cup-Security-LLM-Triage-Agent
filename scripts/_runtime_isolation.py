"""测试 / 门禁的运行时数据隔离：**不改动本机真实业务数据**。

用途
----
    from _runtime_isolation import isolated_runtime

    with isolated_runtime() as report:
        ...跑工具 / 跑门禁...
    if report.drift:
        ...判红（隔离失效，已自动还原）...

为什么不直接改 `McpServer`
-------------------------
生产语义下「MCP 工具调用写审计台账」是**设计意图**（可溯源），README 亦如实声明。
问题只出在**测试/门禁**这一侧：它们不是真实处置，写进去的「审计记录」会覆写本机
真实记录。所以隔离加在测试侧，而非削弱生产能力。

定位（2026-10-14 逐个脚本隔离跑 + 比对 mtime 定位，先定性再下结论）
------------------------------------------------------------------
**写入者**：

- `scripts/_verify.py` —— 经 CLI 子进程 `analyze --event-id EVENT-001` 走编排层，
  改写 `ledger/EVENT-001.json` 与 `triage_history.jsonl`；
- `scripts/_hittl_test.py` 的 `readback_integration_tests` —— 手动把 `app.memory`
  / `app.feedback` 指到临时库，却**漏了 ledger**，故改写 `ledger/EVENT-001.json`
  与 `ledger/EVENT-003.json`。

**零变化**：`_eval_test.py`、`_prefilter_test.py`、以及 MCP 工具层
（`incident_triage` 直调 `ai.triage.triage_event`，不经编排层，故不落台账）。

**准确性质**：当前样例数据下的写入是**幂等重写**——内容逐字节相同（md5 不变），
只有 mtime 被改写。所以这**不是已发生的数据损坏**，而是「隔离缺口」：一旦
`security_agent/data/` 换成真实处置数据、或本机跑过真实研判，同样的路径就会
真覆写审计台账与研判历史。对依赖 mtime 判断「盘面是否被动过」的排查流程，
mtime 被测试改写本身也已构成误导。

与 `check_quant_effect.py --full` 就地覆写 `all_benchmarks_summary.json` 同属
「验证污染被验证对象」这一类。项目已有的 `SecurityAgent.evaluation_sandbox()`
把写开关收归单一持有（`record_ledger` / `record_history`），但它是**实例方法**：
CLI 与子进程路径拿不到 app 实例；`_hittl_test` 更是手动关了两个、漏了第三个——
正是沙箱 docstring 自己点名批评的「每处调用方各自记得关」漂移。本模块补上
「快照 → 跑 → 逐字节比对 → 漂移即还原」这一层，覆盖所有路径。

三个动作
--------
1. **快照**：跑前记录运行时产物的字节内容；
2. **比对**：跑后逐字节比对，报出漂移；
3. **还原**：一旦漂移**自动还原**并把差异交给调用方判红。

`disable_writes=True` 时把 `SecurityAgent.record_ledger` / `record_history` 强制置
False（patch 构造函数，见 `isolated_runtime` 的说明）。注意它**管不到子进程**
（`_verify.py` 走 CLI 子进程）——那种场景靠「快照 + 还原」兜底，而不是靠关写。
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

#: 本机运行时产物。已被 .gitignore（不进版本库），但仍是**真实业务数据**。
RUNTIME_PATHS: tuple[Path, ...] = (
    PROJECT_DIR / "security_agent" / "data" / "ledger",
    PROJECT_DIR / "security_agent" / "data" / "triage_history.jsonl",
    PROJECT_DIR / "security_agent" / "data" / "review_feedback.jsonl",
)


def _files() -> list[Path]:
    found: list[Path] = []
    for path in RUNTIME_PATHS:
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.is_file():
            found.append(path)
    return found


@dataclass(frozen=True)
class FileState:
    """一个运行时文件的完整可还原状态。

    只存内容不够：写入是**幂等重写**（内容相同、mtime 被刷新）时，内容比对
    看不出任何异常，但文件确实被动过——对依赖 mtime 判断「盘面有没有被改」的
    排查流程已构成误导。故 mtime 一并留存，既能检出也能还原。
    """

    content: bytes
    mtime_ns: int


def snapshot() -> dict[str, FileState]:
    """把运行时产物读成 {相对项目根的路径: FileState}。"""
    return {
        str(p.relative_to(PROJECT_DIR)): FileState(p.read_bytes(), p.stat().st_mtime_ns)
        for p in _files()
    }


def drift(before: dict[str, FileState], after: dict[str, FileState]) -> list[str]:
    """比对两次快照，返回人类可读的漂移描述（空列表 = 零变化）。"""
    messages: list[str] = []
    for key in sorted(set(after) - set(before)):
        messages.append(f"新增 {key}（{len(after[key].content)} 字节）")
    for key in sorted(set(before) - set(after)):
        messages.append(f"删除 {key}")
    for key in sorted(set(before) & set(after)):
        old, new = before[key], after[key]
        if old.content != new.content:
            messages.append(
                f"内容变化 {key}（{len(old.content)} → {len(new.content)} 字节）"
            )
        elif old.mtime_ns != new.mtime_ns:
            messages.append(f"被重写（内容相同、mtime 变化）{key}")
    return messages


def restore(before: dict[str, FileState]) -> None:
    """把运行时产物恢复为快照状态：删新增文件、重写原文件、**连 mtime 一并复原**。"""
    for path in _files():
        key = str(path.relative_to(PROJECT_DIR))
        if key not in before:
            try:
                path.unlink()
            except OSError:
                pass
    for key, state in before.items():
        target = PROJECT_DIR / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(state.content)
        try:
            os.utime(target, ns=(state.mtime_ns, state.mtime_ns))
        except OSError:
            pass  # 某些文件系统不支持纳秒精度；内容已还原，不必因此中断


class IsolationReport:
    """隔离期间的观测结果。"""

    def __init__(self) -> None:
        self.drift: list[str] = []
        self.restored = False
        self.writes_disabled = False

    @property
    def clean(self) -> bool:
        return not self.drift


@contextmanager
def isolated_runtime(disable_writes: bool = True):
    """在隔离区间内跑被测代码，退出时比对（并在必要时还原）运行时产物。

    `disable_writes=True` 时把 `SecurityAgent.record_ledger` / `record_history`
    强制置 False。

    **为什么 patch `SecurityAgent.__init__` 而不是 `app.build_app`**：后者只对
    「在函数体内 `from security_agent.app import build_app`」的调用方生效
    （`mcp/server.py` 恰好如此）；一旦调用方在模块顶层 import 了 `build_app`，
    它持有的是 patch 前的引用，隔离**静默失效**——本模块的自证就是这么先踩了一跤。
    patch 构造函数则覆盖所有构造路径，不依赖调用方怎么写 import。
    """
    before = snapshot()
    report = IsolationReport()
    original_init = None
    agent_cls = None

    if disable_writes:
        from security_agent.agent.orchestrator import SecurityAgent  # noqa: PLC0415

        agent_cls = SecurityAgent
        original_init = SecurityAgent.__init__

        def _quiet_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            self.record_ledger = False
            self.record_history = False

        SecurityAgent.__init__ = _quiet_init
        report.writes_disabled = True

    try:
        yield report
    finally:
        if agent_cls is not None and original_init is not None:
            agent_cls.__init__ = original_init
        report.drift = drift(before, snapshot())
        if report.drift:
            restore(before)
            report.restored = True


def format_report(report: IsolationReport) -> str:
    """把隔离报告格式化为一行结论（供门禁打印）。"""
    if report.clean:
        mode = "已关闭写入" if report.writes_disabled else "未关闭写入"
        return f"运行时数据零变化（{mode}；{len(RUNTIME_PATHS)} 个受保护路径）"
    head = "；".join(report.drift[:3])
    more = f" 等 {len(report.drift)} 处" if len(report.drift) > 3 else ""
    tail = "，已自动还原" if report.restored else "，**未能还原**"
    return f"运行时数据发生漂移: {head}{more}{tail}"


if __name__ == "__main__":
    # 自证：必须走**编排层**（`app._triage`）才会落台账。MCP 工具层直调
    # `ai.triage.triage_event`，不经编排层，探针会假绿——这正是定位阶段踩过的坑，
    # 故此处刻意用编排层入口，并显式断言「基线必须出现漂移」，否则结论不可信。
    import sys

    sys.path.insert(0, str(PROJECT_DIR))
    os.chdir(PROJECT_DIR)
    import security_agent.ai.triage as triage_mod  # noqa: PLC0415
    from security_agent.app import build_app  # noqa: PLC0415

    # 规则回退：零网络、零成本、结论可复现
    triage_mod.ai_chat_json = lambda messages, **kwargs: None  # type: ignore[assignment]

    def _triage_once() -> None:
        app = build_app()
        app._triage(app.intake_service.get_event("EVENT-001"))

    with isolated_runtime(disable_writes=False) as bare:
        _triage_once()
    print(f"[基线] 关写={bare.writes_disabled} -> {format_report(bare)}")

    with isolated_runtime(disable_writes=True) as quiet:
        _triage_once()
    print(f"[隔离] 关写={quiet.writes_disabled} -> {format_report(quiet)}")

    ok = True
    if not bare.drift:
        print("[WARN] 基线未产生漂移 —— 探针未覆盖写入路径，其『零变化』结论不可信。")
        ok = False
    if quiet.drift:
        print("[FAIL] 隔离失效：关了写入仍发生漂移。")
        ok = False
    print(f"\n=== {'自证通过（基线漂移 → 隔离零变化）' if ok else '自证未通过'} ===")
    raise SystemExit(0 if ok else 1)
