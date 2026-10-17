"""快速验证脚本：列出事件、分析 EVENT-001、运行评测。

隔离（2026-10-14 补）
--------------------
本脚本经 **CLI 子进程**走编排层（`analyze --event-id EVENT-001`）。子进程里
`build_app()` 新建的 app 拿不到实例级隔离（`evaluation_sandbox()` 是实例方法），
历史上会覆写生产审计台账 `data/ledger/EVENT-001.json` 与误报记忆
`data/triage_history.jsonl`——实测两者 mtime 被改写（内容在当前样例数据下幂等，
故 md5 不变；换成真实数据即真覆写）。

两道防线：
1. `SECURITY_AGENT_RUNTIME_WRITES=0` —— 子进程继承，从源头不写；
2. `isolated_runtime()` 快照比对 —— 万一还有旁路写入，逐字节比对并**自动还原**，
   且漂移即 exit 1（不留"跑完看起来没事"的假象）。
"""
import os
import subprocess
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_DIR)
sys.path.insert(0, PROJECT_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _runtime_isolation import format_report, isolated_runtime  # noqa: E402

from security_agent.console import use_utf8_stdio  # noqa: E402

use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩

# 子进程继承：从源头关掉运行时写入
os.environ["SECURITY_AGENT_RUNTIME_WRITES"] = "0"


def _run(args, timeout=None):
    return subprocess.run(
        # 子进程管道输出被 security_agent.console 固定成 UTF-8 ⇒ 父进程按键 UTF-8 解。
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=PROJECT_DIR, timeout=timeout
    )


def _show(result, limit=2000):
    out = result.stdout
    if len(out) > limit:
        print(out[: limit // 2] + "\n... (truncated) ...\n" + out[-limit // 4 :])
    else:
        print(out)
    if result.stderr:
        print("ERR:", result.stderr[-300:] if len(result.stderr) > 300 else result.stderr)


with isolated_runtime(disable_writes=False) as report:
    print("=== List Events ===")
    _show(_run([sys.executable, "-m", "security_agent.cli", "list-events"]))

    print("=== Analyze EVENT-001 ===")
    _show(
        _run(
            [sys.executable, "-m", "security_agent.cli", "analyze", "--event-id", "EVENT-001"],
            timeout=30,
        )
    )

    print("=== Evaluate ===")
    _show(
        _run([sys.executable, "-m", "security_agent.cli", "evaluate"], timeout=60),
        limit=1000,
    )

print(f"\n[运行时数据] {format_report(report)}")
print("=== DONE ===")
sys.exit(1 if report.drift else 0)
