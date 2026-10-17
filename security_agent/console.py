"""控制台编码无关性：中文输出在任何代码页下都不崩，且管道里恒定是 UTF-8。

背景（2026-10-14 由 CI 首次暴露）
--------------------------------
GitHub 的 `windows-latest` runner 默认 ANSI 代码页是 **cp1252**（英文 Windows）。
stdout 被重定向成管道时，Python 用 `locale.getpreferredencoding()` 决定编码 ⇒
`print("中文")` 直接抛 `UnicodeEncodeError` 崩掉。本机是中文代码页（cp936），
**永远看不到这个现象**，所以「本机全绿」根本没覆盖这条路径。

受害面不止测试脚本：

- `security_agent/cli.py` 的 `list-events` 会崩（事件标题就是中文）；
- `security_agent/mcp/server.py` 往 stdout 写 `ensure_ascii=False` 的 JSON-RPC
  响应也会崩 —— **MCP 服务器是下游平台的接入面，这条尤其致命**；
- 读入侧同样中招：stdin 若按 cp1252 解，客户端发来的 UTF-8 中文会被**静默解错**
  （不报错、只是内容不对，比崩更难发现）。

策略（按流是否连着控制台分派）
------------------------------
- **非控制台（管道 / 重定向 / CI / 被父进程 spawn）**：固定 `encoding="utf-8"`。
  于是日志、管道、stdio 协议两端约定同一套字节，父进程按 UTF-8 解即可，不受本机
  代码页影响。**`PYTHONIOENCODING` 也压不掉它** —— 这正是 CI 里
  `encoding-independence` 那条回归要守的不变量（去掉本模块，那条就必红）。
- **连着控制台**：**保留平台编码**（中文 Windows 的 cp936 显示中文本就正常，
  强行改成 UTF-8 反而会花屏），只把 `errors` 放宽 —— 底线是「不崩」。

为什么 `errors` 一律用 `replace`
------------------------------
encoding 一旦固定为 UTF-8，编码本身就不会再失败（UTF-8 能表示全部码位），
`errors` 只在极端情况（孤立代理项 surrogate）兜底。控制台那条分支则靠它把
「本机代码页表示不了的字」降级成 `?`，而不是抛异常中断整个程序。
"""
from __future__ import annotations

import sys
from typing import Any

__all__ = ["use_utf8_stdio"]


def _reconfigure(stream: Any, *, errors: str) -> None:
    """把单个流调成「不会因编码崩」。非文本流（已被替换 / 无 reconfigure）直接跳过。"""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        # 例如 pytest 的捕获对象、被宿主替换过的流 —— 不是我们能改的，不动。
        return

    is_console = True
    isatty = getattr(stream, "isatty", None)
    if isatty is not None:
        try:
            is_console = bool(isatty())
        except (ValueError, OSError):
            is_console = True  # 判不出来就按控制台处理（保守：不动 encoding）

    try:
        if is_console:
            reconfigure(errors=errors)
        else:
            reconfigure(encoding="utf-8", errors=errors)
    except (ValueError, OSError, LookupError):
        # 流已关闭、或实现不支持重配置。这层只是「让输出更稳」，不该把程序搞崩。
        pass


def use_utf8_stdio(errors: str = "replace") -> None:
    """把 stdin / stdout / stderr 调到「不因编码崩 + 管道里恒定 UTF-8」。幂等，可重复调用。"""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if stream is not None:
            _reconfigure(stream, errors=errors)


if __name__ == "__main__":
    # 自证：证明「管道里本模块确实压得住 PYTHONIOENCODING」。
    # 关键是**必须同时跑反向对照** —— 不导入本模块的子进程必须崩，
    # 否则说明这条自证是空洞绿（探针根本没碰到真实的编码路径）。
    import os
    import subprocess

    PROBE = "print('中文探针')"
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    ok = True
    print("== 编码无关性自证（子进程管道 + PYTHONIOENCODING=cp1252）==")

    guarded = subprocess.run(
        [sys.executable, "-c", f"from security_agent.console import use_utf8_stdio; use_utf8_stdio(); {PROBE}"],
        capture_output=True, encoding="utf-8", errors="replace",
        env=env, cwd=root, timeout=120,
    )
    got = (guarded.stdout or "").strip()
    good = guarded.returncode == 0 and got == "中文探针"
    ok = ok and good
    print(f"  [{'PASS' if good else 'FAIL'}] 调用 use_utf8_stdio() 后仍能打印中文: rc={guarded.returncode} out={got!r}")

    bare = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True, encoding="utf-8", errors="replace",
        env=env, cwd=root, timeout=120,
    )
    good = bare.returncode != 0
    ok = ok and good
    print(f"  [{'PASS' if good else 'FAIL'}] 反向对照：不导入时必须崩（否则自证空洞）: rc={bare.returncode}")

    print(f"\n=== 自证{'通过' if ok else '未通过'} ===")
    raise SystemExit(0 if ok else 1)
