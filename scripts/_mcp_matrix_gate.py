"""全工具出口矩阵门禁：MCP 通道上**每一个**工具都必须真实可调用。

用法：
    python scripts/_mcp_matrix_gate.py            # 门禁（fail-closed，exit 2）
    python scripts/_mcp_matrix_gate.py --mutate   # 变异验证（证明本门禁非空洞绿）

为什么需要它（2026-10-14 立项）
------------------------------
本项目已三度踩中**同一族**缺陷：能力实现了、但出口没接线，或被 fail-open
伪装成成功——

  (1) `event` 是 dict 而非 SecurityEvent  → 10 个工具经 MCP 一个都调不动；
  (2) observation 未还原为 ToolObservation → `false_positive_check` /
      `incident_triage`（研判主入口）恒不可达；
  (3) `inputSchema.required` 对所有工具硬编码 `["event"]`，而 11 个工具里
      6 个实际还需要 `analysis` / `*_observation`，`command_executor` 更只要
      `command` —— 声明失真，遵循声明的客户端必然调不动。

前两次由 `_mcp_test.py` 的手写白名单覆盖，但白名单是**逐工具枚举**的：
新增工具若漏进白名单，缺陷会静默复发。本门禁改为**动态遍历 tools/list**，
并做**双向断言**：

  充分性：只给「工具自己声明必需的参数」→ 必须调用成功（声明不虚报）；
  必要性：逐个抽掉声明的必需参数   → 必须调用失败（声明不遗漏）。

单向断言（只测充分性）会漏掉"声明少了参数"；只测必要性会漏掉"声明多了参数"。
两者同时成立，`required` 才真正等于实现契约。

另有两条接线断言：工具声明的必需参数必须都在 MCP 层**可转发**的键集内；
observation 还原清单必须等于全部工具所需 observation 的并集。
"""
from __future__ import annotations

import json
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.mcp import McpServer  # noqa: E402
from security_agent.mcp import server as mcp_server_module  # noqa: E402
from security_agent.tools.implementations import (  # noqa: E402
    CommandExecutionTool,
    ToolRegistry,
)

# ── 链路拓扑：参数键 ← 生产者 ─────────────────────────────────
# 这是唯一一处需要人写的东西，且**不是第二份契约清单**：它只描述"谁产出谁"，
# 新的必需参数若没有生产者，门禁会 fail-loud 地报出来（见 _provide）。
LITERALS: dict[str, object] = {
    "event": {"id": "EVENT-001"},
    "command": "echo mcp-matrix-gate",
}
TOOL_SOURCES: dict[str, str] = {
    "asset_observation": "asset_lookup",
    "log_observation": "log_lookup",
    "intel_observation": "intel_lookup",
    "history_observation": "history_alert_lookup",
    "false_positive_observation": "false_positive_check",
    "analysis": "incident_triage",
}

# 失败/兜底文案特征：出现即视为「没真干活」
FALLBACK_MARKERS = (
    "工具执行失败",
    "已启用最简兜底结果",
    "研判模块出现异常",
    "has no attribute",
    "TypeError",
    "object is not",
)


class GateError(Exception):
    """门禁内部的结构性错误（非被测对象的失败）。"""


def make_server(with_command: bool = True) -> McpServer:
    """构造覆盖**全部**工具的 server（命令工具默认关闭，门禁显式打开）。"""
    from security_agent.app import build_app

    app = build_app()
    registry = app.tool_registry
    if with_command and "command_executor" not in registry.tools:
        registry = ToolRegistry(list(registry.tools.values()) + [CommandExecutionTool()])
    return McpServer(tool_registry=registry)


class Matrix:
    """一次完整的出口矩阵检查。"""

    def __init__(self, server: McpServer):
        self.server = server
        self.registry = server.tool_registry
        self.failures: list[str] = []
        self.checked = 0
        self._memo: dict[str, object] = {}

    # ── 基础设施 ─────────────────────────────────────────
    def fail(self, msg: str) -> None:
        self.failures.append(msg)

    def check(self, cond: bool, msg: str) -> None:
        self.checked += 1
        if not cond:
            self.fail(msg)

    def listed_tools(self) -> list[dict]:
        return self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]

    def raw_call(self, name: str, arguments: dict) -> tuple[bool, object, str]:
        result = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )["result"]
        text = result["content"][0]["text"]
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
        return bool(result.get("isError")), payload, text

    def _provide(self, key: str, stack: tuple[str, ...] = ()) -> object:
        """按拓扑取到参数 `key` 的一个合法值。"""
        if key in self._memo:
            return self._memo[key]
        if key in LITERALS:
            value = LITERALS[key]
        elif key in TOOL_SOURCES:
            source = TOOL_SOURCES[key]
            if source in stack:
                raise GateError(f"链路拓扑成环: {' -> '.join((*stack, source))}")
            value = self.invoke_minimal(source, stack=(*stack, source))[1]
        else:
            # 工具声明了一个谁都不产出的必需参数 —— 这正是"接线断了"。
            raise GateError(
                f"参数 {key!r} 没有任何生产者；请在 TOOL_SOURCES 中登记产出它的工具，"
                "否则该工具在 MCP 通道上无从调用"
            )
        self._memo[key] = value
        return value

    def invoke_minimal(self, name: str, stack: tuple[str, ...] = ()) -> tuple[bool, object, str]:
        """只按 `Tool.requires` 声明给参数，调用工具。"""
        tool = self.registry.tools[name]
        args = {key: self._provide(key, stack) for key in tool.requires}
        return self.raw_call(name, args)

    # ── 断言 ─────────────────────────────────────────────
    def assert_fallback_free(self, name: str, err: bool, text: str, ctx: str) -> None:
        self.check(not err, f"[{name}] {ctx}: 调用失败 → {text[:120]}")
        for marker in FALLBACK_MARKERS:
            self.check(
                marker not in text,
                f"[{name}] {ctx}: 命中兜底/异常文案 {marker!r} → {text[:120]}",
            )

    def run(self) -> list[str]:
        listed = self.listed_tools()
        names = [t["name"] for t in listed]
        self.check(len(names) == len(set(names)), "tools/list 存在重名工具")
        self.check(len(names) >= 11, f"工具数 {len(names)} 少于预期的 11")

        forwardable = {"event", "analysis", "command", *mcp_server_module.OBSERVATION_ARGUMENTS}

        # ── 1. 声明自洽 + 接线完整 ────────────────────────
        for entry in listed:
            name = entry["name"]
            tool = self.registry.tools[name]
            schema = entry["inputSchema"]
            required = list(schema["required"])
            self.check(
                required == list(tool.requires),
                f"[{name}] inputSchema.required={required} 与 Tool.requires={list(tool.requires)} 不一致",
            )
            self.check(bool(required), f"[{name}] required 为空（客户端无从按声明传参）")
            self.check(
                set(required) <= set(schema["properties"]),
                f"[{name}] required {required} 有键不在 inputSchema.properties 中",
            )
            undeclared = set(required) - forwardable
            self.check(
                not undeclared,
                f"[{name}] required 含 MCP 层不转发的键 {sorted(undeclared)} → 必然调不动（接线断了）",
            )

        # ── 2. 还原清单完备：OBSERVATION_ARGUMENTS 必须覆盖全部工具所需 ──
        needed_obs = {k for t in listed for k in self.registry.tools[t["name"]].requires if k.endswith("_observation")}
        self.check(
            set(mcp_server_module.OBSERVATION_ARGUMENTS) == needed_obs,
            "OBSERVATION_ARGUMENTS="
            f"{sorted(mcp_server_module.OBSERVATION_ARGUMENTS)} 与工具实际所需的 {sorted(needed_obs)} 不一致"
            "（server 侧少还原一项，依赖它的工具就静默不可用）",
        )

        # ── 3. 充分性：按声明的最小集必须调得通 ────────────
        for name in names:
            try:
                err, _payload, text = self.invoke_minimal(name)
            except GateError as exc:
                # 装配不出最小参数集（如拓扑成环 / 无生产者）本身就是出口缺陷
                self.fail(f"[{name}] 最小必需参数集无法装配: {exc}")
                continue
            self.assert_fallback_free(name, err, text, "最小必需参数集")

        # ── 4. 必要性：逐个抽掉声明的必需参数，必须失败且点名 ──
        for name in names:
            tool = self.registry.tools[name]
            for key in tool.requires:
                memo_backup = dict(self._memo)
                try:
                    args = {k: self._provide(k) for k in tool.requires if k != key}
                except GateError as exc:
                    self.fail(f"[{name}] 抽掉 {key!r} 后参数集无法装配: {exc}")
                    continue
                finally:
                    self._memo = memo_backup
                err, _payload, text = self.raw_call(name, args)
                self.check(
                    err,
                    f"[{name}] 抽掉声明必需的 {key!r} 后仍返回成功 —— 该参数其实不必需，"
                    "声明虚报了依赖",
                )
                if err:
                    self.check(
                        key in text,
                        f"[{name}] 缺 {key!r} 的失败提示未点名该参数 → {text[:120]}",
                    )

        return self.failures


# ── 变异验证 ─────────────────────────────────────────────
def _mutations() -> list[tuple[str, str]]:
    """每项返回 (变异名, 说明)；执行后必须使门禁 FAIL。"""
    return [
        ("M1-声明虚报", "把某工具 required 多写一项，充分性应失败"),
        ("M2-声明遗漏", "把某工具 required 清空，必要性应失败"),
        ("M3-接线断裂", "让某工具 run 抛异常，充分性应失败"),
        ("M4-还原漏项", "从 OBSERVATION_ARGUMENTS 去掉一项，清单完备性应失败"),
        ("M5-required 硬编码", "把 required 退回硬编码 ['event']，声明自洽应失败"),
    ]


def run_mutation() -> int:
    print("== 变异验证：每次退化都必须让门禁 FAIL ==")
    ok = True
    for name, desc in _mutations():
        failures = _apply_and_run(name)
        verdict = "PASS" if failures else "FAIL(空洞绿!)"
        ok = ok and bool(failures)
        print(f"  [{verdict}] {name}: {desc}")
        print(f"           -> 门禁报出 {len(failures)} 条，首条: {failures[0][:110] if failures else '（无）'}")
    print(f"\n=== 变异验证 {'全部通过' if ok else '存在空洞绿'} ===")
    return 0 if ok else 1


def _apply_and_run(mutation: str) -> list[str]:
    """退化一次，跑门禁，返回失败列表（应为非空）。"""
    server = make_server()  # 只建一次：变异必须作用在门禁实际使用的这个实例上
    registry = server.tool_registry
    original_obs = mcp_server_module.OBSERVATION_ARGUMENTS
    original_list = McpServer._list_tools

    try:
        if mutation == "M1-声明虚报":
            tool = registry.tools["asset_lookup"]
            tool.requires = (*tool.requires, "command")  # 声明了但 run 根本不读
        elif mutation == "M2-声明遗漏":
            tool = registry.tools["false_positive_check"]
            tool.requires = ("event",)  # run 仍读 asset/log observation
        elif mutation == "M3-接线断裂":
            def _boom(**kwargs):
                raise RuntimeError("变异：接线断裂")

            registry.tools["host_isolation_simulator"].run = _boom
        elif mutation == "M4-还原漏项":
            mcp_server_module.OBSERVATION_ARGUMENTS = tuple(
                k for k in original_obs if k != "false_positive_observation"
            )
        elif mutation == "M5-required 硬编码":
            def _hardcoded(self):
                tools = []
                for nm, tl in self.tool_registry.tools.items():
                    doc = (tl.__class__.__doc__ or "").strip().split("\n")[0]
                    tools.append(
                        {
                            "name": nm,
                            "description": doc or f"安全工具: {nm}",
                            "inputSchema": {
                                "type": "object",
                                "properties": dict(self.TOOL_ARGUMENT_SCHEMA),
                                "required": ["event"],
                            },
                        }
                    )
                return tools

            McpServer._list_tools = _hardcoded
        else:
            raise GateError(f"未知变异 {mutation}")

        return Matrix(server).run()
    finally:
        mcp_server_module.OBSERVATION_ARGUMENTS = original_obs
        McpServer._list_tools = original_list


def main(argv: list[str]) -> int:
    if "--mutate" in argv:
        return run_mutation()

    print("== 全工具出口矩阵门禁 ==")
    matrix = Matrix(make_server())
    failures = matrix.run()
    print(f"  断言 {matrix.checked} 条，失败 {len(failures)} 条")
    for line in failures[:20]:
        print(f"  [FAIL] {line}")
    if failures:
        print("\n=== GATE FAILED ===")
        return 2
    print("\n=== GATE PASSED ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
