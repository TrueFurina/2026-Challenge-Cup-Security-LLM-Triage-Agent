"""全工具出口矩阵门禁（薄壳）：检查逻辑在 `security_agent/mcp/matrix.py`。

用法：
    python scripts/_mcp_matrix_gate.py            # 门禁（fail-closed，exit 2）
    python scripts/_mcp_matrix_gate.py --mutate   # 变异验证（证明本门禁非空洞绿）

检查内容与动机见 `security_agent/mcp/matrix.py` 的模块 docstring。
本脚本只负责两件库侧不方便做的事：
  1. 构造一个**覆盖全部工具**的 server（命令工具默认关闭，门禁显式打开）；
  2. 变异验证 —— 逐类退化实现，确认门禁会 FAIL 而不是空洞绿。
"""
from __future__ import annotations

import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.mcp import McpServer  # noqa: E402
from security_agent.mcp import server as mcp_server_module  # noqa: E402
from security_agent.mcp.matrix import MatrixError, ToolMatrix  # noqa: E402
from security_agent.tools.implementations import (  # noqa: E402
    CommandExecutionTool,
    ToolRegistry,
)


def make_server(with_command: bool = True) -> McpServer:
    """构造覆盖**全部**工具的 server（命令工具默认关闭，门禁显式打开）。"""
    from security_agent.app import build_app

    app = build_app()
    registry = app.tool_registry
    if with_command and "command_executor" not in registry.tools:
        registry = ToolRegistry(list(registry.tools.values()) + [CommandExecutionTool()])
    return McpServer(tool_registry=registry)


def run_matrix(server: McpServer):
    return ToolMatrix(server, mcp_server_module.OBSERVATION_ARGUMENTS).run()


# ── 变异验证 ─────────────────────────────────────────────
_MUTATIONS = (
    ("M1-声明虚报", "required 多写一项（run 并不读），必要性应失败"),
    ("M2-声明遗漏", "required 清空（run 仍读），充分性应失败"),
    ("M3-接线断裂", "让某工具 run 抛异常，充分性应失败"),
    ("M4-还原漏项", "从 OBSERVATION_ARGUMENTS 去掉一项，还原清单完备性应失败"),
    ("M5-required 硬编码", "把 required 退回硬编码 ['event']，声明自洽应失败"),
)


def _apply_and_run(mutation: str):
    """退化一次，跑门禁，返回 MatrixResult（failures 应为非空）。"""
    server = make_server()  # 只建一次：变异必须作用在门禁实际使用的实例上
    registry = server.tool_registry
    original_obs = mcp_server_module.OBSERVATION_ARGUMENTS
    original_list = McpServer._list_tools
    try:
        if mutation == "M1-声明虚报":
            tool = registry.tools["asset_lookup"]
            tool.requires = (*tool.requires, "command")  # 声明了但 run 根本不读
        elif mutation == "M2-声明遗漏":
            registry.tools["false_positive_check"].requires = ("event",)  # run 仍读 asset_observation
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
            raise MatrixError(f"未知变异 {mutation}")

        return run_matrix(server)
    finally:
        mcp_server_module.OBSERVATION_ARGUMENTS = original_obs
        McpServer._list_tools = original_list


def run_mutation() -> int:
    print("== 变异验证：每次退化都必须让门禁 FAIL ==")
    ok = True
    for name, desc in _MUTATIONS:
        result = _apply_and_run(name)
        verdict = "PASS" if result.failures else "FAIL(空洞绿!)"
        ok = ok and bool(result.failures)
        first = result.failures[0][:110] if result.failures else "（无）"
        print(f"  [{verdict}] {name}: {desc}")
        print(f"           -> 报出 {len(result.failures)} 条，首条: {first}")
    print(f"\n=== 变异验证 {'全部通过' if ok else '存在空洞绿'} ===")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--mutate" in argv:
        return run_mutation()

    print("== 全工具出口矩阵门禁 ==")
    result = run_matrix(make_server())
    print(f"  断言 {result.checked} 条，失败 {len(result.failures)} 条")
    for line in result.failures[:20]:
        print(f"  [FAIL] {line}")
    if result.failures:
        print("\n=== GATE FAILED ===")
        return 2
    print("\n=== GATE PASSED ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
