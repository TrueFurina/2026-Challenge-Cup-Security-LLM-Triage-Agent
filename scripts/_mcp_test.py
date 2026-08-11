"""阶段 7 MCP 集成测试。

用法: python scripts/_mcp_test.py
验证：
1. tools/list 返回工具清单（≥10 个）
2. tools/call 调用工具返回结构化结果（asset_lookup）
3. 未知 method 返回 JSON-RPC error
4. 未知工具返回 isError
5. serve-mcp CLI 管道收发（echo 一条请求 → 读响应）
"""
import json
import os
import subprocess
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from security_agent.mcp import McpServer  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}: actual={actual!r} expected={expected!r}")
    PASS += int(ok)
    FAIL += int(not ok)


def make_server():
    from security_agent.app import build_app

    app = build_app()
    return McpServer(tool_registry=app.tool_registry)


def list_tools_tests():
    print("== 1. tools/list ==")
    server = make_server()
    resp = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    check("返回 result.tools", "tools" in resp.get("result", {}), True)
    tools = resp["result"]["tools"]
    check("工具数 >= 10", len(tools) >= 10, True)
    names = {t["name"] for t in tools}
    check("含 asset_lookup", "asset_lookup" in names, True)
    check("含 ioc_search", "ioc_search" in names, True)
    check("每工具含 description", all("description" in t for t in tools), True)


def call_tool_tests():
    print("== 2. tools/call ==")
    server = make_server()
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "asset_lookup", "arguments": {}},
        }
    )
    check("返回 result.content", "content" in resp.get("result", {}), True)
    text = resp["result"]["content"][0]["text"]
    check("调用结果可序列化", isinstance(text, str) and len(text) > 0, True)


def error_tests():
    print("== 3. 错误处理 ==")
    server = make_server()
    resp = server.handle({"jsonrpc": "2.0", "id": 3, "method": "unknown/method"})
    check("未知 method → error", "error" in resp, True)
    check("error code -32601", resp["error"]["code"], -32601)

    resp2 = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}},
        }
    )
    check("未知工具 → isError", resp2["result"]["isError"], True)


def initialize_tests():
    print("== 4. initialize 握手 ==")
    server = make_server()
    resp = server.handle({"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {}})
    check("协议版本", resp["result"]["protocolVersion"], "2024-11-05")
    check("能力含 tools", "tools" in resp["result"]["capabilities"], True)


def cli_pipe_tests():
    print("== 5. serve-mcp CLI 管道 ==")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "security_agent.cli", "serve-mcp"],
            input=request + "\n",
            capture_output=True,
            text=True,
            timeout=60,
            cwd=PROJECT_DIR,
        )
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        check("stdout 有 JSON 响应", len(lines) >= 1, True)
        if lines:
            resp = json.loads(lines[0])
            check("响应含 tools", "tools" in resp.get("result", {}), True)
            check("工具数 >= 10", len(resp["result"]["tools"]) >= 10, True)
    except subprocess.TimeoutExpired:
        check("serve-mcp 管道未超时", False, True)


def main() -> int:
    list_tools_tests()
    call_tool_tests()
    error_tests()
    initialize_tests()
    cli_pipe_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
