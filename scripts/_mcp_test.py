"""阶段 7 MCP 集成测试。

用法: python scripts/_mcp_test.py
验证：
1. tools/list 返回工具清单（≥10 个）
2. tools/call **真的调通**工具（断言 isError=False 与结构化结果，不只看返回形状）
3. 未知 method 返回 JSON-RPC error
4. 未知工具返回 isError
5. serve-mcp CLI 管道收发（echo 一条请求 → 读响应）
6. 协议合规：通知不响应 / ping 可用 / inputSchema 声明与实现一致

（2026-10-14 修订：第 2 节原为「空洞绿」——只断言 content 存在、text 非空，
而失败返回的正是「工具执行失败: ...」，因此 10 个工具全部不可用时该节依然全绿。
现改为断言真实成败，并补第 6 节协议合规与契约一致性。）
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
    # MCP 客户端只能给 JSON，因此 event 以 dict 传入 —— 服务端必须还原为
    # SecurityEvent。此前不还原，工具读 event.host 直接 AttributeError，
    # 10 个工具经 MCP 一个也调不动。
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "asset_lookup", "arguments": {"event": {"id": "EVENT-001"}}},
        }
    )
    result = resp.get("result", {})
    check("返回 result.content", "content" in result, True)
    text = result["content"][0]["text"]
    check("调用结果可序列化", isinstance(text, str) and len(text) > 0, True)

    # ── 关键断言：必须断言「真的成功了」 ─────────────────────────
    # 旧版只断言 content 存在 + text 非空字符串，而失败返回的正是
    # "工具执行失败: ..." —— 于是 10 个工具全部报错时本测试照样全绿。
    # 这是典型的「空洞绿」：断言了形状，没断言成败。
    check("工具调用未失败 isError=False", result.get("isError"), False)
    check("未出现失败文案", "工具执行失败" in text, False)
    payload = json.loads(text)
    check("结果为结构化对象", isinstance(payload, dict), True)
    check("含 tool_name", payload.get("tool_name"), "asset_lookup")
    check("summary 非空", bool(payload.get("summary")), True)

    # 兼容两种传参：按声明 `{"kwargs": {...}}` 包裹 与 扁平直传，二者结果必须一致
    wrapped = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "asset_lookup",
                "arguments": {"kwargs": {"event": {"id": "EVENT-001"}}},
            },
        }
    )
    check("kwargs 包裹传参同样成功", wrapped["result"].get("isError"), False)
    check("两种传参结果一致", wrapped["result"]["content"][0]["text"], text)

    # 只传 event 即可调用的工具（其余需上游参数，属设计如此，另有测试覆盖）
    for tool_name in ("log_lookup", "intel_lookup", "history_alert_lookup", "ioc_search"):
        r = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": {"event": {"id": "EVENT-001"}}},
            }
        )["result"]
        check(f"{tool_name} 经 MCP 可调用", r.get("isError"), False)

    # 依赖上游参数的工具：失败信息必须可操作（告诉调用方缺什么），
    # 而不是抛一个 LLM 无法据以纠正的裸 AttributeError 文案。
    dep = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {"name": "incident_triage", "arguments": {"event": {"id": "EVENT-001"}}},
        }
    )["result"]
    check("缺上游参数 → isError", dep.get("isError"), True)
    check("缺参提示可操作（指明补 analysis/*_observation）", "依赖上游阶段参数" in dep["content"][0]["text"], True)


def protocol_tests():
    print("== 6. MCP 协议合规 ==")
    server = make_server()
    # 通知不得被响应：此前对 notifications/initialized 回了一条 id=null 的
    # -32601 错误，标准客户端会收到一条不符合预期的消息。
    check(
        "通知不产生任何响应",
        server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        None,
    )
    check(
        "无 id 的自定义通知同样不响应",
        server.handle({"jsonrpc": "2.0", "method": "exit"}),
        None,
    )
    ping = server.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})
    check("ping 有响应", ping is not None, True)
    check("ping 返回空 result", ping.get("result"), {})

    # 声明(inputSchema) 必须与实现(_call_tool 转发) 一致
    tools = server.handle({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})["result"]["tools"]
    schema = tools[0]["inputSchema"]
    check("声明含 event", "event" in schema["properties"], True)
    check("声明不再用与实现不符的 kwargs 包裹", "kwargs" in schema["properties"], False)
    check("required 为 [event]", schema.get("required"), ["event"])
    check("声明键集与实现转发键集一致", set(schema["properties"]), set(server.TOOL_ARGUMENT_SCHEMA))
    check("全部工具 schema 一致", all(t["inputSchema"] == schema for t in tools), True)


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


def upstream_passthrough_tests():
    """上游观察结果「回传下游」必须可用（2026-10-14 修复的两处同族缺陷）。

    为什么单列一节：`tools/list` 与单工具调用都只能证明「单个工具能调」，
    照不出两类问题——
    (1) 调用方把上游工具输出回传下游时，协议层的 dict → ToolObservation 不还原；
    (2) fail-open 把入参契约错配伪装成「成功」（返回 isError=False 却一步没做）。
    只有把链路串起来才暴露，故此处按真实链路断言。
    """
    print("== 7. 上游结果回传链路（防契约错配复发）==")
    server = make_server()

    def call(tool, **args):
        result = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            }
        )["result"]
        text = result["content"][0]["text"]
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
        return result.get("isError"), payload, text

    event = {"id": "EVENT-001"}
    _, asset, _ = call("asset_lookup", event=event)
    _, logs, _ = call("log_lookup", event=event)
    _, intel, _ = call("intel_lookup", event=event)
    _, history, _ = call("history_alert_lookup", event=event)

    # 缺陷 1：上游输出经 MCP 是 dict，而工具按属性读 `.details`。
    # 不还原即 AttributeError: 'dict' object has no attribute 'details'。
    err, fp, fp_text = call(
        "false_positive_check", event=event, asset_observation=asset, log_observation=logs
    )
    check("回传 dict observation 不失败", err, False)
    check("未出现属性访问错误", "has no attribute" in fp_text, False)
    check("误报剔除返回结构化结论", bool(fp.get("summary")) if isinstance(fp, dict) else False, True)

    # 缺陷 2：incident_triage 是 triage_event 的薄封装，而调用方入参形态不一
    # （MCP 带 knowledge_hub、不传 plan）。原样 `**kwargs` 转发必 TypeError，
    # 而 fail-open 会把它降级成「最简兜底结果」——返回 isError=False，
    # 调用方以为研判成功，实际一步研判都没做。
    err, triage, _ = call(
        "incident_triage",
        event=event,
        asset_observation=asset,
        log_observation=logs,
        intel_observation=intel,
        history_observation=history,
        false_positive_observation=fp,
    )
    check("研判主入口经 MCP 可调用", err, False)
    reasoning = " ".join(str(x) for x in (triage.get("reasoning_summary") or []))
    check("研判未走异常兜底", "研判模块出现异常" in reasoning, False)
    check(
        "研判产出合法风险等级",
        triage.get("risk_level") in {"low", "medium", "high", "critical"},
        True,
    )
    check("研判产出事件类型", bool(triage.get("event_type")), True)

    # 下游：处置编排依赖 incident_triage 的 analysis（dict，走下标访问，本就兼容）
    err, playbook, _ = call("playbook_matcher", event=event, analysis=triage)
    check("playbook_matcher 可消费研判结论", err, False)
    err, ticket, _ = call("ticket_generator", event=event, analysis=triage)
    check("ticket_generator 可消费研判结论", err, False)


def main() -> int:
    list_tools_tests()
    call_tool_tests()
    error_tests()
    initialize_tests()
    cli_pipe_tests()
    protocol_tests()
    upstream_passthrough_tests()
    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
