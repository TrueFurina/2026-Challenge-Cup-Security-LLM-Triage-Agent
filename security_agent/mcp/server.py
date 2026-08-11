"""MCP Server：纯标准库实现（阶段 7）。

通过 stdio 使用 JSON-RPC 2.0 提供 MCP 核心方法：
- initialize   ：协议握手
- tools/list   ：返回工具清单（从 ToolRegistry 动态生成）
- tools/call   ：调用指定工具（fail-open：异常返回 error 不崩溃）

设计原则：
1. 零依赖：不依赖 `mcp` python 包，纯标准库 json/sys，`pip install` 失败不影响
2. 动态注册：从 ToolRegistry 自动发现工具，新增工具无需改 MCP 层
3. fail-open：任何异常返回 JSON-RPC error，进程不退出
"""
from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Optional

PROTOCOL_VERSION = "2024-11-05"


class McpServer:
    """极简 MCP server（stdio + JSON-RPC 2.0）。"""

    def __init__(self, tool_registry):
        self.tool_registry = tool_registry

    # ── 对外入口 ──────────────────────────────────────────
    def serve_stdio(self) -> None:
        """从 stdin 逐行读 JSON-RPC 请求，处理后写回 stdout（flush 保证即时）。"""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._write_error(-32700, "Parse error")
                continue
            response = self.handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                sys.stdout.flush()

    def handle(self, message: dict) -> Optional[dict]:
        """处理单条 JSON-RPC 消息（供测试直接调用）。"""
        request_id = message.get("id")
        method = message.get("method")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "security-agent-mcp", "version": "0.1.0"},
                },
            }
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": self._list_tools()},
            }
        if method == "tools/call":
            params = message.get("params", {}) or {}
            name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": self._call_tool(name, arguments),
            }
        # 未知方法 → JSON-RPC Method not found
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    # ── 内部 ──────────────────────────────────────────────
    def _list_tools(self) -> list[dict]:
        """从 ToolRegistry 动态生成工具清单。"""
        tools = []
        for name, tool in self.tool_registry.tools.items():
            doc = (tool.__class__.__doc__ or "").strip().split("\n")[0]
            tools.append(
                {
                    "name": name,
                    "description": doc or f"安全工具: {name}",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"kwargs": {"type": "object", "description": "工具参数"}},
                    },
                }
            )
        return tools

    def _call_tool(self, name: str, arguments: dict) -> dict:
        """调用工具并序列化结果（fail-open：未知工具/异常均返回 isError 不崩溃）。"""
        try:
            tool = self.tool_registry.get(name)
        except KeyError:
            return {
                "content": [{"type": "text", "text": f"未知工具: {name}"}],
                "isError": True,
            }

        try:
            # 工具依赖 kwargs（event/knowledge_hub 等），构造最小环境
            from security_agent.app import build_app

            app = build_app()
            result = tool.run(
                event=arguments.get("event"),
                knowledge_hub=app.knowledge_hub,
                analysis=arguments.get("analysis"),
                command=arguments.get("command"),
                asset_observation=arguments.get("asset_observation"),
                log_observation=arguments.get("log_observation"),
                intel_observation=arguments.get("intel_observation"),
                history_observation=arguments.get("history_observation"),
                false_positive_observation=arguments.get("false_positive_observation"),
            )
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            self._serialize(result), ensure_ascii=False
                        ),
                    }
                ],
                "isError": False,
            }
        except Exception as exc:  # noqa: BLE001 - MCP 工具调用异常不崩溃
            return {
                "content": [{"type": "text", "text": f"工具执行失败: {exc}"}],
                "isError": True,
            }

    @staticmethod
    def _serialize(result: Any) -> Any:
        """把 ToolObservation/dict/list 转为可 JSON 序列化结构。"""
        if hasattr(result, "to_dict"):
            return result.to_dict()
        if hasattr(result, "__dict__") and not isinstance(result, dict):
            return {k: McpServer._serialize(v) for k, v in vars(result).items()}
        if isinstance(result, list):
            return [McpServer._serialize(item) for item in result]
        if isinstance(result, dict):
            return {k: McpServer._serialize(v) for k, v in result.items()}
        return result

    def _write_error(self, code: int, message: str) -> None:
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}, ensure_ascii=False)
            + "\n"
        )
        sys.stdout.flush()


class McpToolError(Exception):
    """MCP 工具调用错误。"""
