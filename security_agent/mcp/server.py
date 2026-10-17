"""MCP Server：纯标准库实现（阶段 7）。

通过 stdio 使用 JSON-RPC 2.0 提供 MCP 核心方法：
- initialize   ：协议握手
- ping         ：存活探测（标准客户端 KeepAlive 会发）
- tools/list   ：返回工具清单（从 ToolRegistry 动态生成）
- tools/call   ：调用指定工具（fail-open：异常返回 error 不崩溃）

设计原则：
1. 零依赖：不依赖 `mcp` python 包，纯标准库 json/sys，`pip install` 失败不影响
2. 动态注册：从 ToolRegistry 自动发现工具，新增工具无需改 MCP 层
3. fail-open：任何异常返回 JSON-RPC error，进程不退出

协议合规（2026-10-14 修复，此前这三处使标准客户端无法对通）：
- 通知不响应：`notifications/initialized` 曾回一条 id=null 的 -32601 错误；
- 支持 `ping`；
- `tools/call` 声明与实现对齐：`_list_tools` 声明 `{kwargs:{...}}` 而实现读扁平键，
  且 `event` 以 JSON dict 传入（工具要求 SecurityEvent 属性），
  导致**10 个工具经 MCP 一个也调不动**——见 `_coerce_event` 与下方 schema。

链路可通性（2026-10-14 二次修复）：
- 上游观察结果同样需要 dict→`ToolObservation` 还原（见 `_coerce_observation`）。
  此前只还原了 `event`、漏了 observation，使 `false_positive_check` /
  `incident_triage` 在 MCP 通道上无法完成「上游输出回传下游」的唯一可行用法，
  即**研判主入口不可达**。工具单测与 `tools/list` 均照不出此问题，
  只有串起完整链路的出口集成断言能照出。

声明与实现同源（2026-10-14 三次修复）：
- `tools/list` 的 `inputSchema.required` 改为逐工具取自 `Tool.requires`。
  此前对所有工具硬编码 `["event"]`，而实测 11 个工具中 6 个只传 event 必然
  失败——声明即失真，遵循声明的客户端调不动。`command_executor` 更极端：
  它不读 `event`，唯一必需入参是 `command`。
- 失败提示改为点名「缺少必需参数: X」；此前用 `"NoneType" in str(exc)`
  一刀切，把缺 `command` 也归因为"缺上游阶段参数"，把调用方引向错误方向。
"""
from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Optional

from security_agent.console import use_utf8_stdio

PROTOCOL_VERSION = "2024-11-05"

# 需要由 dict 还原为 ToolObservation 的参数名。
# 必须与 `_call_tool` 的转发、以及 `TOOL_ARGUMENT_SCHEMA` 的声明保持一致：
# 三者任一处漏项，都会让依赖该参数的工具在协议层静默不可用。
OBSERVATION_ARGUMENTS = (
    "asset_observation",
    "log_observation",
    "intel_observation",
    "history_observation",
    "false_positive_observation",
)


class McpServer:
    """极简 MCP server（stdio + JSON-RPC 2.0）。"""

    # 工具实际接受的参数键 —— 必须与 `_call_tool` 的转发清单逐项一致。
    # 声明（inputSchema）与实现不一致时，任何遵循声明的客户端都会调用失败。
    TOOL_ARGUMENT_SCHEMA: dict[str, dict] = {
        "event": {
            "type": "object",
            "description": "安全事件，至少含 id/host；带 id 时按 id 取权威事件",
        },
        "analysis": {"type": "object", "description": "上一阶段研判结论（可选）"},
        "command": {"type": "string", "description": "命令文本（仅命令类工具需要，可选）"},
        "asset_observation": {"type": "object", "description": "资产观察结果（可选）"},
        "log_observation": {"type": "object", "description": "日志观察结果（可选）"},
        "intel_observation": {"type": "object", "description": "情报观察结果（可选）"},
        "history_observation": {"type": "object", "description": "历史告警观察结果（可选）"},
        "false_positive_observation": {
            "type": "object",
            "description": "误报判定依据（可选）",
        },
    }

    def __init__(self, tool_registry):
        self.tool_registry = tool_registry

    # ── 对外入口 ──────────────────────────────────────────
    def serve_stdio(self) -> None:
        """从 stdin 逐行读 JSON-RPC 请求，处理后写回 stdout（flush 保证即时）。

        传输层不变量：**本通道两端一律 UTF-8**。响应用 `ensure_ascii=False`
        直写中文，而英文 Windows（ANSI 代码页 cp1252）的管道 stdout 编码是
        cp1252 ⇒ 一写中文就 `UnicodeEncodeError` 整个进程退出；读入侧同理，
        按 cp1252 解 UTF-8 请求会**静默解错**（不报错、只是内容不对）。
        放在这里而不是只放在 `cli.py`：下游平台有自己的 stdio 启动入口，
        不一定经本项目的 CLI —— 传输边界才是这条不变量该待的地方。
        """
        use_utf8_stdio()
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
        """处理单条 JSON-RPC 消息（供测试直接调用）。

        **通知（无 `id`）必须返回 None**：JSON-RPC 2.0 规定通知不得被响应。
        此前对 `notifications/initialized` 回了一条 id=null 的 -32601 错误，
        标准客户端（官方 go-sdk 等）会把它当成不符合预期的消息。
        """
        if "id" not in message:
            return None  # 通知：按协议不响应

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
        if method == "ping":
            # 标准客户端（官方 SDK 的 KeepAlive）会发 ping；此前回 -32601 易被判为不可用
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
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
        """从 ToolRegistry 动态生成工具清单。

        每个工具的 `required` 取自 `Tool.requires`（工具自己声明的必需入参，
        与 `run()` 实际读取的键同源），**不再对所有工具硬编码 `["event"]`**。

        2026-10-14 修复：硬编码曾使 11 个工具中的 6 个「声明与实现不符」——
        `playbook_matcher` / `ticket_generator` / `host_isolation_simulator`
        实际需要 `analysis`，`false_positive_check` / `incident_triage` 需要
        `*_observation`，而 `command_executor` 根本不要 `event` 只要 `command`。
        遵循声明的客户端按 `required` 传参，必然调用失败。
        """
        tools = []
        for name, tool in self.tool_registry.tools.items():
            doc = (tool.__class__.__doc__ or "").strip().split("\n")[0]
            required = list(getattr(tool, "requires", ()) or ("event",))
            extra = [key for key in required if key != "event"]
            description = doc or f"安全工具: {name}"
            if extra:
                # 让客户端一眼看出「这个工具不是只传 event 就能调」，
                # 而不是调用失败后再靠报错反推。
                description = f"{description}（另需 {'/'.join(extra)}）"
            tools.append(
                {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "type": "object",
                        "properties": dict(self.TOOL_ARGUMENT_SCHEMA),
                        "required": required,
                    },
                }
            )
        return tools

    @staticmethod
    def _coerce_event(payload: Any) -> Any:
        """把 MCP 传入的事件 JSON 还原为 `SecurityEvent`。

        工具签名的 `event` 是 SecurityEvent（读 `event.host` 等属性）；直接传 dict
        会以 `AttributeError: 'dict' object has no attribute 'host'` 失败。优先按
        `id` 取库内权威事件（字段最全，与 Web/CLI 同源），取不到再按字段构造。
        """
        if not isinstance(payload, dict):
            return payload
        if payload.get("id"):
            try:
                from security_agent.intake.service import EventIntakeService

                return EventIntakeService.default().get_event(str(payload["id"]))
            except Exception:  # noqa: BLE001 - 取不到就走字段构造
                pass
        try:
            from security_agent.agent.models import SecurityEvent

            fields = {
                k: v for k, v in payload.items() if k in SecurityEvent.__dataclass_fields__
            }
            return SecurityEvent(**fields)
        except Exception:  # noqa: BLE001 - 构造失败则原样返回，由工具侧 fail-open 处理
            return payload

    @staticmethod
    def _coerce_observation(payload: Any) -> Any:
        """把 MCP 传入的观察结果 JSON 还原为 `ToolObservation`。

        与 `_coerce_event` 成对：一个还原事件，一个还原上游观察结果。

        **为什么必须做**：工具内部按*属性*访问观察结果
        （`asset_observation.details`），而 JSON-RPC 只能传 JSON。调用方把上游
        `asset_lookup` 的输出原样回传时是个 dict，不做还原即
        `AttributeError: 'dict' object has no attribute 'details'` ——
        结果是 `false_positive_check` 与 `incident_triage`（研判主入口）
        这两个依赖上游的工具**在 MCP 通道上永远调不通**，整条研判链路断在
        协议层，而工具单测与 `tools/list` 都照不出这个问题。
        """
        if not isinstance(payload, dict):
            return payload
        try:
            from security_agent.agent.models import ToolObservation

            known = set(ToolObservation.__dataclass_fields__)
            return ToolObservation(**{k: v for k, v in payload.items() if k in known})
        except Exception:  # noqa: BLE001 - 还原失败原样返回，由工具侧 fail-open 处理
            return payload

    @staticmethod
    def _missing_required(tool, arguments: dict) -> list[str]:
        """列出「工具声明必需、但调用方没给」的入参键。

        提示必须**点名具体参数**：此前用 `"NoneType" in str(exc)` 一刀切，
        把 `command_executor` 缺 `command` 也归因为"缺上游阶段参数"，
        提示调用方去补 `analysis` / `*_observation` —— 方向完全错了，
        LLM 客户端会照着提示补一堆无关参数并反复空转。
        """
        return [
            key
            for key in (getattr(tool, "requires", ()) or ())
            if arguments.get(key) is None
        ]

    def _call_tool(self, name: str, arguments: dict) -> dict:
        """调用工具并序列化结果（fail-open：未知工具/异常均返回 isError 不崩溃）。"""
        try:
            tool = self.tool_registry.get(name)
        except KeyError:
            return {
                "content": [{"type": "text", "text": f"未知工具: {name}"}],
                "isError": True,
            }

        arguments = arguments or {}
        # 兼容两种传参：按声明 `{"kwargs": {...}}` 包裹，或扁平直传。
        # 历史实现只读扁平键，却对外声明 `kwargs` 包裹 —— 契约自相矛盾，
        # 遵循声明的客户端必然全挂。
        if isinstance(arguments.get("kwargs"), dict):
            arguments = {
                **arguments["kwargs"],
                **{k: v for k, v in arguments.items() if k != "kwargs"},
            }
        # `event` 必须是 SecurityEvent：工具读 event.host 等属性，传 JSON dict 会
        # AttributeError。这是「10 个工具经 MCP 一个也调不动」的直接根因。
        event = self._coerce_event(arguments.get("event"))

        # 上游观察结果同理：工具按属性读 `.summary` / `.details`，必须还原为
        # ToolObservation，否则调用方「把上游输出回传下游」这条唯一可行用法
        # 必然 AttributeError（false_positive_check / incident_triage 首当其冲）。
        observations = {
            key: self._coerce_observation(arguments.get(key))
            for key in OBSERVATION_ARGUMENTS
        }

        try:
            # 工具依赖 kwargs（event/knowledge_hub 等），构造最小环境
            from security_agent.app import build_app

            app = build_app()
            result = tool.run(
                event=event,
                knowledge_hub=app.knowledge_hub,
                analysis=arguments.get("analysis"),
                command=arguments.get("command"),
                **observations,
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
            # 失败提示必须可操作：点名「缺哪个参数」，而不是抛一句原始报错。
            # 调用方是 LLM，拿不到可纠正的信息就会反复空转。
            missing = self._missing_required(tool, arguments)
            if missing:
                hint = f"（缺少必需参数: {', '.join(missing)}）"
            elif "NoneType" in str(exc):
                hint = (
                    "（该工具依赖上游阶段参数：请在 arguments 中一并提供 "
                    "analysis / *_observation 中相应的字段，仅传 event 不足以调用）"
                )
            else:
                hint = ""
            return {
                "content": [{"type": "text", "text": f"工具执行失败: {exc}{hint}"}],
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
