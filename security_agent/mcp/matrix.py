"""MCP 全工具出口矩阵检查（库侧）。

放在库内而非脚本里，是为了让**上游门禁脚本**与**下游接入方自检**共用同一份
逻辑，避免维护第二份清单（这是本项目的既有纪律：清单只允许有一处事实源）。

为什么需要（2026-10-14 立项）
----------------------------
本项目已三度踩中**同一族**缺陷：能力实现了、但出口没接线，或被 fail-open
伪装成成功——

  (1) `event` 是 dict 而非 SecurityEvent  → 10 个工具经 MCP 一个都调不动；
  (2) observation 未还原为 ToolObservation → `false_positive_check` /
      `incident_triage`（研判主入口）恒不可达；
  (3) `inputSchema.required` 对所有工具硬编码 `["event"]`，而 11 个工具里
      6 个实际还需要 `analysis` / `*_observation`，`command_executor` 更只要
      `command` —— 声明失真，遵循声明的客户端必然调不动。

`_mcp_test.py` 的覆盖是**手写白名单**，逐工具枚举：新增工具若漏进白名单，
缺陷会静默复发。本模块改为**动态遍历 tools/list**，并做**双向断言**：

  充分性：只给「工具自己声明必需的参数」→ 必须调用成功（声明不虚报）；
  必要性：逐个抽掉声明的必需参数      → 必须调用失败且点名（声明不遗漏）。

只测充分性会漏掉"声明少了参数"，只测必要性会漏掉"声明多了参数"。
两者同时成立，`required` 才真正等于实现契约。

另有两条接线断言：工具声明的必需参数必须都在 MCP 层**可转发**的键集内
（否则调用必然失败）；observation 还原清单必须等于全部工具所需 observation
的并集（少一项，依赖它的工具就静默不可用）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

# ── 链路拓扑：参数键 ← 生产者 ─────────────────────────────────
# 这是唯一一处需要人写的东西，且**不是第二份契约清单**：它只描述"谁产出谁"。
# 新的必需参数若没有生产者，检查会 fail-loud 地报出来（见 _provide）。
LITERALS: dict[str, object] = {
    "event": {"id": "EVENT-001"},
    "command": "echo mcp-matrix-check",
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


class MatrixError(Exception):
    """检查内部的结构性错误（非被测对象的失败），例如拓扑成环、参数无生产者。"""


@dataclass
class MatrixResult:
    """一次矩阵检查的结果。"""

    checked: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


class ToolMatrix:
    """对「MCP 通道上每个工具是否真实可调用」做双向断言。

    `server` 需是 `McpServer` 实例（或其鸭子类型：具备 `handle` /
    `tool_registry` / `OBSERVATION_ARGUMENTS` 语义）。
    """

    #: MCP 层 `_call_tool` 实际会转发的键（event/analysis/command + observations）
    FORWARD_EXTRA = ("analysis", "command")

    def __init__(self, server, observation_arguments: tuple[str, ...]):
        self.server = server
        self.registry = server.tool_registry
        self.observation_arguments = tuple(observation_arguments)
        self.result = MatrixResult()
        self._memo: dict[str, object] = {}

    # ── 基础设施 ─────────────────────────────────────────
    def _fail(self, msg: str) -> None:
        self.result.failures.append(msg)

    def _check(self, cond: bool, msg: str) -> None:
        self.result.checked += 1
        if not cond:
            self._fail(msg)

    def _listed_tools(self) -> list[dict]:
        return self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]

    def _raw_call(self, name: str, arguments: dict) -> tuple[bool, object, str]:
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
                raise MatrixError(f"链路拓扑成环: {' -> '.join((*stack, source))}")
            value = self.invoke_minimal(source, stack=(*stack, source))[1]
        else:
            # 工具声明了一个谁都不产出的必需参数 —— 这正是"接线断了"。
            raise MatrixError(
                f"参数 {key!r} 没有任何生产者；请在 TOOL_SOURCES 中登记产出它的工具，"
                "否则该工具在 MCP 通道上无从调用"
            )
        self._memo[key] = value
        return value

    def invoke_minimal(self, name: str, stack: tuple[str, ...] = ()) -> tuple[bool, object, str]:
        """只按工具自己声明的必需参数调用它。"""
        tool = self.registry.tools[name]
        args = {key: self._provide(key, stack) for key in tool.requires}
        return self._raw_call(name, args)

    # ── 断言 ─────────────────────────────────────────────
    def _assert_fallback_free(self, name: str, err: bool, text: str, ctx: str) -> None:
        self._check(not err, f"[{name}] {ctx}: 调用失败 → {text[:120]}")
        for marker in FALLBACK_MARKERS:
            self._check(
                marker not in text,
                f"[{name}] {ctx}: 命中兜底/异常文案 {marker!r} → {text[:120]}",
            )

    def run(self) -> MatrixResult:
        listed = self._listed_tools()
        names = [t["name"] for t in listed]
        self._check(len(names) == len(set(names)), "tools/list 存在重名工具")
        self._check(
            len(names) == len(self.registry.tools),
            f"tools/list 列出 {len(names)} 个工具，registry 却有 {len(self.registry.tools)} 个"
            "（清单漏列 = 客户端根本看不到该工具，属接线缺陷）",
        )

        forwardable = {"event", *self.FORWARD_EXTRA, *self.observation_arguments}

        # ── 1. 声明自洽 + 接线完整 ────────────────────────
        for entry in listed:
            name = entry["name"]
            tool = self.registry.tools[name]
            schema = entry["inputSchema"]
            required = list(schema["required"])
            self._check(
                required == list(tool.requires),
                f"[{name}] inputSchema.required={required} 与 Tool.requires={list(tool.requires)} 不一致",
            )
            self._check(bool(required), f"[{name}] required 为空（客户端无从按声明传参）")
            self._check(
                set(required) <= set(schema["properties"]),
                f"[{name}] required {required} 有键不在 inputSchema.properties 中",
            )
            undeclared = set(required) - forwardable
            self._check(
                not undeclared,
                f"[{name}] required 含 MCP 层不转发的键 {sorted(undeclared)} → 必然调不动（接线断了）",
            )

        # ── 2. 还原清单完备 ──────────────────────────────
        needed_obs = {
            k
            for t in listed
            for k in self.registry.tools[t["name"]].requires
            if k.endswith("_observation")
        }
        self._check(
            set(self.observation_arguments) == needed_obs,
            f"observation 还原清单={sorted(self.observation_arguments)} 与工具实际所需的 "
            f"{sorted(needed_obs)} 不一致（少还原一项，依赖它的工具就静默不可用）",
        )

        # ── 3. 充分性：按声明的最小集必须调得通 ────────────
        for name in names:
            try:
                err, _payload, text = self.invoke_minimal(name)
            except MatrixError as exc:
                self._fail(f"[{name}] 最小必需参数集无法装配: {exc}")
                continue
            self._assert_fallback_free(name, err, text, "最小必需参数集")

        # ── 4. 必要性：逐个抽掉声明的必需参数，必须失败且点名 ──
        for name in names:
            tool = self.registry.tools[name]
            for key in tool.requires:
                memo_backup = dict(self._memo)
                try:
                    args = {k: self._provide(k) for k in tool.requires if k != key}
                except MatrixError as exc:
                    self._fail(f"[{name}] 抽掉 {key!r} 后参数集无法装配: {exc}")
                    continue
                finally:
                    self._memo = memo_backup
                err, _payload, text = self._raw_call(name, args)
                self._check(
                    err,
                    f"[{name}] 抽掉声明必需的 {key!r} 后仍返回成功 —— 该参数其实不必需，"
                    "声明虚报了依赖",
                )
                if err:
                    self._check(
                        key in text,
                        f"[{name}] 缺 {key!r} 的失败提示未点名该参数 → {text[:120]}",
                    )

        return self.result
