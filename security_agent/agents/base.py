"""BaseAgent 抽象接口（阶段 3.1）。

每个 Agent 独立负责一个协作环节，输入输出统一为 AgentInput/AgentOutput，
前序 Agent 的 data 会合并进后续 Agent 的 context，形成顺序协作链。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AgentInput:
    """Agent 输入：事件 + 共享上下文（前序 Agent 输出 + 工具观测）。"""

    event: Any
    context: dict = field(default_factory=dict)  # 共享上下文，贯穿全链路
    knowledge_items: list = field(default_factory=list)
    plan: list = field(default_factory=list)
    llm: Any = None  # LLM 客户端（可选，Agent 自行决定是否使用）


@dataclass
class AgentOutput:
    """Agent 输出：发现 + 摘要 + 结构化数据（传给下一 Agent）。"""

    agent_name: str
    findings: list[str] = field(default_factory=list)
    summary: str = ""
    data: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    error: str = ""  # 非空表示该步骤降级（fail-open），链路继续


class BaseAgent(ABC):
    """Agent 抽象基类：每个 Agent 可独立测试、可 mock。"""

    name: str = ""
    role: str = ""
    used_tools: list[str] = []
    timeout_seconds: float = 30.0

    @abstractmethod
    def run(self, agent_input: AgentInput) -> AgentOutput:
        """执行 Agent 环节，返回结构化输出。"""
        raise NotImplementedError

    def summarize(self, agent_input: AgentInput, output: AgentOutput) -> AgentOutput:
        """统一包装：给输出补充 agent_name（子类可覆写增加日志）。"""
        output.agent_name = output.agent_name or self.name
        return output
