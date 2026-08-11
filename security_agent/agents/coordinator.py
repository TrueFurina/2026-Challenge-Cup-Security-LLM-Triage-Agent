"""AgentCoordinator 顺序编排器（阶段 3.3）。

串行调用 4 个协作 Agent，前序 Agent 输出作为后序 Agent 输入：
TriageAgent → HuntAgent → RespondAgent → ReportAgent

设计原则：
1. 任一步骤失败 → 降级到已有结论，不中断（fail-open）
2. 共享上下文 context 贯穿全链路，记录每步输入/输出供审计
3. 每个 Agent 可 mock（外部注入 agent 列表）
"""
from __future__ import annotations

import time
from typing import Any, Optional

from security_agent.agents.base import AgentInput, AgentOutput, BaseAgent


class AgentCoordinator:
    """多 Agent 顺序协作编排器。"""

    def __init__(self, agents: Optional[list[BaseAgent]] = None):
        self.agents = agents  # 默认在 run() 时由 default_agents() 构造

    @classmethod
    def default_agents(cls) -> list[BaseAgent]:
        from security_agent.agents.impl import (
            HuntAgent,
            ReportAgent,
            RespondAgent,
            TriageAgent,
        )

        return [TriageAgent(), HuntAgent(), RespondAgent(), ReportAgent()]

    def coordinate(self, agent_input: AgentInput) -> dict:
        """执行全链路协作，返回 {agent_records, final_report, context}。"""
        agents = self.agents or self.default_agents()
        context = dict(agent_input.context)
        agent_records: list[dict] = []
        started = time.perf_counter()

        # 注入处置/狩猎工具到 context（供 Respond/Hunt Agent 使用）
        if "tool_registry" in context:
            registry = context["tool_registry"]
            context.setdefault("playbook_matcher", registry.get("playbook_matcher"))
            context.setdefault("ticket_generator", registry.get("ticket_generator"))
            context.setdefault("host_isolation_simulator", registry.get("host_isolation_simulator"))
            context.setdefault("ioc_search", registry.get("ioc_search"))

        current_input = agent_input
        for agent in agents:
            step_started = time.perf_counter()
            try:
                output = agent.run(current_input)
            except Exception as exc:  # noqa: BLE001 - fail-open：外部 Agent 异常也降级不中断
                output = AgentOutput(
                    agent_name=agent.name,
                    findings=[f"{agent.name} 异常: {exc}"],
                    summary=f"{agent.name} 降级：异常",
                    error=str(exc),
                )
            output.duration_ms = (time.perf_counter() - step_started) * 1000

            # 按 Agent 名写入共享上下文（Triage → triage, Hunt → hunt, ...）
            slot = agent.name.split()[0].lower()
            context[slot] = output.data

            agent_records.append(
                {
                    "name": agent.name,
                    "role": agent.role,
                    "used_tools": agent.used_tools,
                    "findings": output.findings,
                    "summary": output.summary,
                    "error": output.error,
                    "duration_ms": round(output.duration_ms, 2),
                }
            )

            # 前序输出作为后序输入：重建 AgentInput，context 指向共享上下文
            current_input = AgentInput(
                event=agent_input.event,
                context=context,
                knowledge_items=agent_input.knowledge_items,
                plan=agent_input.plan,
                llm=agent_input.llm,
            )

        final_report = context.get("report", {})
        if isinstance(final_report, dict) and "report" in final_report:
            final_report = final_report["report"]
        return {
            "agent_records": agent_records,
            "final_report": final_report,
            "context": context,
            "total_duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "agents_ok": all(not record["error"] for record in agent_records),
        }
