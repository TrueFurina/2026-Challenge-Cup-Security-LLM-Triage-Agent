"""四个协作 Agent 实现（阶段 3.2）。

数据流：
TriageAgent（初判）→ HuntAgent（威胁狩猎）→ RespondAgent（处置建议）→ ReportAgent（汇总导出）

设计原则：
1. TriageAgent 复用 ai/triage.py 的 triage_event（不重写推理）
2. RespondAgent 复用现有 PlaybookMatcherTool / TicketGeneratorTool / HostIsolationSimulatorTool
3. 每个 Agent fail-open：任何异常返回 error 标记的 AgentOutput，链路不中断
"""
from __future__ import annotations

import time
from typing import Any, Optional

from security_agent.agents.base import AgentInput, AgentOutput, BaseAgent


class TriageAgent(BaseAgent):
    """初判：事件类型 / 风险等级 / 置信度 / 误报判断（复用现有 AI 研判）。"""

    name = "Triage Agent"
    role = "初步研判与误报剔除"
    used_tools = ["asset_lookup", "log_lookup", "intel_lookup", "history_alert_lookup", "false_positive_check"]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            from security_agent.ai.triage import triage_event

            context = agent_input.context
            analysis = triage_event(
                event=agent_input.event,
                asset_observation=context.get("asset_observation"),
                log_observation=context.get("log_observation"),
                intel_observation=context.get("intel_observation"),
                history_observation=context.get("history_observation"),
                false_positive_observation=context.get("false_positive_observation"),
                knowledge_items=agent_input.knowledge_items,
                plan=agent_input.plan,
            )
            if analysis is None:
                return AgentOutput(
                    agent_name=self.name,
                    findings=["LLM 研判不可用，TriageAgent 无有效裁决"],
                    summary="TriageAgent 降级：无裁决",
                    error="triage_event 返回 None",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            data = {
                "event_type": analysis["event_type"],
                "risk_level": analysis["risk_level"],
                "confidence": analysis["confidence"],
                "confidence_score": analysis.get("confidence_score", 0.7),
                "is_false_positive": analysis["is_false_positive"],
                "verdict": analysis["verdict"],
                "risk_score": analysis.get("risk_score"),
                "evidence": analysis.get("evidence", []),
                "recommendations": analysis.get("recommendations", []),
            }
            return AgentOutput(
                agent_name=self.name,
                findings=[
                    f"事件类型: {analysis['event_type']}",
                    f"风险等级: {analysis['risk_level']}",
                    f"置信度: {analysis['confidence']}（{data['confidence_score']}）",
                    f"误报判断: {'是' if analysis['is_false_positive'] else '否'}",
                ],
                summary=f"初判为 {analysis['event_type']} / {analysis['risk_level']}",
                data=data,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open，不中断链路
            return AgentOutput(
                agent_name=self.name,
                findings=[f"TriageAgent 异常: {exc}"],
                summary="TriageAgent 降级：异常",
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )


class HuntAgent(BaseAgent):
    """威胁狩猎：根据初判结果，用 IocSearch 工具补充调查情报命中与知识库关联。"""

    name = "Hunt Agent"
    role = "威胁狩猎与情报关联"
    used_tools = ["ioc_search", "intel_lookup"]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            event = agent_input.event
            triage_data = context.get("triage", {})

            # IocSearch：按主机/IP/域名/进程检索情报与知识库
            ioc_search = context.get("ioc_search")
            ioc_hits: list[str] = []
            if ioc_search is not None:
                ioc_hits = list(ioc_search.run(event=event, knowledge_hub=context.get("knowledge_hub")))

            # 从 intel 观测提取情报命中
            intel_obs = context.get("intel_observation")
            intel_hits = list(intel_obs.details) if intel_obs is not None else []

            hunt_findings: list[str] = []
            if ioc_hits:
                hunt_findings.append(f"IOC 情报命中: {'; '.join(ioc_hits)}")
            if intel_hits:
                hunt_findings.append(f"外联情报: {len(intel_hits)} 条")
            if not hunt_findings:
                hunt_findings.append("未发现额外威胁情报命中，维持初判结论")

            data = dict(context.get("triage", {}))
            data.update(
                {
                    "hunt_findings": hunt_findings,
                    "ioc_hits": ioc_hits,
                    "intel_hits": intel_hits,
                }
            )
            return AgentOutput(
                agent_name=self.name,
                findings=hunt_findings,
                summary="; ".join(hunt_findings[:2]),
                data=data,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"HuntAgent 异常: {exc}"],
                summary="HuntAgent 降级：异常",
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )


class RespondAgent(BaseAgent):
    """处置建议：预案匹配 + 工单生成 + 主机隔离建议。"""

    name = "Respond Agent"
    role = "处置建议与动作编排"
    used_tools = ["playbook_matcher", "ticket_generator", "host_isolation_simulator"]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            event = agent_input.event
            triage_data = dict(context.get("triage", {}))

            # 构造 analysis 结构（供现有处置工具复用）
            analysis = {
                "event_type": triage_data.get("event_type", "通用异常行为"),
                "verdict": triage_data.get("verdict", ""),
                "risk_level": triage_data.get("risk_level", "medium"),
                "confidence": triage_data.get("confidence", "low"),
                "is_false_positive": triage_data.get("is_false_positive", False),
            }

            playbook_tool = context.get("playbook_matcher")
            ticket_tool = context.get("ticket_generator")
            isolation_tool = context.get("host_isolation_simulator")

            playbook_obs = playbook_tool.run(event=event, analysis=analysis) if playbook_tool else None
            ticket_obs = ticket_tool.run(event=event, analysis=analysis) if ticket_tool else None
            isolation_obs = isolation_tool.run(event=event, analysis=analysis) if isolation_tool else None

            data = dict(triage_data)
            data.update(
                {
                    "playbook": playbook_obs.summary if playbook_obs else "",
                    "playbook_steps": list(playbook_obs.details) if playbook_obs else [],
                    "ticket": ticket_obs.summary if ticket_obs else "",
                    "ticket_details": list(ticket_obs.details) if ticket_obs else [],
                    "isolation": isolation_obs.summary if isolation_obs else "",
                    "isolation_details": list(isolation_obs.details) if isolation_obs else [],
                }
            )
            findings = [data["playbook"], data["ticket"], data["isolation"]]
            findings = [item for item in findings if item]
            return AgentOutput(
                agent_name=self.name,
                findings=findings,
                summary=findings[0] if findings else "无处置建议",
                data=data,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"RespondAgent 异常: {exc}"],
                summary="RespondAgent 降级：异常",
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )


class ReportAgent(BaseAgent):
    """汇总报告：聚合前三 Agent 输出，形成最终裁决与导出结构。"""

    name = "Report Agent"
    role = "汇总输出与报告生成"

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            triage_data = context.get("triage", {})
            hunt_data = context.get("hunt", {})
            respond_data = context.get("respond", {})

            verdict = triage_data.get("verdict", "存在待确认风险，需要进一步补充上下文。")
            risk_level = triage_data.get("risk_level", "medium")
            event_type = triage_data.get("event_type", "通用异常行为")
            is_false_positive = triage_data.get("is_false_positive", False)

            report = {
                "event_id": getattr(agent_input.event, "id", ""),
                "scenario": getattr(agent_input.event, "scenario", ""),
                "event_type": event_type,
                "verdict": verdict,
                "risk_level": risk_level,
                "confidence": triage_data.get("confidence", "low"),
                "confidence_score": triage_data.get("confidence_score", 0.5),
                "is_false_positive": is_false_positive,
                "hunt_findings": hunt_data.get("hunt_findings", []),
                "playbook": respond_data.get("playbook", ""),
                "ticket": respond_data.get("ticket", ""),
                "isolation": respond_data.get("isolation", ""),
                "evidence": triage_data.get("evidence", []),
                "recommendations": triage_data.get("recommendations", []),
            }

            findings = [
                f"最终裁决: {event_type} / {risk_level}",
                f"误报判断: {'是' if is_false_positive else '否'}",
            ]
            if respond_data.get("ticket"):
                findings.append(respond_data["ticket"])
            return AgentOutput(
                agent_name=self.name,
                findings=findings,
                summary=f"报告生成完成: {event_type} / {risk_level}",
                data={"report": report},
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"ReportAgent 异常: {exc}"],
                summary="ReportAgent 降级：异常",
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )
