"""四个协作 Agent 实现（决策闭环：Planner → Classifier → Triage → Reviewer）。

数据流（顺序协作，前序 Agent 的 data 合并进共享 context）：
PlannerAgent（规划）→ ClassifierAgent（确定性预筛分类）→ TriageAgent（深度研判）
→ ReviewerAgent（一致性复核 + 处置门控）

设计原则：
1. PlannerAgent 基于事件特征**真实决策**分析步骤，非硬编码 4 步模板。
2. ClassifierAgent 复用 PreFilterEngine：确定性误报/攻击直接短路（skip_triage），
   证据不足则交由 TriageAgent 深度研判。
3. TriageAgent 复用 ai/triage.py 的 triage_event（LLM 决策 + 规则回退，失败开放），
   不重写推理逻辑；plan 取自 PlannerAgent 输出。
4. ReviewerAgent 做反驳性复核：低置信/前后矛盾标记人工复核，预筛确定性结论直接采纳。
5. 每个 Agent fail-open：任何异常返回 error 标记的 AgentOutput，链路不中断。
"""
from __future__ import annotations

import time
from typing import Any, Optional

from security_agent.agents.base import AgentInput, AgentOutput, BaseAgent
from security_agent.ai.triage import _SCORE_FROM_LEVEL, triage_event
from security_agent.prefilter import AUTO_CLOSE, AUTO_ESCALATE, NEED_LLM


class PlannerAgent(BaseAgent):
    """规划：基于事件特征**真实决策**后续分析步骤（非硬编码模板）。"""

    name = "Planner Agent"
    role = "研判规划与场景识别"
    focus = "基于进程/行为/外联/变更单/攻击特征决定分析路径与重点"
    used_tools = ["asset_lookup", "log_lookup", "intel_lookup"]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            event = agent_input.event
            corpus = " ".join(
                [
                    event.process,
                    event.behavior,
                    event.raw_log,
                    event.destination_domain or "",
                    event.destination_ip or "",
                    " ".join(getattr(event, "tags", []) or []),
                ]
            ).lower()

            plan = ["Monitor Agent 接收事件并完成场景识别（入口）"]
            if event.change_ticket:
                plan.append("核验变更单与维护窗口是否支持误报判定")
            if event.destination_domain or event.destination_ip:
                plan.append("关联威胁情报与外部目的资产（IOC 检索）")
            if any(k in corpus for k in ("powershell", "encodedcommand", "invoke-expression", "iex(")):
                plan.append("识别恶意脚本执行痕迹（PowerShell / 编码命令）")
            if any(k in corpus for k in ("ransom", "encrypt", "lsass", "minidump", "cred")):
                plan.append("重点排查勒索加密 / 凭据窃取行为")
            if any(k in corpus for k in ("net.exe", "admin$", "psexec", "wmic")):
                plan.append("排查横向移动与远程命令执行")
            plan.append("Context Agent 关联资产 / 日志 / 知识库上下文")
            plan.append("Classifier Agent 确定性预筛分类（规则优先）")
            plan.append("Triage Agent 深度研判（LLM / 规则回退）")
            plan.append("Reviewer Agent 一致性复核与处置门控")

            return AgentOutput(
                agent_name=self.name,
                findings=[
                    f"规划步骤: {len(plan)} 项",
                    f"事件入口: {event.id}（场景: {event.scenario}）",
                    f"初始严重性: {event.severity}",
                ],
                summary=f"规划完成，共 {len(plan)} 步分析路径",
                data={"plan": plan},
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"PlannerAgent 异常: {exc}"],
                summary="PlannerAgent 降级：异常",
                error=str(exc),
                data={"plan": []},
                duration_ms=(time.perf_counter() - started) * 1000,
            )


class ClassifierAgent(BaseAgent):
    """确定性预筛分类：复用 PreFilterEngine，产出分类提案并决定 Triage 是否可短路。"""

    name = "Classifier Agent"
    role = "确定性预筛与事件分类"
    focus = "规则优先：高置信误报/攻击直接定级，证据不足交 Triage 深度研判"
    used_tools = ["asset_lookup", "log_lookup", "intel_lookup", "false_positive_check"]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            event = agent_input.event
            prefilter = context.get("prefilter_result")
            matched = " / ".join(prefilter.matched_rules) if prefilter else "无"

            if prefilter is not None and prefilter.decision == AUTO_CLOSE:
                data = {
                    "decision": "AUTO_CLOSE",
                    "event_type": prefilter.event_type or "误报",
                    "risk_level": "low",
                    "is_false_positive": True,
                    "confidence": "high",
                    "confidence_score": 0.9,
                    "risk_score": 15,
                    "verdict": f"确定性预筛判定为误报，已自动关闭（命中规则: {matched}）。",
                    "reason": prefilter.reason,
                    "skip_triage": True,  # 确定性结论，TriageAgent 可短路
                }
                findings = [
                    f"确定性误报（AUTO_CLOSE）：命中规则 {matched}",
                    f"已建议自动关闭，跳过 LLM 深度研判",
                ]
            elif prefilter is not None and prefilter.decision == AUTO_ESCALATE:
                risk = prefilter.risk_level or "high"
                data = {
                    "decision": "AUTO_ESCALATE",
                    "event_type": prefilter.event_type or "通用异常行为",
                    "risk_level": risk,
                    "is_false_positive": False,
                    "confidence": "high",
                    "confidence_score": 0.9,
                    "risk_score": _SCORE_FROM_LEVEL.get(risk, 68),
                    "verdict": f"确定性预筛命中高置信攻击特征，直接定级（命中规则: {matched}）。",
                    "reason": prefilter.reason,
                    "skip_triage": True,
                }
                findings = [
                    f"高置信攻击（AUTO_ESCALATE）：命中规则 {matched}",
                    f"建议直接定级 {risk}，跳过 LLM 深度研判",
                ]
            else:
                data = {
                    "decision": "NEED_LLM",
                    "event_type": "通用异常行为",
                    "risk_level": "medium",
                    "is_false_positive": False,
                    "confidence": "medium",
                    "reason": "预筛证据不足，交由 Triage Agent 深度研判。",
                    "skip_triage": False,
                }
                findings = [
                    "预筛未达确定性阈值（NEED_LLM）",
                    "交由 Triage Agent 做 LLM / 规则深度研判",
                ]

            return AgentOutput(
                agent_name=self.name,
                findings=findings,
                summary="; ".join(findings[:2]),
                data=data,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"ClassifierAgent 异常: {exc}"],
                summary="ClassifierAgent 降级：异常",
                error=str(exc),
                data={"decision": "NEED_LLM", "skip_triage": False},
                duration_ms=(time.perf_counter() - started) * 1000,
            )


class TriageAgent(BaseAgent):
    """深度研判：事件类型 / 风险等级 / 置信度 / 误报判断（复用现有 AI 研判）。"""

    name = "Triage Agent"
    role = "深度研判与误报剔除"
    focus = "综合上下文证据完成分类、风险定级与误报判断（LLM 优先，规则回退）"
    used_tools = [
        "asset_lookup",
        "log_lookup",
        "intel_lookup",
        "history_alert_lookup",
        "false_positive_check",
    ]

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            event = agent_input.event

            # 确定性预筛已结论 → 直接复用 Classifier 提案，避免重复 LLM 调用
            classifier = context.get("classifier", {}) or {}
            if classifier.get("skip_triage"):
                triage_dict = {
                    "event_type": classifier.get("event_type", "通用异常行为"),
                    "verdict": classifier.get("verdict", ""),
                    "risk_level": classifier.get("risk_level", "medium"),
                    "confidence": classifier.get("confidence", "high"),
                    "confidence_score": classifier.get("confidence_score", 0.9),
                    "is_false_positive": classifier.get("is_false_positive", False),
                    "risk_score": classifier.get("risk_score", 18),
                    "reasoning_summary": [classifier.get("reason", "确定性预筛结论")],
                    "evidence": [],
                    "recommendations": [],
                    "execution_log": [],
                    "tool_observations": list(context.get("tool_observations", []) or []),
                }
                return AgentOutput(
                    agent_name=self.name,
                    findings=[
                        f"复用确定性预筛结论: {triage_dict['event_type']} / {triage_dict['risk_level']}"
                    ],
                    summary=f"初判为 {triage_dict['event_type']} / {triage_dict['risk_level']}（预筛短路）",
                    data=triage_dict,
                    duration_ms=(time.perf_counter() - started) * 1000,
                )

            # plan 取自 PlannerAgent 输出（前序 Agent 已写入 context）
            plan = (context.get("planner", {}) or {}).get("plan") or agent_input.plan

            if context.get("force_rule_fallback"):
                # 纯规则模式：走 IncidentTriageTool（其本质是 triage_event 的封装）
                analyzer = context.get("tool_registry").get("incident_triage")
                analysis = analyzer.run(
                    event=event,
                    knowledge_items=agent_input.knowledge_items,
                    asset_observation=context.get("asset_observation"),
                    log_observation=context.get("log_observation"),
                    intel_observation=context.get("intel_observation"),
                    history_observation=context.get("history_observation"),
                    false_positive_observation=context.get("false_positive_observation"),
                    history_items=context.get("history_items") or [],
                    # 阶段 2 HITL：人工对该事件的复核反馈作为证据注入
                    human_feedback=context.get("human_feedback"),
                    # LLM 调用审计钩子（透传给 triage_event → ai_chat_json）
                    on_llm_call=context.get("on_llm_call"),
                )
            else:
                analysis = triage_event(
                    event=event,
                    asset_observation=context.get("asset_observation"),
                    log_observation=context.get("log_observation"),
                    intel_observation=context.get("intel_observation"),
                    history_observation=context.get("history_observation"),
                    false_positive_observation=context.get("false_positive_observation"),
                    knowledge_items=agent_input.knowledge_items,
                    plan=plan,
                    # 阶段 6：注入相似历史研判记忆（由 orchestrator 经 memory.search 取回）
                    history_items=context.get("history_items") or [],
                    # 阶段 2：注入人工复核反馈（由 orchestrator 经 feedback.latest 取回）
                    human_feedback=context.get("human_feedback"),
                    # LLM 调用审计钩子：使 Ledger 记录本次 AI 调用的 prompt/response
                    on_llm_call=context.get("on_llm_call"),
                )
            if analysis is None:
                return AgentOutput(
                    agent_name=self.name,
                    findings=["LLM 研判不可用，TriageAgent 无有效裁决"],
                    summary="TriageAgent 降级：无裁决",
                    error="triage_event 返回 None",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            # 透传完整研判 dict（供 Reviewer / orchestrator 使用）
            data = dict(analysis)
            data.setdefault("risk_score", _SCORE_FROM_LEVEL.get(analysis.get("risk_level", "medium"), 48))
            return AgentOutput(
                agent_name=self.name,
                findings=[
                    f"事件类型: {analysis['event_type']}",
                    f"风险等级: {analysis['risk_level']}",
                    f"置信度: {analysis['confidence']}（{data.get('confidence_score')}）",
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


class ReviewerAgent(BaseAgent):
    """复核：反驳性审查 + 处置门控（低置信 / 前后矛盾标记人工复核）。"""

    name = "Reviewer Agent"
    role = "一致性复核与处置门控"
    focus = "校验预筛/初判一致性，低置信或矛盾时标记人工复核，预筛确定性结论直接采纳"
    used_tools = []

    def run(self, agent_input: AgentInput) -> AgentOutput:
        started = time.perf_counter()
        try:
            context = agent_input.context
            event = agent_input.event
            prefilter = context.get("prefilter_result")
            classifier = context.get("classifier", {}) or {}
            triage = context.get("triage", {}) or {}
            tool_observations = list(context.get("tool_observations", []) or [])

            review_notes: list[str] = []
            needs_human_review = False

            if prefilter is not None and prefilter.decision == AUTO_CLOSE:
                # 确定性误报：直接采纳，无需复核
                final = {
                    "event_type": classifier.get("event_type", "误报"),
                    "verdict": classifier.get("verdict", "确定性预筛判定为误报，已自动关闭。"),
                    "risk_level": "low",
                    "confidence": "high",
                    "confidence_score": 0.9,
                    "risk_score": 15,
                    "is_false_positive": True,
                    "reasoning_summary": [classifier.get("reason", "确定性预筛结论")],
                    "evidence": [
                        f"事件标题: {event.title}",
                        f"行为描述: {event.behavior}",
                        f"预筛命中规则: {(' / '.join(prefilter.matched_rules) or '无')}",
                    ],
                    "recommendations": [
                        "核对维护窗口、白名单和变更单",
                        "确认无进一步恶意行为后关闭告警",
                        "记录误报原因并更新规则抑制条件",
                    ],
                    "execution_log": [
                        f"预筛器决策: AUTO_CLOSE（命中规则: {' / '.join(prefilter.matched_rules) or '无'}）"
                    ],
                    "tool_observations": tool_observations,
                }
                review_notes.append("预筛确定性误报，Reviewer 确认自动关闭。")
            elif prefilter is not None and prefilter.decision == AUTO_ESCALATE:
                risk = classifier.get("risk_level", "high")
                final = {
                    "event_type": classifier.get("event_type", "通用异常行为"),
                    "verdict": classifier.get("verdict", "确定性预筛命中高置信攻击特征，直接定级。"),
                    "risk_level": risk,
                    "confidence": "high",
                    "confidence_score": 0.9,
                    "risk_score": _SCORE_FROM_LEVEL.get(risk, 68),
                    "is_false_positive": False,
                    "reasoning_summary": [classifier.get("reason", "确定性预筛结论")],
                    "evidence": [
                        f"事件标题: {event.title}",
                        f"行为描述: {event.behavior}",
                        f"预筛命中规则: {(' / '.join(prefilter.matched_rules) or '无')}",
                    ],
                    "recommendations": [
                        "立即通知安全运营人员进行复核",
                        "根据处置预案执行遏制与隔离",
                        "补充日志和身份侧证据后升级处置",
                    ],
                    "execution_log": [
                        f"预筛器决策: AUTO_ESCALATE（命中规则: {' / '.join(prefilter.matched_rules) or '无'}）"
                    ],
                    "tool_observations": tool_observations,
                }
                if risk == "critical":
                    needs_human_review = True
                    review_notes.append("高置信严重攻击，已标记人工复核确认处置。")
                else:
                    review_notes.append("预筛命中高置信攻击特征，Reviewer 确认升级。")
            else:
                # 深度研判路径：以 Triage 为权威，仅做一致性门控
                final = dict(triage)
                final.setdefault("tool_observations", tool_observations)
                final.setdefault("execution_log", [])
                if classifier.get("is_false_positive") != triage.get("is_false_positive"):
                    needs_human_review = True
                    review_notes.append(
                        "快速分类与深度研判在误报判定上不一致，已标记待人工复核（以深度研判为准）。"
                    )
                if triage.get("confidence") == "low":
                    needs_human_review = True
                    review_notes.append("深度研判置信度低，已标记待人工复核。")

            final["needs_human_review"] = needs_human_review
            final["review_status"] = "pending_review" if needs_human_review else "auto_reviewed"
            final["review_notes"] = review_notes

            # ── 阶段 2：HITL 读回门控（把人工复核结论落到 review_status）──
            #
            # 此前 `review_feedback.jsonl` 只被 Web 写、从未被 Agent 读：人工点下
            # 「驳回」后同一事件重跑，Agent 仍原样给出已被否定的结论，复核状态也
            # 仍是他自己算的 auto_reviewed/pending_review——闭环在代码里不存在。
            #
            # 归属判定：反馈带**被复核那版裁决的摘要**（event_type/risk_level/
            # is_false_positive），只有摘要与本次结论三者全等，该反馈才适用于本次：
            #   · confirm 且适用于本次 → human_confirmed（人已认可，解除复核门控）
            #   · reject  且适用于本次 → human_rejected：Agent 重复了被否定结论，
            #     强制挂起（needs_human_review=True）并在理由里写明冲突
            #   · 摘要不符（本次是新结论）或摘要缺失（旧记录）→ 不改显示器门控结果，
            #     反馈已在 Triage 提示词中生效，等待下一次复核确认。
            human_feedback = context.get("human_feedback")
            if human_feedback is not None:
                applies = human_feedback.matches_verdict(
                    final.get("event_type", ""),
                    final.get("risk_level", ""),
                    bool(final.get("is_false_positive", False)),
                )
                if applies and human_feedback.decision == "confirm":
                    final["review_status"] = "human_confirmed"
                    final["needs_human_review"] = False
                    review_notes.append(
                        f"人工已确认该裁决（{human_feedback.timestamp[:10] or '未知时间'}），复核状态置为 human_confirmed。"
                    )
                elif applies and human_feedback.decision == "reject":
                    final["review_status"] = "human_rejected"
                    final["needs_human_review"] = True
                    review_notes.append(
                        "本次结论与人工已驳回的那版一致，Agent 重复了被否定的裁决，已强制挂起待人工仲裁。"
                    )
                elif not applies:
                    review_notes.append(
                        "存在人工复核记录，但其针对的是另一版裁决（本次结论已不同），本次按常规门控处理。"
                    )
            final["review_notes"] = review_notes
            final["plan"] = (context.get("planner", {}) or {}).get("plan", [])
            final["reasoning_summary"] = list(final.get("reasoning_summary", [])) + [
                f"Reviewer 复核: {n}" for n in review_notes
            ] or ["Reviewer 复核通过，无异常。"]

            return AgentOutput(
                agent_name=self.name,
                findings=[
                    f"最终裁决: {final['event_type']} / {final['risk_level']}",
                    f"误报判断: {'是' if final['is_false_positive'] else '否'}",
                    f"复核状态: {final['review_status']}",
                ],
                summary=f"复核完成: {final['event_type']} / {final['risk_level']}（{final['review_status']}）",
                data={"final_decision": final},
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 - fail-open
            return AgentOutput(
                agent_name=self.name,
                findings=[f"ReviewerAgent 异常: {exc}"],
                summary="ReviewerAgent 降级：异常",
                error=str(exc),
                data={"final_decision": {}},
                duration_ms=(time.perf_counter() - started) * 1000,
            )


def _default_pipeline() -> list[BaseAgent]:
    """四角色决策闭环（顺序串行）。"""
    return [PlannerAgent(), ClassifierAgent(), TriageAgent(), ReviewerAgent()]
