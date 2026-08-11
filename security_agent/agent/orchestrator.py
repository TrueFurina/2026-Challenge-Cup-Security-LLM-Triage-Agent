from security_agent.agent.models import AnalysisResult, PhaseAgentRecord, SecurityEvent
from security_agent.agent.planner import build_plan
from security_agent.ai.triage import CONFIDENCE_SCORES, triage_event as ai_triage_event
from security_agent.ledger import LedgerStore
from security_agent.memory import MemoryStore
from security_agent.prefilter import AUTO_CLOSE, AUTO_ESCALATE, NEED_LLM, PreFilterEngine


class SecurityAgent:
    def __init__(
        self,
        llm,
        intake_service,
        knowledge_hub,
        tool_registry,
        evaluation_service,
        prefilter_engine=None,
        memory_store=None,
        ledger_store=None,
    ):
        self.llm = llm
        self.intake_service = intake_service
        self.knowledge_hub = knowledge_hub
        self.tool_registry = tool_registry
        self.evaluation_service = evaluation_service
        self.prefilter_engine = prefilter_engine or PreFilterEngine.default()
        self.prefilter_stats = {"auto_close": 0, "auto_escalate": 0, "need_llm": 0}
        self.memory = memory_store or MemoryStore()
        self.record_history = True  # 评测时会临时关闭，避免污染记忆
        self.ledger = ledger_store or LedgerStore()
        self.record_ledger = True  # 审计记录开关（fail-open：写入失败不阻断）

    def list_events(self) -> list[SecurityEvent]:
        return self.intake_service.list_events()

    def triage_event(self, event_id: str) -> AnalysisResult:
        event = self.intake_service.get_event(event_id)
        return self._triage(event)

    def triage_submission(self, payload: str, source_type: str) -> AnalysisResult:
        event = self.intake_service.build_submission_event(
            payload=payload,
            source_type=source_type,
        )
        return self._triage(event)

    def _triage(self, event: SecurityEvent) -> AnalysisResult:
        plan = build_plan(event)
        module_trace = [
            "任务入口模块",
            "智能体编排模块",
            "知识与数据模块",
            "工具执行模块",
            "结果输出模块",
        ]

        # 阶段 8：Investigation Ledger 审计（fail-open：创建失败返回 None 不阻断）
        ledger = (
            self.ledger.begin(event.id, event.scenario)
            if getattr(self, "record_ledger", True)
            else None
        )

        knowledge_items, knowledge_observation = self.knowledge_hub.retrieve_knowledge(event)
        asset_tool = self.tool_registry.get("asset_lookup")
        log_tool = self.tool_registry.get("log_lookup")
        intel_tool = self.tool_registry.get("intel_lookup")
        history_tool = self.tool_registry.get("history_alert_lookup")
        fp_tool = self.tool_registry.get("false_positive_check")
        analyzer_tool = self.tool_registry.get("incident_triage")
        playbook_tool = self.tool_registry.get("playbook_matcher")
        ticket_tool = self.tool_registry.get("ticket_generator")
        isolation_tool = self.tool_registry.get("host_isolation_simulator")

        asset_observation = asset_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        log_observation = log_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        intel_observation = intel_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        history_observation = history_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        false_positive_observation = fp_tool.run(
            event=event,
            knowledge_hub=self.knowledge_hub,
            asset_observation=asset_observation,
            log_observation=log_observation,
        )
        # 阶段 8：记录上下文工具观测步骤（审计）
        if ledger is not None:
            for obs in (
                asset_observation,
                log_observation,
                intel_observation,
                history_observation,
                false_positive_observation,
            ):
                ledger.record_step(
                    "context",
                    tool=obs.tool_name,
                    summary=obs.summary,
                    details=obs.details[:5],
                )
            ledger.record_step("knowledge", summary=knowledge_observation.summary)

        # 阶段 1：确定性预筛 —— 规则先筛，不确定才给 LLM（毫秒级，省成本）
        prefilter_result = self.prefilter_engine.prefilter(
            event=event,
            asset_observation=asset_observation,
            intel_observation=intel_observation,
            false_positive_observation=false_positive_observation,
            log_observation=log_observation,
            history_observation=history_observation,
        )
        if ledger is not None:
            ledger.record_step(
                "prefilter",
                decision=prefilter_result.decision,
                matched_rules=prefilter_result.matched_rules,
                llm_skipped=prefilter_result.llm_skipped,
            )

        context_observations = [
            asset_observation,
            log_observation,
            intel_observation,
            history_observation,
            false_positive_observation,
        ]

        if prefilter_result.decision == AUTO_CLOSE:
            # 高置信误报：跳过 LLM，直接生成"误报已关闭"
            self.prefilter_stats["auto_close"] += 1
            analysis = self._build_prefilter_analysis(
                prefilter_result, event, context_observations
            )
        elif prefilter_result.decision == AUTO_ESCALATE:
            # 高置信攻击特征：直接定级，跳过 LLM
            self.prefilter_stats["auto_escalate"] += 1
            analysis = self._build_prefilter_analysis(
                prefilter_result, event, context_observations
            )
        else:
            # 证据不足：LLM 深度研判 → 回退硬编码规则
            if getattr(self, "force_rule_fallback", False):
                # 纯规则评测模式：强制跳过 LLM（不统计 need_llm，成本为 0）
                analysis = None
            else:
                self.prefilter_stats["need_llm"] += 1
                # 阶段 6：检索相似历史研判记忆，注入 prompt 供一致性参考
                history_items = self.memory.search(event, top_k=3) or None
                analysis = ai_triage_event(
                    event=event,
                    asset_observation=asset_observation,
                    log_observation=log_observation,
                    intel_observation=intel_observation,
                    history_observation=history_observation,
                    false_positive_observation=false_positive_observation,
                    knowledge_items=knowledge_items,
                    plan=plan,
                    history_items=history_items,
                    # 阶段 8：LLM 调用审计（prompt + response 记录到 ledger）
                    on_llm_call=(
                        ledger.record_llm if ledger is not None else None
                    ),
                )
            if analysis is None:
                analysis = analyzer_tool.run(
                    event=event,
                    knowledge_items=knowledge_items,
                    asset_observation=asset_observation,
                    log_observation=log_observation,
                    intel_observation=intel_observation,
                    history_observation=history_observation,
                    false_positive_observation=false_positive_observation,
                    plan=plan,
                )

        # 阶段 8：记录研判核心步骤（审计）
        if ledger is not None:
            ledger.record_step(
                "triage",
                event_type=analysis["event_type"],
                risk_level=analysis["risk_level"],
                confidence=analysis["confidence"],
                is_false_positive=analysis["is_false_positive"],
                verdict=analysis["verdict"],
            )

        playbook_observation = playbook_tool.run(event=event, analysis=analysis)
        ticket_observation = ticket_tool.run(event=event, analysis=analysis)
        isolation_observation = isolation_tool.run(event=event, analysis=analysis)

        if ledger is not None:
            for obs in (
                playbook_observation,
                ticket_observation,
                isolation_observation,
            ):
                ledger.record_step(
                    "postprocess",
                    tool=obs.tool_name,
                    summary=obs.summary,
                    details=obs.details[:3],
                )

        analysis["tool_observations"].extend(
            [knowledge_observation, playbook_observation, ticket_observation, isolation_observation]
        )
        analysis["execution_log"].extend(
            [
                knowledge_observation.summary,
                playbook_observation.summary,
                ticket_observation.summary,
                isolation_observation.summary,
            ]
        )
        analysis["reasoning_summary"].append(
            f"后处理阶段已补充处置预案、工单和动作模拟，形成更接近真实运营的闭环。"
        )
        analysis["evidence"].extend(
            [
                f"处置预案: {playbook_observation.summary}",
                f"工单生成: {ticket_observation.summary}",
                f"动作模拟: {isolation_observation.summary}",
            ]
        )
        analysis["recommendations"].extend(playbook_observation.details[1:3])
        if isolation_observation.details:
            action_line = next(
                (item for item in isolation_observation.details if item.startswith("动作建议: ")),
                "",
            )
            if action_line:
                analysis["recommendations"].append(action_line.replace("动作建议: ", ""))

        if prefilter_result.decision in (AUTO_CLOSE, AUTO_ESCALATE):
            # 预筛直达路径：不调 LLM，确定性生成总结（避免 summarize 再次请求 LLM）
            summary = {
                "verdict": analysis["verdict"],
                "risk_level": analysis["risk_level"],
                "is_false_positive": analysis["is_false_positive"],
                "evidence": analysis["evidence"],
                "recommendations": analysis["recommendations"],
            }
        else:
            summary = self.llm.summarize(
                event=event,
                analysis=analysis,
                knowledge_items=knowledge_items,
                plan=plan,
            )

        phase_agents = [
            PhaseAgentRecord(
                name="Monitor Agent",
                role="事件接收与场景识别",
                focus="识别事件入口、初始风险和后续分析方向",
                outputs=[
                    f"接收到事件: {event.id}",
                    f"场景: {event.scenario}",
                    f"初始严重性: {event.severity}",
                ],
            ),
            PhaseAgentRecord(
                name="Context Agent",
                role="上下文关联与知识补全",
                focus="关联资产、日志、情报和知识库，为研判阶段提供上下文",
                used_tools=[
                    asset_observation.tool_name,
                    log_observation.tool_name,
                    intel_observation.tool_name,
                    history_observation.tool_name,
                ],
                outputs=[
                    asset_observation.summary,
                    log_observation.summary,
                    intel_observation.summary,
                    history_observation.summary,
                    knowledge_observation.summary,
                ],
            ),
            PhaseAgentRecord(
                name="Triage Agent",
                role="初步研判与误报剔除",
                focus="综合上下文证据，完成事件分类、风险定级和误报判断",
                used_tools=[
                    false_positive_observation.tool_name,
                    analyzer_tool.name,
                ],
                outputs=[
                    f"事件类型: {analysis['event_type']}",
                    f"风险等级: {analysis['risk_level']}",
                    false_positive_observation.summary,
                ],
            ),
            PhaseAgentRecord(
                name="Report Agent",
                role="结构化输出与处置建议",
                focus="形成统一报告结果，并补充工单、预案和动作建议",
                used_tools=[
                    playbook_observation.tool_name,
                    ticket_observation.tool_name,
                    isolation_observation.tool_name,
                ],
                outputs=[
                    f"研判结论: {summary['verdict']}",
                    playbook_observation.summary,
                    ticket_observation.summary,
                    isolation_observation.summary,
                    f"误报判断: {'是' if summary['is_false_positive'] else '否'}",
                ],
            ),
        ]

        # 阶段 2：置信度门控 —— 低置信 → 标记待人工复核，不自动处置
        confidence = analysis["confidence"]
        confidence_score = analysis.get(
            "confidence_score", CONFIDENCE_SCORES.get(confidence, 0.7)
        )
        needs_human_review = confidence == "low"
        review_status = "pending_review" if needs_human_review else "auto_reviewed"

        # 阶段 6：研判结果持久化（误报记忆，评测时 record_history=False 不写入）
        if getattr(self, "record_history", True):
            self.memory.append(
                {
                    "event_id": event.id,
                    "host": event.host,
                    "process": event.process,
                    "behavior": event.behavior,
                    "event_type": analysis["event_type"],
                    "risk_level": analysis["risk_level"],
                    "confidence": confidence,
                    "is_false_positive": summary["is_false_positive"],
                }
            )

        # 阶段 8：Ledger 最终裁决审计落盘（fail-open）
        if ledger is not None:
            ledger.finalize(
                {
                    "event_id": event.id,
                    "event_type": analysis["event_type"],
                    "verdict": summary["verdict"],
                    "risk_level": summary["risk_level"],
                    "confidence": confidence,
                    "is_false_positive": summary["is_false_positive"],
                    "prefilter_decision": prefilter_result.decision,
                }
            )

        return AnalysisResult(
            event_id=event.id,
            scenario=event.scenario,
            event_type=analysis["event_type"],
            verdict=summary["verdict"],
            risk_level=summary["risk_level"],
            confidence=analysis["confidence"],
            confidence_score=confidence_score,
            risk_score=analysis.get("risk_score", 0),
            is_false_positive=summary["is_false_positive"],
            review_status=review_status,
            needs_human_review=needs_human_review,
            prefilter_decision=prefilter_result.decision,
            module_trace=module_trace,
            phase_agents=phase_agents,
            plan_steps=plan,
            reasoning_summary=analysis["reasoning_summary"],
            evidence=summary["evidence"],
            recommendations=summary["recommendations"],
            knowledge_hits=[
                self._format_knowledge_hit(item) for item in knowledge_items
            ],
            tool_observations=analysis["tool_observations"],
            execution_log=analysis["execution_log"],
        )

    @staticmethod
    def _format_knowledge_hit(item) -> str:
        """格式化知识命中（含 ATT&CK/CVE 依据，供 Web 面板展示）。"""
        attck = "/".join(getattr(item, "attck_ids", []) or []) or "无"
        cve = "/".join(getattr(item, "cve_ids", []) or []) or "无"
        return f"{item.title} [{item.category}] | ATT&CK: {attck} | CVE: {cve}"

    def _build_prefilter_analysis(
        self, prefilter_result, event, observations: list
    ) -> dict:
        """预筛直达路径的裁决结果（不调 LLM，标记 source: prefilter）。"""
        matched = " / ".join(prefilter_result.matched_rules) or "无"
        if prefilter_result.decision == AUTO_CLOSE:
            verdict = (
                f"确定性预筛判定为误报，已自动关闭（命中规则: {matched}）。"
            )
            event_type = prefilter_result.event_type or "误报"
            risk_level = "low"
            is_false_positive = True
            recommendations = [
                "核对维护窗口、白名单和变更单",
                "确认无进一步恶意行为后关闭告警",
                "记录误报原因并更新规则抑制条件",
            ]
        else:
            verdict = (
                f"确定性预筛命中高置信攻击特征，直接定级（命中规则: {matched}）。"
            )
            event_type = prefilter_result.event_type or "通用异常行为"
            risk_level = prefilter_result.risk_level or "high"
            is_false_positive = False
            recommendations = [
                "立即通知安全运营人员进行复核",
                "根据处置预案执行遏制与隔离",
                "补充日志和身份侧证据后升级处置",
            ]
        return {
            "source": "prefilter",
            "event_type": event_type,
            "verdict": verdict,
            "risk_level": risk_level,
            "confidence": "high",
            "is_false_positive": is_false_positive,
            "reasoning_summary": [
                f"确定性预筛器命中规则: {matched}，未调用 LLM。",
                f"预筛依据: {prefilter_result.reason}",
            ],
            "evidence": [
                f"事件标题: {event.title}",
                f"行为描述: {event.behavior}",
                f"预筛命中规则: {matched}",
            ],
            "recommendations": recommendations,
            "execution_log": [
                f"预筛器决策: {prefilter_result.decision}（命中规则: {matched}）"
            ],
            "tool_observations": observations,
        }

    def analyze_alert(self, alert_id: str) -> AnalysisResult:
        return self.triage_event(alert_id)

    def coordinate_event(self, event_id: str) -> dict:
        """阶段 3：多 Agent 顺序协作（Triage → Hunt → Respond → Report）。

        返回全链路记录（每 Agent 输入/输出），供 CLI/Web 展示与审计。
        """
        from security_agent.agents.base import AgentInput
        from security_agent.agents.coordinator import AgentCoordinator

        event = self.intake_service.get_event(event_id)
        knowledge_items, _ = self.knowledge_hub.retrieve_knowledge(event)

        context = {
            "knowledge_hub": self.knowledge_hub,
            "tool_registry": self.tool_registry,
        }
        # 预计算工具观测，供 TriageAgent 复用（与主研判链路一致）
        asset_tool = self.tool_registry.get("asset_lookup")
        log_tool = self.tool_registry.get("log_lookup")
        intel_tool = self.tool_registry.get("intel_lookup")
        history_tool = self.tool_registry.get("history_alert_lookup")
        fp_tool = self.tool_registry.get("false_positive_check")
        context["asset_observation"] = asset_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        context["log_observation"] = log_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        context["intel_observation"] = intel_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        context["history_observation"] = history_tool.run(event=event, knowledge_hub=self.knowledge_hub)
        context["false_positive_observation"] = fp_tool.run(
            event=event,
            knowledge_hub=self.knowledge_hub,
            asset_observation=context["asset_observation"],
            log_observation=context["log_observation"],
        )

        agent_input = AgentInput(
            event=event,
            context=context,
            knowledge_items=knowledge_items,
            plan=build_plan(event),
            llm=self.llm,
        )
        coordinator = AgentCoordinator()
        return coordinator.coordinate(agent_input)

    def evaluate_cases(self) -> dict:
        return self.evaluation_service.evaluate(self)
