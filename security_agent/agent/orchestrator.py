import tempfile
from contextlib import contextmanager
from pathlib import Path

from security_agent.agent.models import AnalysisResult, PhaseAgentRecord, SecurityEvent
from security_agent.ai.triage import CONFIDENCE_SCORES
from security_agent.agents.base import AgentInput
from security_agent.agents.coordinator import AgentCoordinator
from security_agent.hitl import DECISION_REJECT, HumanFeedbackStore
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
        feedback_store=None,
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
        # 阶段 2 HITL：人工复核反馈的读取源（评测期同样由沙箱隔离）
        self.feedback = feedback_store or HumanFeedbackStore()

    def list_events(self) -> list[SecurityEvent]:
        return self.intake_service.list_events()

    @contextmanager
    def evaluation_sandbox(self):
        """评测沙箱：研判记忆**读写双向隔离** + 审计轨迹**写隔离**，保证测量可复现。

        为什么必须隔离（都会让「同一次运行」留下不该留下的痕迹或跑出不同数字）：

        **记忆写**：每跑一轮评测，全量用例裁决都会被写进 `data/triage_history.jsonl`；
        下轮又经 `MemoryStore.search`（按**同主机**匹配）取回并注入 LLM 提示词——
        「自己污染自己」。实测 EVENT-013 曾因此拿到同主机 EVENT-001 的
        `恶意脚本执行 / critical` 历史裁决而判错，且**推理链本身正确**：
        它引用的确实是取回的证据，只是那证据来自另一个事件。

        **记忆读**：只关写仍不够。磁盘上任何**存量**记忆（生产运行留下的、或早期
        未关写时遗留的）都会被注入提示词。评测要度量「模型本身的能力」，
        不是「这台机器的历史」——故读取也须隔离到临时空库。

        **审计轨迹写**：`data/ledger/*.json` 是**真实处置的审计证据**，一次运行一个
        事件、覆盖写。评测跑 38 例会把 38 份「审计记录」写进去，与真实运行记录
        混杂，令审计轨迹失去证据价值；holdout 同理。ledger **不参与判定**
        （`LedgerStore.load` 仅供 Web 回放），故只需写隔离。
        > 该开关此前只在 Web 的「生成三模式对比」处手动关闭（`web/server.py`），
        > 命令行 `evaluate`、`_llm_eval.py`、`_holdout_eval.py` 三条路径均漏关，
        > 是「每处调用方各自记得关」的典型漂移——现收归本沙箱单一持有。

        **人工复核反馈读**：`data/review_feedback.jsonl` 是**真实运营**里人对
        Agent 裁决的判断，属于本机的业务数据而非被测能力。若评测期间仍被读取，
        同一份代码在"有人复核过这批事件"的机器上会跑出不同结果。故读源一并
        隔离到临时空库（写侧本就由 Web 面板持有，不存在评测写）。

        评测入口与离线评测脚本**共用此实现**，避免多处各自漂移。
        """
        previous_record_history = self.record_history
        previous_record_ledger = getattr(self, "record_ledger", True)
        previous_memory = self.memory
        previous_feedback = getattr(self, "feedback", None)
        self.record_history = False
        self.record_ledger = False
        try:
            with tempfile.TemporaryDirectory(prefix="secagent-eval-") as tmp:
                tmp_root = Path(tmp)
                self.memory = MemoryStore(tmp_root / "eval_history.jsonl")
                self.feedback = HumanFeedbackStore(tmp_root / "eval_feedback.jsonl")
                yield self
        finally:
            self.memory = previous_memory
            self.feedback = previous_feedback
            self.record_ledger = previous_record_ledger
            self.record_history = previous_record_history

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
        module_trace = [
            "任务入口模块",
            "智能体编排模块（Planner→Classifier→Triage→Reviewer）",
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

        # LLM 调用审计回调：把 AI 的 prompt/response 写入审计链路，使 Ledger 能回答
        # 「AI 凭什么这么判」。此为本次新增接线——此前 `LedgerRecord.record_llm()` 从未被
        # 生产调用（同族「实现了却不接线」缺陷第三例），导致 ledger 只有工具/阶段步骤、
        # 独缺 AI 自身证据。仅在审计开启时挂接；评测沙箱 record_ledger=False → 传入 None，
        # 与修复前代码路径等价，评测结果不受影响。回调本身由 ai/client 侧 try/except 兜住。
        def on_llm_call(prompt: str, response: str) -> None:
            if ledger is not None:
                ledger.record_llm(prompt, response)

        knowledge_items, knowledge_observation = self.knowledge_hub.retrieve_knowledge(event)
        asset_tool = self.tool_registry.get("asset_lookup")
        log_tool = self.tool_registry.get("log_lookup")
        intel_tool = self.tool_registry.get("intel_lookup")
        history_tool = self.tool_registry.get("history_alert_lookup")
        fp_tool = self.tool_registry.get("false_positive_check")
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

        # 阶段 6：检索相似历史研判记忆（同主机 +3 / 同进程 +2 / 行为重叠 +1），
        # 注入 Triage 提示词的「历史研判记忆」段。
        #
        # 修复说明：`MemoryStore.append` 一直在写，但 `MemoryStore.search` 此前
        # **在生产链路中从未被调用**，`triage_event(history_items=...)` 也从未被传值
        # （仅 `_memory_test.py` 手工传过）——「误报记忆注入」是只写不读的死功能，
        # 与"阶段 6 卖点 + 一致性复用"的叙事不符。此处接回。
        #
        # 评测隔离：`evaluation_sandbox()` 已把 `self.memory` 指向临时空库，
        # 故评测期此处恒返回 []，测量不受存量记忆影响（读隔离已由沙箱保证）。
        history_items = self.memory.search(event)

        # 阶段 2 HITL：读回人工对该事件的复核反馈，作为**证据**参与本次研判。
        #
        # 修复说明：`review_feedback.jsonl` 此前只有 Web 写、Agent 从不读——是条
        # 单向死数据，所谓「闭环」在代码里不成立。此处接回读侧，衔接已有 dad
        # 提示词注入链路（history_items）的模式，不再依赖 LLM 自觉。
        #
        # 评测隔离：`evaluation_sandbox()` 已把 `self.feedback` 指向临时空库，
        # 故评测期此处恒返回 None，测量不受本机运营反馈影响。
        human_feedback = self.feedback.latest(event.id)

        # ── 四角色决策闭环（真实串行，数据沿 context 流动）──────────
        context = {
            "knowledge_hub": self.knowledge_hub,
            "tool_registry": self.tool_registry,
            "asset_observation": asset_observation,
            "log_observation": log_observation,
            "intel_observation": intel_observation,
            "history_observation": history_observation,
            "false_positive_observation": false_positive_observation,
            "tool_observations": context_observations,
            "prefilter_result": prefilter_result,
            "history_items": history_items,
            "human_feedback": human_feedback,
            # LLM 调用审计钩子（ledger 关闭时为 None，评测路径等价）
            "on_llm_call": on_llm_call if ledger is not None else None,
            "force_rule_fallback": getattr(self, "force_rule_fallback", False),
        }
        agent_input = AgentInput(
            event=event,
            context=context,
            knowledge_items=knowledge_items,
            plan=[],  # 由 PlannerAgent 基于事件特征真实生成
            llm=self.llm,
        )
        coordinator = AgentCoordinator()
        coord_result = coordinator.coordinate(agent_input)
        agent_records = coord_result["agent_records"]

        # Reviewer 为末位 Agent，其产出写回共享 context["reviewer"]["final_decision"]
        final = coord_result["context"].get("reviewer", {}).get("final_decision") or {}
        if not final:
            # Reviewer 异常降级：以 Triage 结果为兜底（fail-open）
            final = dict(coord_result["context"].get("triage", {}) or {})
            final.setdefault("tool_observations", context_observations)
            final.setdefault("needs_human_review", True)
            final.setdefault("review_status", "pending_review")

        analysis = final  # 最终裁决 dict
        if prefilter_result.decision == AUTO_CLOSE:
            self.prefilter_stats["auto_close"] += 1
        elif prefilter_result.decision == AUTO_ESCALATE:
            self.prefilter_stats["auto_escalate"] += 1
        else:
            self.prefilter_stats["need_llm"] += 1

        # 阶段 8：记录研判核心步骤（审计）
        if ledger is not None:
            ledger.record_step(
                "triage",
                event_type=analysis.get("event_type", "通用异常行为"),
                risk_level=analysis.get("risk_level", "medium"),
                confidence=analysis.get("confidence", "low"),
                is_false_positive=analysis.get("is_false_positive", False),
                verdict=analysis.get("verdict", ""),
            )

        # 后处理：处置预案 / 工单 / 动作模拟（闭环收口）
        playbook_observation = playbook_tool.run(event=event, analysis=analysis)
        ticket_observation = ticket_tool.run(event=event, analysis=analysis)
        isolation_observation = isolation_tool.run(event=event, analysis=analysis)

        if ledger is not None:
            for obs in (playbook_observation, ticket_observation, isolation_observation):
                ledger.record_step(
                    "postprocess",
                    tool=obs.tool_name,
                    summary=obs.summary,
                    details=obs.details[:3],
                )

        analysis["tool_observations"] = list(analysis.get("tool_observations", []))
        analysis["tool_observations"].extend(
            [knowledge_observation, playbook_observation, ticket_observation, isolation_observation]
        )
        analysis["execution_log"] = list(analysis.get("execution_log", []))
        analysis["execution_log"].extend(
            [
                knowledge_observation.summary,
                playbook_observation.summary,
                ticket_observation.summary,
                isolation_observation.summary,
            ]
        )
        analysis["reasoning_summary"] = list(analysis.get("reasoning_summary", []))
        analysis["reasoning_summary"].append(
            "后处理阶段已补充处置预案、工单和动作模拟，形成更接近真实运营的闭环。"
        )
        analysis["evidence"] = list(analysis.get("evidence", []))
        analysis["evidence"].extend(
            [
                f"处置预案: {playbook_observation.summary}",
                f"工单生成: {ticket_observation.summary}",
                f"动作模拟: {isolation_observation.summary}",
            ]
        )
        analysis["recommendations"] = list(analysis.get("recommendations", []))
        analysis["recommendations"].extend(playbook_observation.details[1:3])
        if isolation_observation.details:
            action_line = next(
                (item for item in isolation_observation.details if item.startswith("动作建议: ")),
                "",
            )
            if action_line:
                analysis["recommendations"].append(action_line.replace("动作建议: ", ""))

        summary = {
            "verdict": analysis.get("verdict", ""),
            "risk_level": analysis.get("risk_level", "medium"),
            "is_false_positive": analysis.get("is_false_positive", False),
            "evidence": analysis.get("evidence", []),
            "recommendations": analysis.get("recommendations", []),
        }

        # 真实四角色执行记录（替代原硬编码展示串）
        phase_agents = [
            PhaseAgentRecord(
                name=rec["name"],
                role=rec["role"],
                focus=rec.get("focus", ""),
                used_tools=rec["used_tools"],
                outputs=rec["findings"],
            )
            for rec in agent_records
        ]

        confidence = analysis.get("confidence", "low")
        confidence_score = analysis.get(
            "confidence_score", CONFIDENCE_SCORES.get(confidence, 0.7)
        )
        needs_human_review = analysis.get("needs_human_review", confidence == "low")
        review_status = analysis.get(
            "review_status", "pending_review" if needs_human_review else "auto_reviewed"
        )

        # 阶段 6：研判结果持久化（误报记忆，评测时 record_history=False 不写入）
        #
        # 污染防线：该事件若存在人工**驳回**记录，本次裁决一律**不写入**误报记忆。
        # 记忆会被 `MemoryStore.search`（按同主机/同进程/行为重叠）取回，并注入后续
        # 所有同类事件的提示词——把一份「人明确否定过」的结论写进去，等于让错误
        # 结论通过组织记忆传播到未来每一条同主机告警。既然无法确认本次新结论已被
        # 人工认可，宁可不写（保守优于污染）。
        if getattr(self, "record_history", True):
            if human_feedback is not None and human_feedback.decision == DECISION_REJECT:
                analysis["reasoning_summary"] = list(analysis.get("reasoning_summary", []))
                analysis["reasoning_summary"].append(
                    "该事件存在人工驳回记录，本次裁决未写入误报记忆（避免被否定的结论经记忆扩散）。"
                )
            else:
                self.memory.append(
                    {
                        "event_id": event.id,
                        "host": event.host,
                        "process": event.process,
                        "behavior": event.behavior,
                        "event_type": analysis.get("event_type", "通用异常行为"),
                        "risk_level": analysis.get("risk_level", "medium"),
                        "confidence": confidence,
                        "is_false_positive": summary["is_false_positive"],
                    }
                )

        # 阶段 8：Ledger 最终裁决审计落盘（fail-open）
        if ledger is not None:
            ledger.finalize(
                {
                    "event_id": event.id,
                    "event_type": analysis.get("event_type", "通用异常行为"),
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
            event_type=analysis.get("event_type", "通用异常行为"),
            verdict=summary["verdict"],
            risk_level=summary["risk_level"],
            confidence=confidence,
            confidence_score=confidence_score,
            risk_score=analysis.get("risk_score", 0),
            is_false_positive=summary["is_false_positive"],
            review_status=review_status,
            needs_human_review=needs_human_review,
            prefilter_decision=prefilter_result.decision,
            # 阶段 2：透出读回的人工复核反馈（{} = 无人复核）。
            # review_status 的归属判定由 Reviewer 完成（见 agents/impl.py）。
            human_feedback=human_feedback.to_dict() if human_feedback is not None else {},
            module_trace=module_trace,
            phase_agents=phase_agents,
            plan_steps=analysis.get("plan", []),
            reasoning_summary=analysis.get("reasoning_summary", []),
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

    def analyze_alert(self, alert_id: str) -> AnalysisResult:
        return self.triage_event(alert_id)

    def coordinate_event(self, event_id: str) -> dict:
        """阶段 3：多 Agent 顺序协作（Planner → Classifier → Triage → Reviewer）。

        返回全链路记录（每 Agent 输入/输出），供 CLI/Web 展示与审计。
        """
        from security_agent.agents.coordinator import AgentCoordinator

        event = self.intake_service.get_event(event_id)
        knowledge_items, _ = self.knowledge_hub.retrieve_knowledge(event)

        context = {
            "knowledge_hub": self.knowledge_hub,
            "tool_registry": self.tool_registry,
        }
        # 预计算工具观测，供 Classifier/Triage Agent 复用（与主研判链路一致）
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
        context["tool_observations"] = [
            context["asset_observation"],
            context["log_observation"],
            context["intel_observation"],
            context["history_observation"],
            context["false_positive_observation"],
        ]
        context["prefilter_result"] = self.prefilter_engine.prefilter(
            event=event,
            asset_observation=context["asset_observation"],
            intel_observation=context["intel_observation"],
            false_positive_observation=context["false_positive_observation"],
            log_observation=context["log_observation"],
            history_observation=context["history_observation"],
        )
        context["force_rule_fallback"] = getattr(self, "force_rule_fallback", False)

        agent_input = AgentInput(
            event=event,
            context=context,
            knowledge_items=knowledge_items,
            plan=[],  # 由 PlannerAgent 生成
            llm=self.llm,
        )
        coordinator = AgentCoordinator()
        return coordinator.coordinate(agent_input)

    def evaluate_cases(self) -> dict:
        return self.evaluation_service.evaluate(self)
