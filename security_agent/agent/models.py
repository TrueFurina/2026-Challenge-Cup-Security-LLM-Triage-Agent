from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecurityEvent:
    id: str
    title: str
    severity: str
    source_ip: str
    host: str
    user: str
    process: str
    behavior: str
    raw_log: str
    destination_ip: str = ""
    destination_domain: str = ""
    scenario: str = "安全事件初步研判 + 误报剔除"
    change_ticket: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class KnowledgeItem:
    title: str
    content: str
    tags: list[str] = field(default_factory=list)
    category: str = "general"
    attck_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class AssetRecord:
    host: str
    owner: str
    department: str
    criticality: str
    baseline_processes: list[str] = field(default_factory=list)
    maintenance_window: str = ""


@dataclass
class IntelRecord:
    indicator: str
    indicator_type: str
    reputation: str
    note: str


@dataclass
class LogRecord:
    host: str
    user: str
    message: str
    timestamp: str
    # 事件归属：日志数据按「事件」标注归属，检索时优先按事件作用域返回。
    # 缺失（历史数据）时回落主机/账号匹配，保证向后兼容。
    # 加这个字段的原因：日志集按主机写死，同主机被多条事件共用时会互相灌入
    # 他人证据（实测 EVENT-013 拿到 EVENT-001 的 WinRM/Invoke-Expression 日志，
    # 导致「例行共享核查」被判成 critical）——属评测装置缺陷，非模型缺陷。
    event_id: str = ""


@dataclass
class HistoricalAlertRecord:
    event_id: str
    host: str
    user: str
    title: str
    verdict: str
    risk_level: str
    timestamp: str


@dataclass
class HistoryAlertMatch:
    """历史告警检索结果：记录 + 关联强度。

    历史告警是**弱关联线索**（「这台主机/这个账号以前有没有类似告警」），
    不是当前事件的取证证据，因此不能像日志那样做事件作用域隔离。
    但不同关联方式的证据力不同，必须显式区分并在观测中标注来源，
    否则模型会把异主机记录当成本机历史：

    - ``same_host``：同主机历史行为，强关联（该主机的行为画像）。
    - ``same_account``：仅账号同名，弱关联，且**通用/角色账号不参与召回**。
    """

    record: HistoricalAlertRecord
    relation: str  # "same_host" | "same_account"


@dataclass
class ToolObservation:
    tool_name: str
    summary: str
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "summary": self.summary,
            "details": self.details,
        }


@dataclass
class PhaseAgentRecord:
    name: str
    role: str
    focus: str
    used_tools: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "focus": self.focus,
            "used_tools": self.used_tools,
            "outputs": self.outputs,
        }


@dataclass
class AnalysisResult:
    event_id: str
    scenario: str
    event_type: str
    verdict: str
    risk_level: str
    confidence: str
    is_false_positive: bool
    module_trace: list[str]
    phase_agents: list[PhaseAgentRecord]
    plan_steps: list[str]
    reasoning_summary: list[str]
    evidence: list[str]
    recommendations: list[str]
    knowledge_hits: list[str]
    tool_observations: list[ToolObservation]
    execution_log: list[str]
    prefilter_decision: str = "NEED_LLM"
    confidence_score: float = 0.7
    review_status: str = "auto_reviewed"
    needs_human_review: bool = False
    risk_score: int = 0
    # 阶段 2：读回的人工复核反馈（无则为 {}）。供 Web/CLI 展示「人工已复核」状态，
    # 也是 HITL 闭环的取证——证明该结论已回到人的判断，而非停在单向写文件。
    human_feedback: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "scenario": self.scenario,
            "event_type": self.event_type,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "is_false_positive": self.is_false_positive,
            "module_trace": self.module_trace,
            "phase_agents": [item.to_dict() for item in self.phase_agents],
            "plan_steps": self.plan_steps,
            "reasoning_summary": self.reasoning_summary,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "knowledge_hits": self.knowledge_hits,
            "tool_observations": [item.to_dict() for item in self.tool_observations],
            "execution_log": self.execution_log,
            "prefilter_decision": self.prefilter_decision,
            "confidence_score": self.confidence_score,
            "review_status": self.review_status,
            "needs_human_review": self.needs_human_review,
            "risk_score": self.risk_score,
            "human_feedback": self.human_feedback,
        }


# ── 阶段 2 HITL：人工复核反馈（review_feedback.jsonl 的单条记录）──────────


@dataclass
class HumanFeedbackRecord:
    """人工在 Web 面板对某次裁决做的复核反馈（确认 / 驳回）。

    除 `decision` 外还记录**被复核的那次裁决摘要**（event_type / risk_level /
    is_false_positive）。这是读回闭环能成立的前提：只有知道"人否定/采纳的是
    哪个结论"，Agent 才能判断该反馈是否适用于本次新结论——否则只能把反馈当
    模糊先验塞进提示词，`review_status` 却无从判归属。

    旧记录（无裁决摘要字段）一律按"摘要未知"处理：仅作提示词参考，不参与
    review_status 判定，保证向后兼容。
    """

    event_id: str
    decision: str  # confirm | reject
    note: str = ""
    timestamp: str = ""
    event_type: str = ""
    risk_level: str = ""
    is_false_positive: Optional[bool] = None  # None = 摘要未知（旧格式）

    def has_verdict(self) -> bool:
        """是否携带可比的裁决摘要。"""
        return bool(self.event_type and self.risk_level) and self.is_false_positive is not None

    def matches_verdict(self, event_type: str, risk_level: str, is_false_positive: bool) -> bool:
        """该反馈是否针对同一份裁决结论（三者全等才算命中）。"""
        if not self.has_verdict():
            return False
        return (
            self.event_type == event_type
            and self.risk_level == risk_level
            and self.is_false_positive is bool(is_false_positive)
        )

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "decision": self.decision,
            "note": self.note,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "risk_level": self.risk_level,
            "is_false_positive": self.is_false_positive,
        }
