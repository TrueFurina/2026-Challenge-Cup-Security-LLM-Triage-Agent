from dataclasses import dataclass, field


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
        }
