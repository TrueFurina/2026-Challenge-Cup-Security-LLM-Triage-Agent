from security_agent.agent.orchestrator import SecurityAgent
from security_agent.config import AppConfig
from security_agent.evaluation import EvaluationService
from security_agent.intake.service import EventIntakeService
from security_agent.knowledge.store import KnowledgeHub
from security_agent.llm.mock import MockLLM
from security_agent.llm.openai_compatible import OpenAICompatibleLLM
from security_agent.tools.implementations import ToolRegistry


def build_app() -> SecurityAgent:
    config = AppConfig.from_env()
    if config.use_real_llm:
        llm = OpenAICompatibleLLM(
            base_url=config.llm_base_url,
            api_key=config.llm_api_key,
            model=config.llm_model,
            timeout_seconds=config.llm_timeout_seconds,
        )
    else:
        llm = MockLLM()

    app = SecurityAgent(
        llm=llm,
        intake_service=EventIntakeService.default(),
        knowledge_hub=KnowledgeHub.default(),
        tool_registry=ToolRegistry.default(config),
        evaluation_service=EvaluationService.default(),
    )
    if not config.runtime_writes_enabled:
        # 隔离模式（SECURITY_AGENT_RUNTIME_WRITES=0）：不写审计台账、不写误报记忆。
        # 为什么放在这里而不是 `evaluation_sandbox()` 里：后者是**实例方法**，
        # 而 CLI 与子进程路径（如 `scripts/_verify.py` 调 `cli.py analyze`）
        # 各自新建 app、拿不到实例，只有配置开关能统一覆盖。
        app.record_ledger = False
        app.record_history = False
    return app
