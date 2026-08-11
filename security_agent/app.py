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

    return SecurityAgent(
        llm=llm,
        intake_service=EventIntakeService.default(),
        knowledge_hub=KnowledgeHub.default(),
        tool_registry=ToolRegistry.default(config),
        evaluation_service=EvaluationService.default(),
    )
