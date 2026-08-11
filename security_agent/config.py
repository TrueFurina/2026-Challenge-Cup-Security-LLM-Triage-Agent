import os
from dataclasses import dataclass


@dataclass
class AppConfig:
    use_real_llm: bool
    llm_provider: str
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    llm_timeout_seconds: int
    command_tool_enabled: bool

    @classmethod
    def from_env(cls) -> "AppConfig":
        use_real_llm = os.getenv("SECURITY_AGENT_USE_REAL_LLM", "0") == "1"
        provider = os.getenv("SECURITY_AGENT_LLM_PROVIDER", "generic").strip().lower()
        base_url, model = _resolve_provider_defaults(provider)
        return cls(
            use_real_llm=use_real_llm,
            llm_provider=provider,
            llm_base_url=os.getenv(
                "SECURITY_AGENT_LLM_BASE_URL",
                base_url,
            ),
            llm_api_key=os.getenv("SECURITY_AGENT_LLM_API_KEY", ""),
            llm_model=os.getenv("SECURITY_AGENT_LLM_MODEL", model),
            llm_timeout_seconds=int(os.getenv("SECURITY_AGENT_LLM_TIMEOUT", "45")),
            command_tool_enabled=os.getenv("SECURITY_AGENT_ENABLE_COMMAND_TOOL", "0")
            == "1",
        )


def _resolve_provider_defaults(provider: str) -> tuple[str, str]:
    if provider == "deepseek":
        return ("https://api.deepseek.com/chat/completions", "deepseek-v4-flash")
    if provider == "qwen":
        return (
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            "qwen-plus",
        )
    return ("https://api.openai.com/v1/chat/completions", "gpt-4o-mini")
