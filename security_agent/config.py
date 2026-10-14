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
    #: 是否把研判结果落盘为运行时数据（审计台账 `data/ledger/*` 与误报记忆
    #: `data/triage_history.jsonl`）。**默认开启**——生产语义要留证据。
    #: 测试 / 隔离跑批置 0（`SECURITY_AGENT_RUNTIME_WRITES=0`）。
    #:
    #: 为什么需要它：`SecurityAgent.evaluation_sandbox()` 是**实例方法**，
    #: CLI 与子进程路径（`_verify.py` 经 `cli.py analyze`）拿不到 app 实例，
    #: 关不掉写；这两条路径会覆写生产台账。此开关是它们唯一可用的收口。
    runtime_writes_enabled: bool = True

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
            runtime_writes_enabled=os.getenv("SECURITY_AGENT_RUNTIME_WRITES", "1") == "1",
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
