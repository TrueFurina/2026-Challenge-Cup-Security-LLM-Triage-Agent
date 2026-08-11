"""AI 增强模块：统一 LLM 客户端、AI 事件研判与事件富化。

- client.ai_chat():       通用 AI 对话（失败开放）
- client.ai_chat_json():  结构化 JSON 输出（自动剥离代码围栏）
- triage.triage_event():  AI 安全事件研判（替代硬编码规则，带规则引擎回退）
- enricher.enrich_event(): AI 事件富化（MITRE ATT&CK / CVE / 调查步骤）
"""

from security_agent.ai.client import ai_chat, ai_chat_json
from security_agent.ai.enricher import enrich_event
from security_agent.ai.triage import triage_event

__all__ = [
    "ai_chat",
    "ai_chat_json",
    "triage_event",
    "enrich_event",
]
