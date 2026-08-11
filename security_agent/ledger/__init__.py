"""Investigation Ledger 审计追踪（阶段 8，评审杀手锏）。

记录每次研判的完整证据链（prompt / LLM响应 / 工具调用 / 证据引用 / 最终裁决），
可回放、可审计。对标 [AiSOC](https://github.com/beenuar/AiSOC) 的 Investigation Ledger。
"""
from security_agent.ledger.store import LedgerStore

__all__ = ["LedgerStore"]
