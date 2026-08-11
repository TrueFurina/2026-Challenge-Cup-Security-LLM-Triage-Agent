"""确定性预筛器（阶段 1 核心交付）。

规则先筛，不确定才给 LLM —— 提升速度、降低成本、提高准确率。
输出三态：AUTO_CLOSE（误报自动关闭）/ AUTO_ESCALATE（直接定级）/ NEED_LLM（深度研判）。
"""

from security_agent.prefilter.engine import (
    AUTO_CLOSE,
    AUTO_ESCALATE,
    NEED_LLM,
    PreFilterEngine,
    PreFilterResult,
)

__all__ = [
    "AUTO_CLOSE",
    "AUTO_ESCALATE",
    "NEED_LLM",
    "PreFilterEngine",
    "PreFilterResult",
]
