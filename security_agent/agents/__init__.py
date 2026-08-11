"""多 Agent 协作层（阶段 3）。

从"单编排器 + 展示层分阶段"升级为"真正多 Agent 顺序协作"：
Triage Agent → Hunt Agent → Respond Agent → Report Agent，
前序 Agent 输出作为后序 Agent 输入，体现赛题 XH-202609 的"自主决策"。

设计原则：
1. 每个 Agent 可独立测试、可 mock（BaseAgent 抽象接口）
2. 任一步骤失败 → 降级到已有结论，不中断（fail-open）
3. 共享上下文 context 贯穿全链路，记录每步输入/输出供审计
"""
from security_agent.agents.base import AgentInput, AgentOutput, BaseAgent

__all__ = ["AgentInput", "AgentOutput", "BaseAgent"]
