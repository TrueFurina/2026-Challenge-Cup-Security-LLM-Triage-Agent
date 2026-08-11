"""MCP（Model Context Protocol）集成（阶段 7，前沿加分项）。

把安全工具以 MCP 标准暴露，体现"智能体可接入统一工具生态"。
纯标准库实现（stdio + JSON-RPC 2.0），零依赖、fail-open。
对标 [TriageMCP](https://github.com/alex-klinkovich/TriageMCP)、[Vigil](https://github.com/Vigil-SOC/vigil)。
"""
from security_agent.mcp.server import McpServer

__all__ = ["McpServer"]
