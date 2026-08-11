import subprocess
from datetime import datetime

from security_agent.agent.models import ToolObservation
from security_agent.tools.base import Tool


class AssetLookupTool(Tool):
    name = "asset_lookup"

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        asset = knowledge_hub.get_asset(event.host)
        if asset is None:
            return ToolObservation(
                tool_name=self.name,
                summary=f"未找到主机 {event.host} 的资产画像",
                details=[],
            )
        return ToolObservation(
            tool_name=self.name,
            summary=f"已获取 {event.host} 的资产画像",
            details=[
                f"资产负责人: {asset.owner}",
                f"部门: {asset.department}",
                f"重要性: {asset.criticality}",
                f"维护窗口: {asset.maintenance_window or '无'}",
                f"基线进程: {', '.join(asset.baseline_processes) or '无'}",
            ],
        )


class LogLookupTool(Tool):
    name = "log_lookup"

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        logs = knowledge_hub.find_logs(event.host, event.user)[:3]
        details = [f"{item.timestamp} {item.message}" for item in logs]
        return ToolObservation(
            tool_name=self.name,
            summary=f"返回 {len(details)} 条与主机/账号相关的日志",
            details=details or ["未检索到更多关联日志"],
        )


class IntelLookupTool(Tool):
    name = "intel_lookup"

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        records = knowledge_hub.get_intel(event.destination_ip, event.destination_domain)
        details = [
            f"{item.indicator} [{item.indicator_type}] 信誉: {item.reputation}; 说明: {item.note}"
            for item in records
        ]
        summary = f"命中 {len(details)} 条外联情报" if details else "未命中已知外联情报"
        return ToolObservation(tool_name=self.name, summary=summary, details=details)


class HistoryAlertLookupTool(Tool):
    name = "history_alert_lookup"

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        records = knowledge_hub.find_history_alerts(event.host, event.user)[:3]
        details = [
            f"{item.timestamp} {item.title} | 风险: {item.risk_level} | 结论: {item.verdict}"
            for item in records
        ]
        summary = f"返回 {len(details)} 条历史告警记录" if details else "未检索到历史告警记录"
        return ToolObservation(tool_name=self.name, summary=summary, details=details)


class FalsePositiveCheckTool(Tool):
    name = "false_positive_check"

    def run(self, **kwargs):
        event = kwargs["event"]
        asset_observation = kwargs["asset_observation"]
        log_observation = kwargs["log_observation"]
        corpus = " ".join(
            [
                event.process,
                event.behavior,
                event.raw_log,
                " ".join(asset_observation.details),
                " ".join(log_observation.details),
                event.change_ticket,
            ]
        ).lower()
        matches = []
        if "baseline" in corpus or "maintenance" in corpus:
            matches.append("命中基线或维护窗口特征")
        if event.change_ticket:
            matches.append(f"存在变更单: {event.change_ticket}")
        if "whitelist" in corpus:
            matches.append("命中白名单特征")

        summary = "发现误报线索，需要结合人工确认" if matches else "未发现明确误报线索"
        return ToolObservation(tool_name=self.name, summary=summary, details=matches)


class IncidentTriageTool(Tool):
    name = "incident_triage"

    def run(self, **kwargs):
        from security_agent.ai.triage import triage_event

        try:
            # AI 研判：LLM 决策 + 防御性解析 + 规则引擎回退（fail-open）
            return triage_event(**kwargs)
        except Exception as exc:  # noqa: BLE001 - 保险兜底，保证研判链路永不中断
            event = kwargs["event"]
            observations = [
                kwargs["asset_observation"],
                kwargs["log_observation"],
                kwargs["intel_observation"],
                kwargs["history_observation"],
                kwargs["false_positive_observation"],
            ]
            return {
                "event_type": "通用异常行为",
                "verdict": "存在待确认风险，需要进一步补充上下文。",
                "risk_level": "medium",
                "confidence": "low",
                "is_false_positive": False,
                "reasoning_summary": [
                    "研判模块出现异常，已启用最简兜底结果。",
                    f"异常原因: {exc}",
                ],
                "evidence": [
                    f"事件标题: {event.title}",
                    f"行为描述: {event.behavior}",
                ],
                "recommendations": [
                    "复核进程链、登录行为和最近 24 小时外联记录",
                ],
                "execution_log": [observation.summary for observation in observations],
                "tool_observations": observations,
            }


class PlaybookMatcherTool(Tool):
    name = "playbook_matcher"

    def run(self, **kwargs):
        event = kwargs["event"]
        analysis = kwargs["analysis"]
        if analysis["is_false_positive"]:
            playbook_name = "误报复核处置流程"
            steps = [
                "核对维护窗口、白名单和变更单",
                "确认无进一步恶意行为后关闭告警",
                "记录误报原因并更新规则抑制条件",
            ]
        elif analysis["risk_level"] == "critical":
            playbook_name = "高危入侵应急处置流程"
            steps = [
                "立即隔离主机并阻断外联",
                "冻结相关账号和高危会话",
                "保全内存、日志和进程链证据",
                "升级至应急响应团队",
            ]
        elif analysis["risk_level"] == "high":
            playbook_name = "高风险事件研判与遏制流程"
            steps = [
                "收敛受影响资产范围",
                "执行临时访问控制或主机隔离",
                "补充日志和身份侧证据后升级处置",
            ]
        else:
            playbook_name = "中风险持续观察流程"
            steps = [
                "追加 24 小时观察窗口",
                "补充网络、身份和主机上下文",
                "根据新增证据决定升级或关闭",
            ]
        return ToolObservation(
            tool_name=self.name,
            summary=f"匹配到处置预案: {playbook_name}",
            details=[f"适用事件: {event.title}", *steps],
        )


class TicketGeneratorTool(Tool):
    name = "ticket_generator"

    def run(self, **kwargs):
        event = kwargs["event"]
        analysis = kwargs["analysis"]
        now = datetime.utcnow().strftime("%Y%m%d%H%M%S")

        # 阶段 2：置信度门控 —— 低置信结果不自动生成 P 级工单，改"待复核记录"
        if analysis.get("confidence") == "low" or analysis.get("needs_human_review"):
            ticket_id = f"REVIEW-{event.id}-{now}"
            details = [
                f"记录编号: {ticket_id}",
                "优先级: 待人工复核（低置信度，不自动处置）",
                "处理队列: SOC-L1 / 人工复核",
                f"事件类型: {analysis['event_type']}",
                f"结论摘要: {analysis['verdict']}",
                "复核后可在 Web 面板确认或驳回，反馈回写 review_feedback",
            ]
            return ToolObservation(
                tool_name=self.name,
                summary=f"已生成待复核记录 {ticket_id}（低置信，未自动开 P 级工单）",
                details=details,
            )

        priority_map = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
        }
        queue_map = {
            "critical": "SOC-L2 / IR",
            "high": "SOC-L2",
            "medium": "SOC-L1",
            "low": "Security Operations",
        }
        priority = priority_map[analysis["risk_level"]]
        queue = queue_map[analysis["risk_level"]]
        ticket_id = f"TICKET-{event.id}-{now}"
        details = [
            f"工单编号: {ticket_id}",
            f"优先级: {priority}",
            f"处理队列: {queue}",
            f"事件类型: {analysis['event_type']}",
            f"结论摘要: {analysis['verdict']}",
        ]
        return ToolObservation(
            tool_name=self.name,
            summary=f"已生成模拟工单 {ticket_id}",
            details=details,
        )


class HostIsolationSimulatorTool(Tool):
    name = "host_isolation_simulator"

    def run(self, **kwargs):
        event = kwargs["event"]
        analysis = kwargs["analysis"]
        if analysis["is_false_positive"] or analysis["risk_level"] not in {"high", "critical"}:
            return ToolObservation(
                tool_name=self.name,
                summary="当前无需执行主机隔离动作",
                details=["原因: 风险等级不足或事件更接近误报"],
            )

        action = "建议立即隔离主机并限制外联"
        if analysis["risk_level"] == "critical":
            action = "建议立即执行主机隔离、阻断外联并冻结关联账号"
        return ToolObservation(
            tool_name=self.name,
            summary="已生成模拟处置动作",
            details=[
                f"目标主机: {event.host}",
                f"风险等级: {analysis['risk_level']}",
                f"动作建议: {action}",
                "执行模式: 模拟执行，需人工审批后落地",
            ],
        )


class CommandExecutionTool(Tool):
    name = "command_executor"

    def run(self, **kwargs):
        command = kwargs["command"]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True,
            check=False,
        )
        return {
            "success": completed.returncode == 0,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class IocSearchTool(Tool):
    """IOC 情报搜索（阶段 3 HuntAgent 用）：按主机/IP/域名/进程检索情报与知识库。"""

    name = "ioc_search"

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        indicators = [
            event.destination_ip,
            event.destination_domain,
            event.source_ip,
            event.host,
        ]
        hits = []
        for indicator in indicators:
            if not indicator:
                continue
            for record in knowledge_hub.get_intel(indicator):
                hits.append(
                    f"{record.indicator} [{record.indicator_type}] 信誉: {record.reputation}; {record.note}"
                )
        summary = f"IOC 情报命中 {len(hits)} 条" if hits else "未命中已知 IOC 情报"
        return hits if hits else []


class ToolRegistry:
    def __init__(self, tools: list[Tool]):
        self.tools = {tool.name: tool for tool in tools}

    @classmethod
    def default(cls, config) -> "ToolRegistry":
        tools: list[Tool] = [
            AssetLookupTool(),
            LogLookupTool(),
            IntelLookupTool(),
            HistoryAlertLookupTool(),
            FalsePositiveCheckTool(),
            IncidentTriageTool(),
            PlaybookMatcherTool(),
            TicketGeneratorTool(),
            HostIsolationSimulatorTool(),
            IocSearchTool(),
        ]
        if config.command_tool_enabled:
            tools.append(CommandExecutionTool())
        return cls(tools)

    def get(self, name: str) -> Tool:
        if name not in self.tools:
            raise KeyError(f"Unknown tool: {name}")
        return self.tools[name]
