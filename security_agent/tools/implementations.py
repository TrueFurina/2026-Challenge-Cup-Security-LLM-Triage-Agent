import inspect
import subprocess
from datetime import datetime

from security_agent.agent.models import ToolObservation
from security_agent.textmatch import keyword_hit
from security_agent.tools.base import Tool


class AssetLookupTool(Tool):
    name = "asset_lookup"
    requires = ("event",)

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
    requires = ("event",)

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        logs = knowledge_hub.find_logs(event.host, event.user, getattr(event, "id", ""))[:3]
        details = [f"{item.timestamp} {item.message}" for item in logs]
        return ToolObservation(
            tool_name=self.name,
            summary=f"返回 {len(details)} 条与主机/账号相关的日志",
            details=details or ["未检索到更多关联日志"],
        )


class IntelLookupTool(Tool):
    name = "intel_lookup"
    requires = ("event",)

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
    requires = ("event",)

    def run(self, **kwargs):
        event = kwargs["event"]
        knowledge_hub = kwargs["knowledge_hub"]
        matches = knowledge_hub.find_history_alerts(event.host, event.user)[:3]
        # 来源必须随记录一并呈现：不给来源主机时，模型会把异主机历史当成本机行为画像
        # （实测 EVENT-006/022/033 曾仅凭账号 www-data 同名拿到异主机的
        # 「疑似 C2 信标 / high」记录，且无从辨别来源）。
        details = []
        for match in matches:
            item = match.record
            if match.relation == "same_host":
                origin = f"同主机 {item.host}"
            else:
                origin = f"异主机 {item.host} · 仅账号 {item.user} 同名（弱关联，仅供参考）"
            details.append(
                f"[{origin}] {item.timestamp} {item.title} | "
                f"风险: {item.risk_level} | 结论: {item.verdict}"
            )
        if not details:
            summary = "未检索到历史告警记录"
        else:
            same_host = sum(1 for m in matches if m.relation == "same_host")
            summary = (
                f"返回 {len(details)} 条历史告警记录"
                f"（同主机 {same_host} 条，异主机账号同名 {len(details) - same_host} 条）"
            )
        return ToolObservation(tool_name=self.name, summary=summary, details=details)


class FalsePositiveCheckTool(Tool):
    name = "false_positive_check"
    # 必需项只有 event 与 asset_observation：`run` 要读 event 的字段与
    # `asset_observation.details`（维护窗口 / 基线进程两个结构化信号）。
    # 刻意**不含** log_observation —— 见 run 内的语料隔离说明，
    # 声明必须等于真实契约，多报依赖会让客户端白传参数（由
    # scripts/_mcp_matrix_gate.py 的必要性断言把住）。
    requires = ("event", "asset_observation")

    def run(self, **kwargs):
        event = kwargs["event"]
        asset_observation = kwargs["asset_observation"]
        # 语料隔离：仅事件自身字段参与关键词匹配。**刻意不取**
        # log_observation/历史告警 —— 它们与本次事件无必然因果关系。
        # v1 缺陷：把资产画像与关联日志 details 一并拼入，导致用他机/历史
        # 上下文判定本次事件（如 DC-01 的基线进程 lsass.exe 让任何事件
        # 都像"凭据转储"，历史日志里的 maintenance 让攻击看起来像误报）。
        corpus = " ".join(
            [
                event.process,
                event.behavior,
                event.raw_log,
                " ".join(getattr(event, "tags", []) or []),
                event.change_ticket,
            ]
        ).lower()
        matches = []
        # 结构化信号：资产维护窗口（解析自资产画像，非文本匹配）
        if any(
            detail.startswith("维护窗口:") and "无" not in detail
            for detail in asset_observation.details
        ):
            matches.append("资产存在维护窗口")
        # 结构化信号：进程属资产基线（正常白名单，仅作减分项）
        baseline_hit = False
        for detail in asset_observation.details:
            if not detail.startswith("基线进程:"):
                continue
            names = [n.strip().lower() for n in detail.split(":", 1)[1].split(",")]
            baseline_hit = str(event.process).lower() in names
            break
        routine_words = ("例行", "维护", "maintenance", "backup", "备份",
                         "同步", "sync", "scan", "扫描", "routine", "批量")
        if baseline_hit and any(keyword_hit(corpus, w) for w in routine_words):
            matches.append("进程属资产基线且行为为例行操作")
        # 否定语境护栏：'source workstation not in admin group baseline' 这类
        # 否定表述曾被当作「基线内行为」，据此生成误报线索，把已确认的管理共享
        # 访问从 high 压到 medium（实测 H-09）。否定句不构成误报线索。
        if any(keyword_hit(corpus, k) for k in ("baseline", "maintenance", "例行")):
            matches.append("命中基线或维护窗口特征")
        if event.change_ticket:
            matches.append(f"存在变更单: {event.change_ticket}")
        if any(keyword_hit(corpus, k) for k in ("whitelist", "白名单")):
            matches.append("命中白名单特征")

        summary = "发现误报线索，需要结合人工确认" if matches else "未发现明确误报线索"
        return ToolObservation(tool_name=self.name, summary=summary, details=matches)


class IncidentTriageTool(Tool):
    name = "incident_triage"
    # 研判主入口：正常路径透传给 triage_event 消费全部上游观察结果，
    # 兜底路径也逐个读 summary。缺任一 observation 即失败。
    requires = (
        "event",
        "asset_observation",
        "log_observation",
        "intel_observation",
        "history_observation",
        "false_positive_observation",
    )

    @staticmethod
    def _adapt_kwargs(kwargs: dict) -> dict:
        """把调用方入参适配为 `triage_event` 的签名。

        **为什么必须做**：本工具是 `triage_event` 的薄封装，而各调用方入参形态
        并不统一——MCP 层会附带 `knowledge_hub`（`triage_event` 不接受），
        生产规则回退分支（`agents/impl.py` 的 `force_rule_fallback` 路径）则
        未传必需参数 `plan`。原样 `**kwargs` 转发必然 `TypeError`。

        危险之处在于下方 `except Exception` 会 fail-open：把 `TypeError`
        变成"最简兜底结果"，于是工具返回 `isError=False`、
        调用方以为研判成功，**实际一步研判都没做**。
        实测两条路径 100% 触发兜底（2026-10-14），故在此做键过滤 + 必需项补齐。
        """
        from security_agent.ai.triage import triage_event

        allowed = set(inspect.signature(triage_event).parameters)
        adapted = {k: v for k, v in kwargs.items() if k in allowed}

        # knowledge_items 为必需项：MCP 通道只带 knowledge_hub，按事件现场检索补齐
        if "knowledge_items" not in adapted:
            hub, event = kwargs.get("knowledge_hub"), kwargs.get("event")
            items: list = []
            if hub is not None and event is not None:
                try:
                    items = hub.retrieve_knowledge(event)[0]
                except Exception:  # noqa: BLE001 - 检索失败退化为空知识集
                    items = []
            adapted["knowledge_items"] = items

        # plan 为必需项：无 PlannerAgent 上游时（MCP 单次调用 / 规则回退）给空计划，
        # 由 `_format_plan` 渲染为"无计划"，而不是让整个研判退化成兜底。
        adapted.setdefault("plan", [])
        return adapted

    def run(self, **kwargs):
        from security_agent.ai.triage import triage_event

        try:
            # AI 研判：LLM 决策 + 防御性解析 + 规则引擎回退（fail-open）
            return triage_event(**self._adapt_kwargs(kwargs))
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
    requires = ("event", "analysis")

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
    requires = ("event", "analysis")

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
    requires = ("event", "analysis")

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
    # 不读 event：唯一必需入参是 `command`。此前被硬编码声明为 required=["event"]，
    # 遵循声明的客户端会传 event 而不传 command，调用必失败。
    requires = ("command",)

    def run(self, **kwargs):
        command = kwargs["command"]
        completed = subprocess.run(
            command,
            capture_output=True,
            # 显式 UTF-8 + replace：子进程输出按本机代码页解会在英文 Windows 上
            # 解错（cp1252）甚至抛 UnicodeDecodeError；工具输出还要回灌给 LLM，
            # 不能在这里崩，也不能静默解错。
            encoding="utf-8",
            errors="replace",
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
    # 返回**命中列表**，而非其余 10 个工具的统一形态 `ToolObservation`。
    # 这是刻意的既成事实，不是遗漏（2026-10-14 复核）：
    #   · 检索语义——命中项本身就是结论，没有要转交下游的中间结论；
    #   · 无任何消费方按 `ToolObservation` 解析它（`agents/coordinator.py` 只注册
    #     工具对象本身，输出进 context 供 LLM 阅读）；
    #   · MCP 出口矩阵门禁亦不约束返回形态，故此处不构成契约缺陷。
    # 原实现在 return 前算过一个 `summary`（「IOC 情报命中 N 条」）却从未返回 ——
    # 死变量，属未完成的改写残留，已删除。**没有**顺手改成 `ToolObservation`：
    # 统一形态会改变 LLM 可见的工具输出面，该面被评测口径间接依赖，
    # 要改须连同评测基线一起动，不能夹带在"清理"里。
    requires = ("event",)

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
        # 空列表 = 「检索过、未命中」，与调用失败（MCP 层 isError=true）可区分。
        return hits


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
