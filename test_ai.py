import json
import os
from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


# 1. 告警输入模块
alert = {
    "alert_type": "SQL注入攻击",
    "src_ip": "45.23.11.8",
    "dst_ip": "10.0.0.5",
    "url": "/login?id=1' or '1'='1",
    "asset": "学生管理系统Web服务器",
    "level": "high",
    "time": "2026-05-17 14:20:00",
}


# 2. 工具模块
@tool
def query_ip_reputation(ip: str) -> str:
    """查询源IP信誉，返回该IP是否存在恶意扫描、攻击源或其他威胁情报。"""
    suspicious_ips = {
        "45.23.11.8": {
            "reputation": "malicious",
            "confidence": "high",
            "tags": ["scanner", "sql-injection-source"],
            "summary": "该IP存在扫描和SQL注入相关历史行为。",
        }
    }
    result = suspicious_ips.get(
        ip,
        {
            "reputation": "unknown",
            "confidence": "low",
            "tags": [],
            "summary": "未命中已知恶意情报。",
        },
    )
    return json.dumps(result, ensure_ascii=False)


@tool
def query_asset_info(asset_name: str) -> str:
    """查询目标资产画像，返回资产归属、重要性、是否外网暴露和业务属性。"""
    assets = {
        "学生管理系统Web服务器": {
            "owner": "教务信息中心",
            "importance": "critical",
            "internet_exposed": True,
            "business": "学生信息与登录认证",
            "summary": "核心业务Web资产，直接面向外网。",
        }
    }
    result = assets.get(
        asset_name,
        {
            "owner": "未知",
            "importance": "medium",
            "internet_exposed": False,
            "business": "未知",
            "summary": "未查询到明确资产画像。",
        },
    )
    return json.dumps(result, ensure_ascii=False)


@tool
def query_history_alert(asset_name: str) -> str:
    """查询历史告警，返回该资产近期是否出现同类攻击行为和时间分布。"""
    history = {
        "学生管理系统Web服务器": {
            "count_7d": 4,
            "last_alert": "2026-05-15 09:10:00",
            "patterns": ["SQL注入探测", "登录接口异常访问"],
            "summary": "近7天存在同类告警，攻击目标较集中。",
        }
    }
    result = history.get(
        asset_name,
        {
            "count_7d": 0,
            "last_alert": None,
            "patterns": [],
            "summary": "未检索到历史同类告警。",
        },
    )
    return json.dumps(result, ensure_ascii=False)


# 3. Prompt 模板
SYSTEM_PROMPT = """
你是一个企业SOC安全运营分析专家。
你的任务是分析安全告警，判断该告警是真实攻击、疑似威胁还是误报。

你必须结合：
1. 告警内容
2. IP信誉
3. 资产重要性
4. 历史告警

请先调用工具完成查询，再基于查询结果输出最终结论。

输出格式必须为：
【告警结论】
【风险等级】
【判断依据】
【处置建议】
【报告摘要】
""".strip()


def build_input_text(alert_payload: dict[str, Any]) -> str:
    return (
        "请分析以下安全告警：\n\n"
        f"{json.dumps(alert_payload, ensure_ascii=False, indent=2)}\n\n"
        "请你必要时调用工具查询IP信誉、资产信息和历史告警。"
    )


def extract_alert_from_messages(messages: list[BaseMessage]) -> dict[str, Any]:
    user_text = ""
    for message in messages:
        if message.type == "human":
            content = message.content
            if isinstance(content, str):
                user_text = content
            elif isinstance(content, list):
                user_text = "".join(
                    part.get("text", "") for part in content if isinstance(part, dict)
                )

    start = user_text.find("{")
    end = user_text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    return json.loads(user_text[start : end + 1])


def parse_tool_outputs(messages: list[BaseMessage]) -> dict[str, dict[str, Any]]:
    outputs: dict[str, dict[str, Any]] = {}
    for message in messages:
        if isinstance(message, ToolMessage):
            outputs[message.name] = json.loads(str(message.content))
    return outputs


def render_report(
    alert_payload: dict[str, Any],
    ip_data: dict[str, Any],
    asset_data: dict[str, Any],
    history_data: dict[str, Any],
) -> str:
    risk_score = 0
    reasons = []
    actions = []

    if "sql" in alert_payload.get("alert_type", "").lower():
        risk_score += 2
        reasons.append("告警类型为SQL注入攻击，属于常见Web高危攻击场景。")

    if "' or '1'='1" in alert_payload.get("url", "").lower():
        risk_score += 2
        reasons.append("URL参数包含典型SQL注入测试语句。")

    if ip_data.get("reputation") == "malicious":
        risk_score += 2
        reasons.append(f"源IP信誉较差：{ip_data.get('summary', '无')}")

    if asset_data.get("importance") == "critical":
        risk_score += 2
        reasons.append(f"目标资产重要性高：{asset_data.get('summary', '无')}")

    if history_data.get("count_7d", 0) > 0:
        risk_score += 1
        reasons.append(f"历史上存在同类攻击迹象：{history_data.get('summary', '无')}")

    if risk_score >= 7:
        conclusion = "真实攻击"
        risk_level = "高"
    elif risk_score >= 4:
        conclusion = "疑似威胁"
        risk_level = "中"
    else:
        conclusion = "误报"
        risk_level = "低"

    actions.extend(
        [
            "立即核查Web访问日志与WAF/网关日志，确认是否存在批量注入尝试。",
            "对源IP执行临时封禁或限速，并观察是否仍有同类请求。",
            "检查/login接口的参数化查询、输入校验和错误回显策略。",
        ]
    )
    if asset_data.get("importance") == "critical":
        actions.append("由于目标为核心业务资产，建议优先升级处置并安排人工复核。")

    summary = (
        f"该告警发生于 {alert_payload.get('time', '未知时间')}，源IP "
        f"{alert_payload.get('src_ip', '未知')} 针对 {alert_payload.get('asset', '未知资产')} "
        f"发起疑似SQL注入访问，综合IP信誉、资产重要性和历史告警情况，"
        f"判定为{conclusion}，风险等级为{risk_level}。"
    )

    return "\n".join(
        [
            "【告警结论】",
            conclusion,
            "",
            "【风险等级】",
            risk_level,
            "",
            "【判断依据】",
            *[f"- {reason}" for reason in reasons],
            "",
            "【处置建议】",
            *[f"- {action}" for action in actions],
            "",
            "【报告摘要】",
            summary,
        ]
    )


class MockSecurityChatModel(BaseChatModel):
    @property
    def _llm_type(self) -> str:
        return "mock-security-chat-model"

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> "MockSecurityChatModel":
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        tool_messages = [message for message in messages if isinstance(message, ToolMessage)]
        alert_payload = extract_alert_from_messages(messages)

        if not tool_messages:
            response = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "query_ip_reputation",
                        "args": {"ip": alert_payload.get("src_ip", "")},
                        "id": "call_ip_reputation",
                        "type": "tool_call",
                    },
                    {
                        "name": "query_asset_info",
                        "args": {"asset_name": alert_payload.get("asset", "")},
                        "id": "call_asset_info",
                        "type": "tool_call",
                    },
                    {
                        "name": "query_history_alert",
                        "args": {"asset_name": alert_payload.get("asset", "")},
                        "id": "call_history_alert",
                        "type": "tool_call",
                    },
                ],
            )
            return ChatResult(generations=[ChatGeneration(message=response)])

        tool_outputs = parse_tool_outputs(messages)
        report = render_report(
            alert_payload=alert_payload,
            ip_data=tool_outputs.get("query_ip_reputation", {}),
            asset_data=tool_outputs.get("query_asset_info", {}),
            history_data=tool_outputs.get("query_history_alert", {}),
        )
        response = AIMessage(content=report)
        return ChatResult(generations=[ChatGeneration(message=response)])


# 4. Agent 编排
def build_llm() -> BaseChatModel:
    if os.getenv("OPENAI_API_KEY"):
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        base_url = os.getenv("OPENAI_BASE_URL")
        return ChatOpenAI(model=model, temperature=0, base_url=base_url)
    return MockSecurityChatModel()


llm = build_llm()
tools = [query_ip_reputation, query_asset_info, query_history_alert]
agent = create_agent(model=llm, tools=tools, system_prompt=SYSTEM_PROMPT, debug=False)


# 5. 运行测试
if __name__ == "__main__":
    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": build_input_text(alert),
                }
            ]
        }
    )
    print(result["messages"][-1].content)
