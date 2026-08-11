"""事件富化模块：使用 LLM 补充 MITRE ATT&CK 技术、相关 CVE 与调查步骤。

属于可选增强能力（enhancement）：任何失败都返回空结构，
不影响主研判流程（失败开放）。
"""

from __future__ import annotations

import logging
from typing import Optional

from security_agent.ai.client import ai_chat_json

logger = logging.getLogger(__name__)

ENRICH_SYSTEM_PROMPT = """\
你是一名资深安全威胁情报分析专家。
请基于给定的安全事件信息，输出威胁研判所需的富化情报：
1. 最可能相关的 MITRE ATT&CK 技术（最多 5 项，给出技术编号与名称）；
2. 可能相关的已知 CVE 编号（无明确依据时返回空数组，严禁编造）；
3. 建议的进一步调查步骤（3-5 步，按执行顺序排列）。

严格基于事件内容推断，只输出 JSON。"""

ENRICH_JSON_CONTRACT = """输出 JSON 字段说明：
- "mitre_techniques": 对象数组，每项 {"technique_id": "Txxxx", "name": "技术名称"}
- "related_cves": 字符串数组
- "investigation_steps": 字符串数组"""


def enrich_event(event) -> dict:
    """使用 LLM 富化事件情报（失败开放，绝不抛出异常）。

    Args:
        event: SecurityEvent 对象

    Returns:
        dict，包含 mitre_techniques / related_cves / investigation_steps / note。
        字段缺失或 LLM 不可用时返回空列表，note 说明富化状态。
    """
    if event is None:
        return _empty_enrichment("事件为空，跳过富化")
    try:
        prompt = _build_user_prompt(event)
        payload = ai_chat_json(
            [{"role": "user", "content": prompt}],
            system=ENRICH_SYSTEM_PROMPT,
            temperature=0.2,  # 富化为可选增强，可接受略高温度
            max_tokens=1000,
        )
        return _parse_enrichment(payload)
    except Exception as exc:  # noqa: BLE001 - 失败开放：任何异常返回空结构
        logger.warning("事件富化失败（fail-open 返回空结构）: %s", exc)
        return _empty_enrichment("AI 富化不可用")


# ── 内部实现 ──────────────────────────────────────────────


def _build_user_prompt(event) -> str:
    """构建富化提示词（简短版，仅事件核心信息）。"""
    return f"""事件信息：
- ID: {event.id}
- 标题: {event.title}
- 严重性: {event.severity}
- 主机: {event.host} / 用户: {event.user}
- 进程: {event.process}
- 行为描述: {event.behavior}
- 原始日志: {event.raw_log}
- 目的 IP: {event.destination_ip or "无"}
- 目的域名: {event.destination_domain or "无"}

{ENRICH_JSON_CONTRACT}

请仅输出 JSON 对象，不要附带任何其他说明文字。"""


def _parse_enrichment(payload: Optional[dict]) -> dict:
    """防御性解析富化结果，非法/缺失字段回退为空列表。"""
    if not isinstance(payload, dict):
        return _empty_enrichment("AI 富化结果无效")

    techniques: list[dict] = []
    raw_techniques = payload.get("mitre_techniques")
    if isinstance(raw_techniques, list):
        for item in raw_techniques:
            if not isinstance(item, dict):
                continue
            technique_id = item.get("technique_id")
            name = item.get("name")
            if (
                isinstance(technique_id, str)
                and technique_id.strip()
                and isinstance(name, str)
                and name.strip()
            ):
                techniques.append({"technique_id": technique_id.strip(), "name": name.strip()})
            if len(techniques) >= 5:  # 最多保留 5 项
                break

    cves = _as_string_list(payload.get("related_cves"))
    steps = _as_string_list(payload.get("investigation_steps"))

    return {
        "mitre_techniques": techniques,
        "related_cves": cves,
        "investigation_steps": steps,
        "note": "AI 富化完成",
    }


def _empty_enrichment(note: str) -> dict:
    """返回空富化结构。"""
    return {
        "mitre_techniques": [],
        "related_cves": [],
        "investigation_steps": [],
        "note": note,
    }


def _as_string_list(value) -> list[str]:
    """将任意值规范为非空字符串列表，过滤空串与非法项。"""
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if isinstance(item, str):
            text = item.strip()
        else:
            try:
                text = str(item).strip()
            except Exception:  # noqa: BLE001 - 极异常对象直接跳过
                continue
        if text:
            items.append(text)
    return items
