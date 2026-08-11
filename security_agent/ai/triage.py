"""LLM 驱动的安全事件研判模块。

替代 IncidentTriageTool 中硬编码的 suspicious_markers 计数逻辑。核心设计：

1. 综合研判 — 构建中文研判提示词，融合事件详情、五项工具观察、
   知识库命中和研判计划，让 LLM 做决策核心；
2. 低温度确定性 — 调用 ai_chat_json（temperature=0.1）；
3. 防御性解析 — LLM 输出的每个字段都做类型校验，缺失或非法时使用
   默认值（risk_level 默认 medium，event_type 默认「通用异常行为」，
   非法 risk_score 由 risk_level 反推，空证据/建议自动生成）；
4. 失败开放 — LLM 不可用或输出非法 JSON 时，回退到轻量规则引擎
   （仅使用 5 个最关键恶意标记），置信度标记为 low 并注明
   「AI 不可用，使用规则引擎回退」，绝不抛出异常。

输出字段与 IncidentTriageTool 完全一致：
event_type / verdict / risk_level / confidence / is_false_positive /
reasoning_summary / evidence / recommendations / execution_log / tool_observations
"""

from __future__ import annotations

import logging
from typing import Optional

from security_agent.ai.client import ai_chat_json

logger = logging.getLogger(__name__)

# ── 取值域 ────────────────────────────────────────────────

RISK_LEVELS = ("critical", "high", "medium", "low")
CONFIDENCE_LEVELS = ("high", "medium", "low")

# 置信度分级 → 数值映射（阶段 2：置信度门控标准化）
CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.7, "low": 0.5}

# 由风险等级反推的风险分数（用于补齐缺失/非法的 risk_score）
_SCORE_FROM_LEVEL = {"critical": 85, "high": 68, "medium": 48, "low": 18}

_DEFAULT_VERDICT = {
    "critical": "高风险安全事件，建议立即升级处置并保全证据。",
    "high": "存在明显异常行为，建议优先研判并限制风险扩散。",
    "medium": "存在待确认风险，需要进一步补充上下文。",
    "low": "当前更接近误报或运维触发事件，建议结合变更单复核。",
}

# 规则引擎回退使用的 5 个最关键恶意标记
# （原 IncidentTriageTool 15 项标记中的核心子集）
HEURISTIC_MARKERS = ("encodedcommand", "downloadstring", "webshell", "beacon", "rundll32")

# ── Prompt 模板 ───────────────────────────────────────────

TRIAGE_SYSTEM_PROMPT = """\
你是一名拥有 15 年经验的资深 SOC 安全运营分析专家，擅长安全事件研判、误报剔除与威胁建模。

你的任务：基于提供的安全事件及其上下文证据，完成专业的事件分类、风险定级和误报判断。

研判原则：
1. 严格基于输入证据分析，禁止编造不存在的证据。
2. 证据不充分时保持保守：不盲目升级，也不轻易判定误报。
3. 综合考量事件本身特征、资产重要性、关联日志、威胁情报命中、历史告警、误报线索、知识库与研判计划。
4. 高风险攻击特征（PowerShell 编码执行、下载执行、WebShell、凭据窃取、横向枚举、C2 信标等）应显著加分；
   维护窗口、变更单、白名单命中、基线内运维行为等应显著减分。
5. 输出必须严格遵循 JSON 契约，字段名与取值准确。"""

JSON_CONTRACT = """{
  "event_type": "事件类型，仅限以下取值之一：恶意脚本执行 / 异常登录 / 异常外联 / 通用异常行为",
  "risk_level": "风险等级，仅限 critical / high / medium / low",
  "confidence": "置信度，仅限 high / medium / low",
  "risk_score": "0-100 的整数，按评分标准给出",
  "is_false_positive": "是否为误报，true 或 false",
  "verdict": "结论摘要，一句话描述最终研判结论",
  "reasoning_summary": "研判依据数组，2-4 条，逐条说明关键证据与推理",
  "evidence": "证据数组，2-6 条，每条为具体证据事实",
  "recommendations": "处置建议数组，2-6 条，按优先级排列"
}"""

FEW_SHOT_EXAMPLES = """\
## 参考示例
示例1（PowerShell 攻击）：
  事件：域控主机被外部 IP 通过 WinRM 发起 PowerShell 远程执行，原始日志含 EncodedCommand 编码命令；
  证据：资产为高重要度域控、日志显示引擎启动与远程会话、历史无同类告警、无误报线索。
  期望输出：event_type=恶意脚本执行，risk_level=critical，risk_score=85，is_false_positive=false。

示例2（维护误报）：
  事件：白名单资产在维护窗口内被内部扫描工具触发端口扫描告警；
  证据：存在变更单、资产已标记白名单、知识库明确该扫描器每日例行执行、无恶意特征。
  期望输出：event_type=通用异常行为，risk_level=low，risk_score=15，is_false_positive=true。

示例3（模糊外联）：
  事件：办公服务器对未知外部 IP 发起 443 出站连接；
  证据：情报库未命中该 IP/域名、资产为低重要度办公终端、日志无其他异常、历史无同类告警。
  期望输出：event_type=异常外联，risk_level=medium，risk_score=45，is_false_positive=false。"""


# ── 核心研判入口 ──────────────────────────────────────────


def triage_event(
    event,
    asset_observation,
    log_observation,
    intel_observation,
    history_observation,
    false_positive_observation,
    knowledge_items: list,
    plan: list,
    history_items: Optional[list] = None,
    on_llm_call=None,
) -> dict:
    """AI 驱动的事件研判入口（失败开放，绝不抛出异常）。

    Args:
        event: SecurityEvent 对象
        asset_observation / log_observation / intel_observation /
        history_observation / false_positive_observation: ToolObservation 对象
        knowledge_items: KnowledgeItem 列表
        plan: 研判计划步骤列表
        history_items: 相似历史研判记忆列表（阶段 6 误报记忆注入，可选）
        on_llm_call: 可选回调 (prompt, response)，用于审计记录（阶段 8 Ledger）

    Returns:
        dict，字段与 IncidentTriageTool 输出完全一致。
    """
    try:
        prompt = _build_user_prompt(
            event=event,
            asset_observation=asset_observation,
            log_observation=log_observation,
            intel_observation=intel_observation,
            history_observation=history_observation,
            false_positive_observation=false_positive_observation,
            knowledge_items=knowledge_items,
            plan=plan,
            history_items=history_items,
        )
        payload = ai_chat_json(
            [{"role": "user", "content": prompt}],
            system=TRIAGE_SYSTEM_PROMPT,
            temperature=0.1,  # 低温度确保一致性
            max_tokens=2000,
            on_llm_call=on_llm_call,
        )
        core = _parse_llm_result(
            payload,
            event=event,
            intel_observation=intel_observation,
            false_positive_observation=false_positive_observation,
            knowledge_items=knowledge_items,
            plan=plan,
        )
        if core is not None:
            return _assemble_result(
                core,
                event=event,
                asset_observation=asset_observation,
                log_observation=log_observation,
                intel_observation=intel_observation,
                history_observation=history_observation,
                false_positive_observation=false_positive_observation,
                ai_used=True,
            )
    except Exception as exc:  # noqa: BLE001 - 任何异常都回退规则引擎
        logger.warning("AI 研判异常，回退规则引擎: %s", exc)

    return _heuristic_fallback(
        event=event,
        asset_observation=asset_observation,
        log_observation=log_observation,
        intel_observation=intel_observation,
        history_observation=history_observation,
        false_positive_observation=false_positive_observation,
        knowledge_items=knowledge_items,
        plan=plan,
    )


# ── Prompt 构建 ───────────────────────────────────────────


def _build_user_prompt(
    event,
    asset_observation,
    log_observation,
    intel_observation,
    history_observation,
    false_positive_observation,
    knowledge_items: list,
    plan: list,
    history_items: Optional[list] = None,
) -> str:
    """构建综合研判提示词：事件详情 + 五项工具观察 + 知识库 + 历史记忆 + 计划 + 契约。"""
    history_section = _format_history(history_items) if history_items else "- 无相似历史研判记忆"
    return f"""请对以下安全事件进行专业研判。

## 事件信息
- 事件 ID: {event.id}
- 标题: {event.title}
- 初始严重性: {event.severity}
- 主机: {event.host} / 用户: {event.user}
- 进程: {event.process}
- 行为描述: {event.behavior}
- 原始日志: {event.raw_log}
- 目的 IP: {event.destination_ip or "无"}
- 目的域名: {event.destination_domain or "无"}
- 变更单: {event.change_ticket or "无"}

## 工具观察（上下文证据）
### 资产画像
{_format_observation(asset_observation)}
### 关联日志
{_format_observation(log_observation)}
### 威胁情报
{_format_observation(intel_observation)}
### 历史告警
{_format_observation(history_observation)}
### 误报检查
{_format_observation(false_positive_observation)}

## 知识库命中（含 ATT&CK 技术与 CVE 依据）
{_format_knowledge(knowledge_items)}

请结合上述知识条目中的 ATT&CK 技术映射与 CVE 依据进行研判；若事件行为命中某攻击技术（如 T1059.001 PowerShell 执行、T1003.001 凭据转储），请在 reasoning_summary 中明确引用对应技术编号，并据此定级。

## 历史研判记忆（相似历史，供一致性参考）
{history_section}
若本次事件与历史误报特征一致（同主机/同进程/同行为），可优先考虑误报，但必须结合本次新证据；若历史为攻击且本次特征相同，应保持一致的高风险判定。

## 研判计划
{_format_plan(plan)}

## 评分标准（risk_score, 0-100）
- 0-20：明确误报或无害行为（命中维护窗口、变更单、白名单，无恶意特征）
- 21-40：低风险，疑似误报或常规运维行为，需人工复核
- 41-60：中风险，存在异常特征但证据不充分
- 61-80：高风险，存在明显恶意特征（脚本攻击、情报命中、异常凭据行为等）
- 81-100：严重风险，具备完整攻击证据链或高危情报命中

## 输出 JSON 契约（必须严格遵守）
{JSON_CONTRACT}

{FEW_SHOT_EXAMPLES}

请仅输出 JSON 对象，不要附带任何其他说明文字。"""


# ── 防御性解析 ────────────────────────────────────────────


def _parse_llm_result(
    payload: Optional[dict],
    event,
    intel_observation,
    false_positive_observation,
    knowledge_items: list,
    plan: list,
) -> Optional[dict]:
    """防御性解析 LLM 输出：每个字段校验类型、非法值回退默认值。

    Returns:
        解析后的核心字段 dict；payload 非法时返回 None（走规则引擎回退）。
    """
    if not isinstance(payload, dict):
        return None

    # event_type：非空字符串，否则默认「通用异常行为」
    event_type = payload.get("event_type")
    if isinstance(event_type, str) and event_type.strip():
        event_type = event_type.strip()
    else:
        event_type = "通用异常行为"

    # risk_level：合法取值，否则由 risk_score 推导，再否则默认 medium
    risk_level = payload.get("risk_level")
    if isinstance(risk_level, str) and risk_level.strip().lower() in RISK_LEVELS:
        risk_level = risk_level.strip().lower()
    else:
        risk_level = ""

    # risk_score：0-100 整数；非法则由 risk_level 反推
    risk_score = _coerce_risk_score(payload.get("risk_score"))
    if risk_level == "":
        risk_level = _level_from_score(risk_score) if risk_score is not None else "medium"
    if risk_score is None:
        risk_score = _SCORE_FROM_LEVEL[risk_level]

    # confidence：合法取值，否则默认 medium；同时输出数值化置信度（门控用）
    confidence = payload.get("confidence")
    if isinstance(confidence, str) and confidence.strip().lower() in CONFIDENCE_LEVELS:
        confidence = confidence.strip().lower()
    else:
        confidence = "medium"
    confidence_score = CONFIDENCE_SCORES[confidence]

    # is_false_positive：严格布尔校验（防止字符串 "false" 被误判为 True）
    is_false_positive = payload.get("is_false_positive")
    if not isinstance(is_false_positive, bool):
        is_false_positive = False

    # verdict：非空字符串，否则按风险等级生成默认结论
    verdict = payload.get("verdict")
    if not (isinstance(verdict, str) and verdict.strip()):
        verdict = _DEFAULT_VERDICT[risk_level]

    # 列表字段：校验类型并过滤空串；空列表自动生成通用内容
    reasoning_summary = _as_string_list(payload.get("reasoning_summary"))
    evidence = _as_string_list(payload.get("evidence"))
    recommendations = _as_string_list(payload.get("recommendations"))

    if not evidence:
        evidence = _default_evidence(
            event=event,
            event_type=event_type,
            intel_observation=intel_observation,
            false_positive_observation=false_positive_observation,
            knowledge_items=knowledge_items,
        )
    if not recommendations:
        recommendations = _default_recommendations(risk_level, is_false_positive)
    if not reasoning_summary:
        reasoning_summary = [
            f"AI 模型综合事件特征、{len(knowledge_items)} 条知识库命中与 {len(plan)} 步研判计划，"
            f"给出风险分数 {risk_score}/100，判定风险等级为 {risk_level}，置信度 {confidence}。"
        ]

    return {
        "event_type": event_type,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "is_false_positive": is_false_positive,
        "reasoning_summary": reasoning_summary,
        "evidence": evidence,
        "recommendations": recommendations,
    }


# ── 规则引擎回退 ──────────────────────────────────────────


def _heuristic_fallback(
    event,
    asset_observation,
    log_observation,
    intel_observation,
    history_observation,
    false_positive_observation,
    knowledge_items: list,
    plan: list,
) -> dict:
    """轻量启发式回退（原 IncidentTriageTool 规则的简化版，仅 5 个关键标记）。

    置信度固定标记为 low，并在结果中注明「AI 不可用，使用规则引擎回退」。
    """
    corpus = " ".join([event.title, event.process, event.behavior, event.raw_log]).lower()
    suspicious_score = sum(1 for marker in HEURISTIC_MARKERS if marker in corpus)
    intel_score = 1 if intel_observation.details else 0
    false_positive_score = len(false_positive_observation.details)

    if "powershell" in corpus or "encodedcommand" in corpus:
        event_type = "恶意脚本执行"
    elif "login" in corpus or "登录" in event.title:
        event_type = "异常登录"
    elif intel_score:
        event_type = "异常外联"
    else:
        event_type = "通用异常行为"

    total_score = suspicious_score + intel_score - false_positive_score
    if total_score >= 4 and intel_score == 0:
        risk_level, is_false_positive = "high", False
    elif total_score >= 4:
        risk_level, is_false_positive = "critical", False
    elif total_score >= 2:
        risk_level, is_false_positive = "high", False
    elif false_positive_score >= 2:
        risk_level, is_false_positive = "low", True
    else:
        risk_level, is_false_positive = "medium", False

    core = {
        "event_type": event_type,
        "verdict": _DEFAULT_VERDICT[risk_level],
        "risk_level": risk_level,
        "risk_score": _SCORE_FROM_LEVEL[risk_level],
        "confidence": "low",  # 规则引擎回退，置信度标记为低
        "confidence_score": CONFIDENCE_SCORES["low"],
        "is_false_positive": is_false_positive,
        "reasoning_summary": [
            f"规则引擎回退研判：高风险标记命中 {suspicious_score} 项，"
            f"外联情报命中 {intel_score} 项，误报线索命中 {false_positive_score} 项。",
        ],
        "evidence": _default_evidence(
            event=event,
            event_type=event_type,
            intel_observation=intel_observation,
            false_positive_observation=false_positive_observation,
            knowledge_items=knowledge_items,
        ),
        "recommendations": _default_recommendations(risk_level, is_false_positive),
    }
    return _assemble_result(
        core,
        event=event,
        asset_observation=asset_observation,
        log_observation=log_observation,
        intel_observation=intel_observation,
        history_observation=history_observation,
        false_positive_observation=false_positive_observation,
        ai_used=False,
    )


# ── 结果组装 ──────────────────────────────────────────────


def _assemble_result(
    core: dict,
    event,
    asset_observation,
    log_observation,
    intel_observation,
    history_observation,
    false_positive_observation,
    ai_used: bool,
) -> dict:
    """组装与 IncidentTriageTool 完全一致的最终输出结构。"""
    if ai_used:
        engine_note = "AI 大模型已完成综合研判"
        reasoning_summary = [
            f"智能体通过 AI 大模型将该事件识别为“{core['event_type']}”场景，并按四模块链路完成初步研判。",
            *core["reasoning_summary"],
        ]
    else:
        engine_note = "AI 不可用，使用规则引擎回退"
        reasoning_summary = [
            f"智能体将该事件识别为“{core['event_type']}”场景，并按规则引擎链路完成初步研判。",
            *core["reasoning_summary"],
            engine_note,
        ]

    execution_log = [
        "任务入口模块读取事件样本",
        "知识与数据模块完成知识检索",
        asset_observation.summary,
        log_observation.summary,
        intel_observation.summary,
        history_observation.summary,
        false_positive_observation.summary,
        "工具执行模块完成研判聚合",
        engine_note,
    ]

    return {
        "event_type": core["event_type"],
        "verdict": core["verdict"],
        "risk_level": core["risk_level"],
        "risk_score": core["risk_score"],
        "confidence": core["confidence"],
        "confidence_score": core.get("confidence_score", CONFIDENCE_SCORES[core["confidence"]]),
        "is_false_positive": core["is_false_positive"],
        "reasoning_summary": reasoning_summary,
        "evidence": core["evidence"],
        "recommendations": core["recommendations"],
        "execution_log": execution_log,
        "tool_observations": [
            asset_observation,
            log_observation,
            intel_observation,
            history_observation,
            false_positive_observation,
        ],
    }


# ── 辅助函数 ──────────────────────────────────────────────


def _format_observation(observation) -> str:
    """格式化工具观察对象为 prompt 文本。"""
    summary = getattr(observation, "summary", "") or ""
    details = getattr(observation, "details", None) or []
    lines = [f"- 概要: {summary}"]
    if details:
        lines.append("- 详情: " + " | ".join(str(item) for item in details))
    else:
        lines.append("- 详情: 无")
    return "\n".join(lines)


def _format_history(history_items: list) -> str:
    """格式化历史研判记忆（阶段 6 误报记忆注入）。"""
    if not history_items:
        return "- 无相似历史研判记忆"
    lines = []
    for item in history_items:
        verdict = "误报" if item.get("is_false_positive") else "非误报"
        lines.append(
            f"- {item.get('timestamp', '')[:10]} {item.get('host', '?')} "
            f"同类事件 → {item.get('event_type', '?')} / {item.get('risk_level', '?')} / "
            f"判定: {verdict}"
        )
    return "\n".join(lines)


def _format_knowledge(knowledge_items: list) -> str:
    if not knowledge_items:
        return "- 未命中特定知识条目"
    lines = []
    for item in knowledge_items:
        attck = "/".join(getattr(item, "attck_ids", []) or []) or "无"
        cve = "/".join(getattr(item, "cve_ids", []) or []) or "无"
        lines.append(
            f"- {getattr(item, 'title', '')} [{getattr(item, 'category', 'general')}] "
            f"(ATT&CK: {attck} | CVE: {cve}): {getattr(item, 'content', '')}"
        )
    return "\n".join(lines)


def _format_plan(plan: list) -> str:
    if not plan:
        return "- 无"
    return "\n".join(f"- {step}" for step in plan)


def _coerce_risk_score(value) -> Optional[int]:
    """将 LLM 输出的风险分数强制转换为 0-100 整数，非法返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 100 else None
    if isinstance(value, float):
        rounded = int(round(value))
        return rounded if 0 <= rounded <= 100 else None
    return None


def _level_from_score(score: int) -> str:
    """由风险分数推导风险等级（与评分标准对应）。"""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


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


def _default_evidence(
    event,
    event_type: str,
    intel_observation,
    false_positive_observation,
    knowledge_items: list,
) -> list[str]:
    """生成默认证据链（基于事件事实与工具命中数量）。"""
    return [
        f"事件标题: {event.title}",
        f"事件类型: {event_type}",
        f"主机与账号: {event.host} / {event.user}",
        f"关键进程: {event.process}",
        f"行为描述: {event.behavior}",
        f"知识命中数量: {len(knowledge_items)}",
        f"外联情报命中数量: {len(intel_observation.details)}",
        f"误报线索数量: {len(false_positive_observation.details)}",
    ]


def _default_recommendations(risk_level: str, is_false_positive: bool) -> list[str]:
    """生成默认处置建议（按风险等级与误报状态差异化）。"""
    recommendations = [
        "复核进程链、登录行为和最近 24 小时外联记录",
        "关联终端、身份和网络日志确认影响范围",
        "保留原始日志，形成标准化研判记录",
    ]
    if is_false_positive:
        recommendations.insert(0, "核对维护窗口、变更单与白名单配置")
    if risk_level in {"high", "critical"}:
        recommendations.extend(
            [
                "对主机执行隔离或限制外联",
                "对相关账号执行临时管控",
                "将事件升级给安全运营人员进一步处置",
            ]
        )
    return recommendations
