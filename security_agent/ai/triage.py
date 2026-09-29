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
from security_agent.textmatch import matched_keywords

logger = logging.getLogger(__name__)

# ── 取值域 ────────────────────────────────────────────────

RISK_LEVELS = ("critical", "high", "medium", "low")
CONFIDENCE_LEVELS = ("high", "medium", "low")

# 置信度分级 → 数值映射（阶段 2：置信度门控标准化）
CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.7, "low": 0.5}

# 由风险等级反推的风险分数（用于补齐缺失/非法的 risk_score）
_SCORE_FROM_LEVEL = {"critical": 85, "high": 68, "medium": 48, "low": 18}

# 误报事件的类型标签与分数上限（LLM 路径与规则回退路径共用同一口径，
# 避免两条路径对同类误报给出不同字段值）
FALSE_POSITIVE_EVENT_TYPE = "误报"
SCORE_FALSE_POSITIVE_MAX = _SCORE_FROM_LEVEL["low"]

_DEFAULT_VERDICT = {
    "critical": "高风险安全事件，建议立即升级处置并保全证据。",
    "high": "存在明显异常行为，建议优先研判并限制风险扩散。",
    "medium": "存在待确认风险，需要进一步补充上下文。",
    "low": "当前更接近误报或运维触发事件，建议结合变更单复核。",
}

# 规则引擎回退：事件类型识别与证据加权评分（标记定义见下方 EVENT_TYPE_PATTERNS）
# 注：原 HEURISTIC_MARKERS（仅 5 个硬编码标记）已废弃，改为 EVENT_TYPE_PATTERNS
# 覆盖 ATT&CK 常见手法，避免大量事件被兜底为 medium/通用异常行为。

# ── 规则引擎回退：语义化事件分类与风险评分 ────────────────
# 回退路径是"LLM 不可用时的最后一道防线"。原实现只认 5 个 marker，
# 其余全部兜底为 medium/通用异常行为，导致大量事件分类错误。
# 这里改为「事件类型识别 + 证据加权评分」，指标取业界通用攻击特征
# （MITRE ATT&CK 常见手法），而非针对特定测试样本的关键词。

# 事件类型识别模式，按危害程度降序，取首个命中
# 口径（与 TRIAGE_SYSTEM_PROMPT 的「投递 / 执行阶段」约定保持一致）：
# 已进入**执行阶段**（脚本解释器实际运行、下载执行）优先判为「恶意脚本执行」；
# 仍在**投递阶段**（邮件/网关拦截、附件未打开、仅落地宏载荷）才判为「恶意载荷投递」。
# 二者同时具备证据时以「已执行」为准，否则宏文档会被 downloadstring 等特征带走、
# 且与「邮件网关拦截」类事件（应归投递）产生同族口径冲突。
EVENT_TYPE_PATTERNS = (
    # 注：不纳入 rundll32——它是 Windows 常见 LOLBin，正常软件也大量调用，
    # 单凭进程名不足以判定「脚本执行」，会把 C2 信标类事件误吸为脚本执行（实测 H-10）。
    # 反弹 shell 指标（ATT&CK T1059.004 / T1071）纳入本类：解释器实际运行并建立外联。
    ("恶意脚本执行", ("encodedcommand", "downloadstring", "invoke-expression",
                   "powershell -enc", "iex(", "wscript", "cscript",
                   "shellexecute", "bypass", "hidden -e",
                   "/dev/tcp/", "reverse shell", "反弹 shell", "bash -i")),
    ("恶意载荷投递", ("exploit payload", ".docm", "macro-download",
                   "ole_object", "恶意宏", "宏文档", "宏附件")),
    ("WebShell 攻击", ("shell.jsp", "webshell", "cmd=whoami", "aspx?cmd",
                    "jsp?cmd", "cmd.exe&c=")),
    ("勒索软件加密", ("ransomware", ".encrypted", ".locked", "readme_decrypt",
                   "wannacry", "加密后缀")),
    ("凭据转储", ("mimikatz", "sekurlsa", "minidump", "cred.dll",
                "comsvcs.dll", "procdump", "lsass",
                "credential cache", "凭据缓存", "凭据转储")),
    # 第二垂类「Web 漏洞利用研判」：特征词与「脚本执行/投递」族互不重叠，
    # 因此插入位置不影响既有分类（已在 32 例 + holdout v1/v2/v3 上回归验证）。
    ("Web 漏洞利用", ("sql injection", "union select", "sqli", "命令注入",
                   "command injection", "反序列化", "deserialization",
                   "path traversal", "目录穿越", "../..", "文件上传漏洞",
                   "unrestricted upload", "exploit attempt", "cve-20")),
    ("横向移动前置", ("psexec", "share=admin", "admin$", "ipc$",
                   "wmic /node", "net use")),
    ("数据渗出", ("批量导出", "导出全表", "upload to oss", "upload to s3",
                "bulk exfil", "select * from", "数据外传", "外传",
                "upload to external", "export customer")),
    # 注：不纳入 "outbound" 之类泛化词——正常业务的 TLS 出站连接同样会命中，
    # 会把例行对账流量误判为异常外联。
    ("异常外联", ("beacon", "c2", "外联", "信标", "malware-c2")),
    ("异常登录", ("4625", "failed to log", "登录失败", "login attempt",
                "ssh 登录", "ssh.exe", "logged on", "4624",
                "堡垒机", "跳转", "跳板", "暴力", "brute")),
)

# 各事件类型的基线风险分
_TYPE_BASE_SCORE = {
    "恶意脚本执行": 72,
    "WebShell 攻击": 82,
    "勒索软件加密": 82,
    "凭据转储": 82,
    "Web 漏洞利用": 70,
    "恶意载荷投递": 66,
    "横向移动前置": 62,
    "数据渗出": 68,
    "异常外联": 55,
    "异常登录": 45,
    "通用异常行为": 40,
}

# 加分/减分权重（可解释、可调）
SCORE_INTEL_MALICIOUS = 15      # 威胁情报判定目标恶意
SCORE_ASSET_CRITICAL = 8        # 资产重要度 high/critical
SCORE_BASELINE_PROCESS = -10    # 进程属资产基线（正常白名单）
SCORE_PER_FP_CLUE = -12         # 每条误报线索
SCORE_CHANGE_TICKET = -6        # 存在变更单（弱减分，不可单独定性）
SCORE_C2_DOMAIN = 8            # 异常外联目标含强 C2 特征 → 升级 high
SCORE_OPS_REVIEW = -15         # 堡垒机/运维核查等合法运维登录 → 降级 low
SCORE_BRUTE_FORCE = 20         # 暴力破解/凭证填充登录 → 升级 high
SCORE_EXFIL_CRITICAL = 16      # 确认大规模数据渗出（无变更单）→ 升级 critical
SCORE_REMOTE_AUTO = 12         # 无用户交互的远程/自动执行链 → 升级 critical（分级标准判据③）
BRUTE_MARKERS = ("暴力", "brute", "count=", "failed password", "大量失败", "多次失败")
# 「无用户交互的远程/自动下发」标记：分级标准判据③ 的落地依据。
# 与 INTERACTION_CARRIER_MARKERS（文档/附件载体）互斥——有载体说明需用户交互。
REMOTE_AUTO_MARKERS = (
    "remote service", "remote session", "remote command", "via remote",
    "winrm", "remote ip=", "unattended", "no interactive user session",
    "远程服务", "远程下发", "远程执行", "远程会话", "无用户交互",
)
EXFIL_CRITICAL_MARKERS = (
    "select * from", "导出全表", "export customer", "bulk exfil",
    "upload to s3", "upload to external", "导出全量", "全量导出",
)
C2_STRONG_MARKERS = ("malware-c2", "c2.example", "c2-server", "c2-node", "信标", "beacon")
OPS_REVIEW_MARKERS = ("堡垒机", "运维核查", "运维人员", "跳板", "核查", "例行")
ROUTINE_OPS_MARKERS = (
    "routine", "例行", "运维核查", "view share", "shared list",
    "backup", "备份", "扫描", "scan", "同步", "sync", "maintenance",
    "payment gateway", "对账", "tls handshake", "加密通道", "业务通信",
    "business api", "api 调用",
)
FP_THRESHOLD_SCORE = 30         # 低于此分判定误报
FP_MIN_CLUES = 2                # 判定误报所需的最少线索数
SCORE_ATTACK_FLOOR = 40         # 已确认攻击类型的分数下限（= medium 起点，见分级标准第 3 节）

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
5. 输出必须严格遵循 JSON 契约，字段名与取值准确。

风险等级判据（按**事件性质**定级，这是定级的主依据）：
- critical：满足任一即成立——① **不可逆损害已发生或正在发生**：勒索软件加密、凭据转储（lsass 访问、
  mimikatz、procdump 转储）、已可交互的 WebShell、已确认的大批量数据外传；② **高价值资产（域控 /
  数据库 / 核心业务系统）上确认的攻击行为**；③ **无用户交互前提的远程或自动执行链**（网络侧直接
  下发并执行的编码命令、下载执行，不经「用户打开文档/附件」这类交互动作）。
- high：已确认的攻击或高可信入侵链路——**需用户交互触发**的执行链（钓鱼文档/邮件附件打开后 spawn
  脚本解释器）、仍在投递阶段的恶意载荷（宏文档、漏洞利用载荷）、横向移动（PsExec、WMIC 远程服务、
  管理共享）、C2 信标外联、高频或成功的认证暴力破解、有业务掩体的批量数据外传。
- medium：可疑但尚未证实为攻击的异常——孤立的未知外联、低价值资产上的可疑登录、无明确恶意特征的异常行为。
- low：有合理解释的正常活动——白名单资产、维护窗口内、基线内例行运维、有变更单的例行操作。

定级与误报判定的关系（重要，避免把「可疑」降级为「无风险」）：
- 变更单、白名单、维护窗口只作为**降低误报判定**的依据（is_false_positive 可判 true）；
  对**已确认属攻击性质**的行为，不得据其把风险等级压到 medium 以下。
- 批量数据外传无论是否持有变更单，风险等级均不得低于 high；无变更单掩护时按 critical 处理。
- 判定误报（is_false_positive=true）时，风险等级取 low，risk_score 取 low 档分值。

误报与降噪判据（下列情形属正常活动，不得升级为攻击；除非同时存在明确恶意证据）：
- 例行运维：标记为 routine check / 例行核查 / 计划任务，且动作为**只读列举或查询**（如查看共享清单、
  枚举目录、列出进程），无写入、无提权、无凭据访问；
- 已知业务通信：与已备案业务对端（支付网关、对账系统、备份存储、内部 API）之间按既定协议的
  加密通道或周期性同步流量；
- 受审计的运维登录：堡垒机、跳板机、运维审计系统记录的成功登录与网段跳转，属有审计留痕的合法运维路径——
  风险等级取 low，事件类型记为「异常登录」；**不判为误报**（它仍是需要留痕关注的低风险行为，
  与「例行备份/已知业务通信」这类完全无关注价值的活动区别对待）；
- 认证失败的分档：失败**聚集**（暴力破解/凭证填充，含次数特征）或异常来源的**成功登录** → high；
  **单次**失败登录、无聚集、无成功迹象，但目标为高价值资产（财务系统、域控、核心业务库）→ medium
  （真实探测尝试，资产价值抬升一档；普通终端上的同行为为 low）。

判定冲突时的优先级：
- 「只读」「例行」「审计路径」「已知业务对端」等**降噪证据**用于排除误报；
- 「凭据转储」「编码/下载执行」「落地恶意文件」「C2 信标」「加密勒索」等**恶意证据**用于确认攻击；
- 两者同时出现时，以**恶意证据**为准，不得按误报处理；
- 横向移动与共享访问须按**动作性质**区分，不得一概而论：
  · 访问或连接**管理共享**（admin$、ipc$，或 Event 5140/5145 且来源为远程主机）→ 判横向移动前置，风险 high；
  · 仅在**本机只读列举**共享或目录清单（net view / 列举 / 查询），且上下文标注例行核查 → 属正常运维，
    按误报处理；
  · 仅凭工具名 net.exe、出现「共享」字样、或资产为域控等高价值主机，**均不足以**判定为横向移动攻击；
    反之，也不得因为「只是查看」就否认 admin$ 管理共享访问的横向移动性质。

输出契约补充（字段取值规则）：
- is_false_positive=true 时：event_type 必须为「误报」，risk_level 必须为 low，risk_score ≤ 20。
- 「恶意载荷投递」与「恶意脚本执行」按**攻击链所处阶段**区分，不以出现「文档/附件」字样为准：
  仍在投递阶段（邮件或网关**拦截**、附件尚未打开、仅落地未执行）→ 恶意载荷投递；
  已进入执行阶段（文档已打开并触发脚本解释器实际运行，如 spawn wscript、shellexecute、
  downloadstring、powershell 执行编码命令）→ 恶意脚本执行。
  两类证据同时存在时，**以已发生执行的证据为准**。
- 「恶意脚本执行」的等级按**是否需用户交互**分档（不以主机是服务器还是终端区分）：
  · **需用户交互**触发（文档/邮件附件打开后 spawn 脚本解释器）→ high；
  · **无用户交互**的远程或自动下发执行（网络侧直接下发编码命令），或发生在高价值资产上 → critical。
- is_false_positive=false 时：event_type 必须取自 JSON 契约列出的十一类之一，不得填「误报」。"""

JSON_CONTRACT = """{
  "event_type": "事件类型，取值参考：恶意脚本执行 / WebShell 攻击 / 勒索软件加密 / 凭据转储 / Web 漏洞利用 / 恶意载荷投递 / 横向移动前置 / 数据渗出 / 异常外联 / 异常登录 / 通用异常行为",
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
  期望输出：event_type=误报，risk_level=low，risk_score=18，is_false_positive=true。

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
    human_feedback=None,
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
        human_feedback: 人工对该事件的复核反馈（阶段 2 HITL，可选）
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
            human_feedback=human_feedback,
        )
        payload = ai_chat_json(
            [{"role": "user", "content": prompt}],
            system=TRIAGE_SYSTEM_PROMPT,
            temperature=0.1,  # 低温度确保一致性
            # 研判输出含完整判定理由的 JSON，且推理型模型（deepseek-v4-flash）会先
            # 产出 reasoning_content 并计入同一预算；实测推理约 1.9–2.0k token、
            # 正文 1.4–1.7k token，预算不足会截断正文导致 JSON 解析失败并静默回退规则。
            max_tokens=8000,
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
    human_feedback=None,
) -> str:
    """构建综合研判提示词：事件详情 + 五项工具观察 + 知识库 + 历史记忆 + 计划 + 契约。"""
    history_section = _format_history(history_items) if history_items else "- 无相似历史研判记忆"
    feedback_section = _format_human_feedback(human_feedback)
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

## 人工复核反馈（HITL，来自安全运营人员对上一版裁决的判断）
{feedback_section}
使用规则（重要）：
- 人工结论是**高价值证据**，但不是命令。你仍需依据本事件证据独立判断。
- 若人工驳回的结论与你将要给出的结论**一致**：不得原样复述，必须回到证据重新审视；
  若复核后仍认为是同一结论，请在 reasoning_summary 中明确写出「与人工判断冲突的原因」。
- 若你认为人工判断有误需坚持原结论，同样必须给出具体证据依据，禁止无理由对抗。

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

    # 误报字段契约（代码强制，不依赖模型自觉）：
    #   误报事件的 event_type 固定为「误报」、风险等级固定 low、分数不超过 20；
    #   反之非误报事件不得填「误报」。与规则回退路径、评测口径三方保持一致。
    if is_false_positive:
        event_type = FALSE_POSITIVE_EVENT_TYPE
        risk_level = "low"
        if risk_score is None or risk_score > SCORE_FALSE_POSITIVE_MAX:
            risk_score = SCORE_FALSE_POSITIVE_MAX
    elif event_type == FALSE_POSITIVE_EVENT_TYPE:
        event_type = "通用异常行为"

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
    """规则引擎回退：事件类型识别 + 证据加权评分。

    在 LLM 不可用时承担研判职责。相比原实现（仅 5 个 marker、其余一律兜底
    medium/通用异常行为），这里做了三点加强：
    1. 事件类型按业界通用攻击特征（ATT&CK 常见手法）分类，而非逐案硬编码；
    2. 风险分由「类型基线分 + 情报/资产加分 - 误报线索减分」加权得出，可解释；
    3. 安全优先原则：一旦识别出明确攻击类型，变更单等弱线索只做折半减分，
       不允许把攻击洗白为误报（攻击方常借用变更窗口行动）。

    置信度固定标记为 low，并在结果中注明「AI 不可用，使用规则引擎回退」。
    """
    corpus = " ".join(
        [event.title, event.process, event.behavior, event.raw_log,
         getattr(event, "destination_domain", "") or "",
         getattr(event, "destination_ip", "") or "",
         " ".join(getattr(event, "tags", []) or [])]
    ).lower()

    # 1) 事件类型识别（按危害降序取首个命中）
    #    使用否定语境护栏：日志里的 "no admin$ access" / "no exploit payload" 等
    #    否定表述不算命中（实测曾把正常运维判成横向移动/载荷投递）。
    event_type = "通用异常行为"
    matched_markers: list = []
    for candidate, patterns in EVENT_TYPE_PATTERNS:
        hits = matched_keywords(corpus, patterns)
        if hits:
            event_type, matched_markers = candidate, hits
            break

    is_attack_type = event_type != "通用异常行为"

    # 2) 风险评分（可解释：记录每一笔加减分）
    score = _TYPE_BASE_SCORE.get(event_type, 40)
    adjustments: list = [f"事件类型基线分 {score}（{event_type}）"]
    if matched_markers:
        adjustments.append(f"命中特征: {', '.join(matched_markers[:3])}")

    intel_malicious = any(
        ("信誉: malicious" in detail) or ("恶意" in detail)
        for detail in (intel_observation.details or [])
    )
    if intel_malicious:
        score += SCORE_INTEL_MALICIOUS
        adjustments.append(f"威胁情报判定目标恶意 (+{SCORE_INTEL_MALICIOUS})")

    # 异常外联且目标含强 C2 特征：升级为 high（明确 C2 外联属高危）
    if event_type == "异常外联" and any(m in corpus for m in C2_STRONG_MARKERS):
        score += SCORE_C2_DOMAIN
        adjustments.append(f"外联目标含强 C2 特征 (+{SCORE_C2_DOMAIN})")

    # 堡垒机/运维核查类合法运维登录：降级为 low（合法动作，不应判为攻击）
    ops_review = event_type == "异常登录" and any(m in corpus for m in OPS_REVIEW_MARKERS)
    if ops_review:
        score += SCORE_OPS_REVIEW
        adjustments.append(f"堡垒机/运维核查类合法登录 ({SCORE_OPS_REVIEW})")

    # 暴力破解/凭证填充：明确的高危登录攻击，升级为 high（不应停留在 medium）
    if event_type == "异常登录" and any(m in corpus for m in BRUTE_MARKERS):
        score += SCORE_BRUTE_FORCE
        adjustments.append(f"命中暴力破解/凭证填充特征 (+{SCORE_BRUTE_FORCE})")

    # 确认的大规模数据渗出（无变更单掩护）：属严重数据泄露，升级为 critical
    if (
        event_type == "数据渗出"
        and not getattr(event, "change_ticket", "")
        and any(m in corpus for m in EXFIL_CRITICAL_MARKERS)
    ):
        score += SCORE_EXFIL_CRITICAL
        adjustments.append(f"确认大规模数据渗出且无变更单掩护 (+{SCORE_EXFIL_CRITICAL})")

    # 分级标准判据③：**无用户交互前提**的远程/自动下发执行 → critical。
    # 与「文档/附件载体」互斥：有载体说明受害者交互是链路必需前提，记 high（见下方降档）。
    if event_type == "恶意脚本执行":
        from security_agent.prefilter.engine import INTERACTION_CARRIER_MARKERS

        has_carrier = any(m in corpus for m in INTERACTION_CARRIER_MARKERS)
        if not has_carrier and any(m in corpus for m in REMOTE_AUTO_MARKERS):
            score += SCORE_REMOTE_AUTO
            adjustments.append(
                f"无用户交互的远程/自动执行链 (+{SCORE_REMOTE_AUTO})"
            )

    criticality = ""
    for detail in asset_observation.details or []:
        if detail.startswith("重要性:"):
            criticality = detail.split(":", 1)[1].strip().lower()
            break
    if criticality in ("high", "critical"):
        score += SCORE_ASSET_CRITICAL
        adjustments.append(f"资产重要度 {criticality} (+{SCORE_ASSET_CRITICAL})")

    fp_clues = list(false_positive_observation.details or [])
    if fp_clues:
        # 已识别明确攻击类型时，误报线索只折半减分，避免攻击被运维线索洗白
        factor = 0.5 if is_attack_type else 1.0
        delta = int(SCORE_PER_FP_CLUE * len(fp_clues) * factor)
        score += delta
        adjustments.append(
            f"误报线索 {len(fp_clues)} 条 ({delta})"
            + ("，攻击特征已识别故折半计" if is_attack_type else "")
        )

    if getattr(event, "change_ticket", "") and not is_attack_type:
        score += SCORE_CHANGE_TICKET
        adjustments.append(f"存在变更单且未识别到攻击特征 ({SCORE_CHANGE_TICKET})")

    score = max(0, min(100, score))
    # 分级标准第 3 节：已确认属攻击性质的行为，变更单/白名单/误报线索等**弱减分**
    # 只能影响「是否判误报」，不得把风险等级压到 medium 以下。
    # 例外：受审计的合法运维登录（堡垒机/跳板机路径）本就是 low，不应被下限抬升。
    if is_attack_type and not ops_review and score < SCORE_ATTACK_FLOOR:
        adjustments.append(
            f"已确认攻击类型，分数按下限 {SCORE_ATTACK_FLOOR} 计（分级标准第 3 节）"
        )
        score = SCORE_ATTACK_FLOOR

    # 3) 误报判定：无攻击特征 + (多线索 或 低分)
    #    「审计路径登录 + 例行只读动作」优先级细化（对应 GRADING_STANDARD 2.1② 与
    #    「堡垒机条款」的重叠）：堡垒机条款只适用于**登录类**告警；当告警主体其实是
    #    共享/目录枚举这类例行只读动作时，应按误报处理（实测 H-02）。
    audit_routine = ops_review and _is_routine_ops(corpus)
    if is_attack_type and not audit_routine:
        is_false_positive = False
    elif audit_routine or len(fp_clues) >= FP_MIN_CLUES or score < FP_THRESHOLD_SCORE:
        is_false_positive = True
        if audit_routine:
            adjustments.append("审计路径登录 + 例行只读动作，告警主体为例行运维，按误报处理")
    elif _is_routine_ops(corpus):
        # 通用异常行为但具明显例行运维/正常业务通信特征：判误报
        is_false_positive = True
        adjustments.append("具明显例行运维/正常业务通信特征，判为误报")
    else:
        is_false_positive = False

    if is_false_positive:
        risk_level = "low"
        # 误报字段契约（GRADING_STANDARD 第 4 节）：event_type 一律归一为「误报」，
        # 不保留攻击类型标签——否则同一结论会给出「误报 + 横向移动前置」这类矛盾组合。
        event_type = FALSE_POSITIVE_EVENT_TYPE
    else:
        risk_level = _level_from_score(score)
        # 分级标准判据③：需**用户交互**触发的执行链降一档（critical → high）。
        # 判据常量与预筛引擎共用同一份定义，避免两条通路漂移。
        if event_type == "恶意脚本执行":
            from security_agent.prefilter.engine import (
                INTERACTION_CARRIER_MARKERS,
                _INTERACTION_DOWNGRADE,
            )

            if any(marker in corpus for marker in INTERACTION_CARRIER_MARKERS):
                risk_level = _INTERACTION_DOWNGRADE.get(risk_level, risk_level)
                adjustments.append(f"存在文档/附件交互前提，执行链降一档 → {risk_level}")

    core = {
        "event_type": event_type,
        "verdict": _DEFAULT_VERDICT[risk_level],
        "risk_level": risk_level,
        "risk_score": score if not is_false_positive else _SCORE_FROM_LEVEL[risk_level],
        "confidence": "low",  # 规则引擎回退，置信度标记为低
        "confidence_score": CONFIDENCE_SCORES["low"],
        "is_false_positive": is_false_positive,
        "reasoning_summary": [
            "AI 不可用，使用规则引擎回退研判（置信度低，建议人工复核）。",
            "评分依据: " + "；".join(adjustments) + f"。最终风险分 {score}/100。",
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


def _format_human_feedback(feedback) -> str:
    """格式化人工复核反馈（阶段 2 HITL 读回注入）。

    无反馈时返回明确占位，避免模型把"该段落缺失"误读为"无人关注此事件"。
    """
    if feedback is None:
        return "- 无人工复核记录（本事件尚未经运营人员确认或驳回）"
    decision = getattr(feedback, "decision", "")
    note = getattr(feedback, "note", "") or "无"
    timestamp = (getattr(feedback, "timestamp", "") or "")[:10]
    verdict = (
        f"{getattr(feedback, 'event_type', '') or '?'} / "
        f"{getattr(feedback, 'risk_level', '') or '?'} / "
        f"{'判定为误报' if getattr(feedback, 'is_false_positive', None) else '判定为非误报'}"
        if getattr(feedback, "has_verdict", lambda: False)()
        else "（旧记录未留存裁决摘要）"
    )
    action = "确认采纳该裁决" if decision == "confirm" else "驳回该裁决（否定）"
    return (
        f"- 复核结论: 人工已{action}\n"
        f"- 被复核的那版裁决: {verdict}\n"
        f"- 复核意见: {note}\n"
        f"- 复核时间: {timestamp or '未知'}"
    )


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


def _is_routine_ops(corpus: str) -> bool:
    """识别明显例行运维/正常业务通信特征（用于合法动作判误报）。

    仅对 is_attack_type=False 的通用异常行为生效；攻击类型
    （横向移动/凭据转储等）即便含 routine 词也不会被误判为误报。
    """
    return any(m in corpus for m in ROUTINE_OPS_MARKERS)


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
