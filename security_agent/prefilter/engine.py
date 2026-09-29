"""确定性预筛器引擎（v2 证据加权版）。

目标：把"LLM 一律全量研判"改为"规则先筛、不确定才给 LLM"，
提升速度、降低成本，同时保证高置信判定真正可靠。

输出三态：
- AUTO_CLOSE    ：高置信误报，直接关闭，跳过 LLM
- AUTO_ESCALATE ：高置信攻击特征，直接定级，跳过 LLM
- NEED_LLM      ：证据不足，交给 LLM 深度研判

v2 修复的四类失效（对照 v1）：
1. 语料污染：v1 把工具观测 details（他机历史日志、基线进程、历史告警）
   全部拼入关键词匹配语料，导致"用 A 事件的残留日志给 B 事件定级"。
   v2 仅用**事件自身字段**做关键词匹配，工具观测仅用于结构化信号判定。
2. 基线悖论：v1 会把资产基线进程（正常白名单，如 lsass.exe）当作攻击证据，
   使域控上任何事件都被判"凭据转储"。v2 基线进程只作误报减分项。
3. 单词终裁：v1 任一关键词 substring 命中即定 critical
   （"encrypt" 命中 "TLS encrypt"、"net.exe" 命中例行运维）。
   v2 关键词按证据强度分级，弱词单命中不终裁，仅升级为 NEED_LLM。
4. 变更单单点误关：v1 只要存在 change_ticket 就判误报关闭，
   攻击方借变更单即可让系统失明。v2 误报关闭需多条件合取，
   且核心资产禁止自动关闭。

设计原则：
1. 攻击规则优先于误报规则 —— 安全优先，宁可升级也不误关真实攻击
2. 全部规则可配置（data/prefilter_rules.json），支持用户编辑
3. fail-open —— 任何异常安全回退 NEED_LLM，绝不阻断研判链路
4. 兼容 v1 规则文件格式（keywords 为数组时按内置强度表自动分级）
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from security_agent.textmatch import (
    NEGATION_TOKENS,
    _negation_scope,
    keyword_hit,
)

logger = logging.getLogger(__name__)

AUTO_CLOSE = "AUTO_CLOSE"
AUTO_ESCALATE = "AUTO_ESCALATE"
NEED_LLM = "NEED_LLM"

# ── 关键词强度：v1 规则文件（keywords 为数组）按此表自动分级 ──
# strong：高度特异，正常业务几乎不会误命中
# weak  ：泛化词，单独出现不足以定性，需佐证
STRONG_KEYWORDS = {
    "encodedcommand", "downloadstring", "invoke-expression", "iex(",
    # Unix/跨平台反弹 shell（ATT&CK T1059.004 / T1071）——此前缺失导致
    # `bash -i >& /dev/tcp/...` 这类明确入侵被兜底为「通用异常行为」（实测 H-05）
    "/dev/tcp/", "reverse shell", "反弹 shell", "bash -i", "nc -e", "socat exec",
    "shell.jsp", "webshell", "cmd=whoami", "cmd.exe&c=",
    "ransomware", ".locked", "readme_decrypt", "wannacry",
    "mimikatz", "sekurlsa", "enumeratecredentials", "procdump -ma lsass",
    "psexec", "wmic /node", "invoke-smbexec",
    "exploit payload", "macro-download", "shellexecute",
    # 第二垂类「Web 漏洞利用研判」：利用类特征（与扫描探测类特征刻意区分，
    # 扫描本身不是攻击，需另有利用证据才升级）
    "sql injection", "union select", "sqli", "path traversal",
    "deserialization", "反序列化", "命令注入", "command injection",
    "winword", "docm", "ole_object",  # 办公文档载体特征（投递阶段；已执行脚本时由脚本执行规则胜出）
}
WEAK_KEYWORDS = {
    "encrypt", "macro", "net.exe", "net use", "eval(", "lsass",
    "export", "scan", "admin$", "beacon",
}

# ── 用户交互前提（分级标准判据③，见 docs/GRADING_STANDARD.md 第 1 节） ──
# 「无用户交互前提的远程/自动执行链」才构成 critical（说明攻击者已具备活跃控制能力）；
# 钓鱼文档/邮件附件**打开后**才 spawn 脚本解释器的执行链，攻击者尚未证明稳定控制能力，
# 按 high 处理，且与「投递 vs 执行」的阶段约定互相独立（阶段决定 event_type，交互决定等级）。
INTERACTION_CARRIER_MARKERS = (
    "winword", "outlook", "excel", "powerpnt", "ole_object",
    ".docm", "macro-download", "宏文档", "宏附件", "文档附件", "attachment",
)
_INTERACTION_DOWNGRADE = {"critical": "high"}

# 风险等级降级映射（证据强度不足时的保守下调）
_RISK_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


@dataclass
class RuleHit:
    """单条规则的命中详情（用于可解释性输出）。"""

    rule_id: str
    description: str
    weight: float
    score: float
    risk_level: str = "high"
    event_type: str = "通用异常行为"
    # 攻击链阶段：execution（已执行）/ delivery（仅投递）。
    # 依据 docs/GRADING_STANDARD.md 第 2.1 节——两类证据同时存在时以「已发生执行」为准，
    # 否则「文档已打开并 spawn 脚本解释器」会被投递规则按命中词数量压过（实测 H-12）。
    stage: str = "execution"
    strong: list = field(default_factory=list)
    medium: list = field(default_factory=list)
    weak: list = field(default_factory=list)

    @property
    def all_hits(self) -> list:
        return self.strong + self.medium + self.weak

    @property
    def evidence_ratio(self) -> float:
        """证据强度比（score/weight）：<0.5 表示仅弱词命中。"""
        return self.score / self.weight if self.weight else 0.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "weight": self.weight,
            "score": round(self.score, 2),
            "risk_level": self.risk_level,
            "event_type": self.event_type,
            "stage": self.stage,
            "strong": self.strong,
            "medium": self.medium,
            "weak": self.weak,
        }


@dataclass
class PreFilterResult:
    """预筛器输出结果。"""

    decision: str = NEED_LLM
    matched_rules: list = field(default_factory=list)
    risk_level: str = ""
    event_type: str = ""
    is_false_positive: bool = False
    confidence: str = "high"
    reason: str = ""
    llm_skipped: bool = False
    evidence: list = field(default_factory=list)  # v2：证据明细（可解释性）
    total_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "matched_rules": self.matched_rules,
            "risk_level": self.risk_level,
            "event_type": self.event_type,
            "is_false_positive": self.is_false_positive,
            "confidence": self.confidence,
            "reason": self.reason,
            "llm_skipped": self.llm_skipped,
            "evidence": self.evidence,
            "total_score": round(self.total_score, 2),
        }


class PreFilterEngine:
    """确定性预筛引擎：毫秒级规则判定，输出三态决策。"""

    def __init__(self, rules: Optional[dict] = None):
        loaded = rules or self._load_rules()
        self.rules = loaded
        self.attack_rules = loaded.get("attack_rules", [])
        self.false_positive_rules = loaded.get("false_positive_rules", [])
        thresholds = loaded.get("thresholds", {}) or {}
        self.escalate_threshold = float(thresholds.get("escalate_weight", 2.5))
        self.min_fp_conditions = int(thresholds.get("min_fp_conditions", 2))
        self.protected_criticality = {
            str(c).lower() for c in thresholds.get("protected_criticality", ["high", "critical"])
        }

    @classmethod
    def default(cls) -> "PreFilterEngine":
        return cls()

    def _load_rules(self) -> dict:
        path = Path(__file__).resolve().parent.parent / "data" / "prefilter_rules.json"
        try:
            if not path.exists():
                logger.warning("预筛规则文件不存在，使用内置默认规则: %s", path)
                return BUILTIN_RULES
            rules = json.loads(path.read_text(encoding="utf-8"))
            logger.info("已加载预筛规则: %s", path.name)
            return rules
        except Exception as exc:  # noqa: BLE001 - 配置损坏时兜底内置规则
            logger.warning("预筛规则加载失败，使用内置默认规则: %s", exc)
            return BUILTIN_RULES

    # ── 主入口 ────────────────────────────────────────────
    def prefilter(
        self,
        event,
        asset_observation=None,
        intel_observation=None,
        false_positive_observation=None,
        log_observation=None,
        history_observation=None,
    ) -> PreFilterResult:
        """执行确定性预筛（fail-open：任何异常回退 NEED_LLM）。"""
        try:
            observations = {
                "asset": asset_observation,
                "intel": intel_observation,
                "fp": false_positive_observation,
                "log": log_observation,
                "history": history_observation,
            }
            # v2 关键修复：仅事件自身字段参与关键词匹配
            event_corpus = self._build_event_corpus(event)

            # 1) 攻击规则评估（安全优先：先评估攻击，避免误关真实攻击）
            hits: list[RuleHit] = []
            for rule in self.attack_rules:
                hit = self._match_attack_rule(rule, event, event_corpus, observations)
                if hit is not None:
                    hits.append(hit)

            total_score = sum(h.score for h in hits)
            has_strong = any(h.strong for h in hits)
            multi_rule = len(hits) >= 2

            if hits:
                primary = self._select_primary(hits)
                # 强证据 = 命中 strong 关键词，或多条规则相互佐证
                strong_evidence = has_strong or multi_rule
                if total_score >= self.escalate_threshold and strong_evidence:
                    event_type = self._event_type_for_rule(primary)
                    risk_level = self._apply_interaction_downgrade(
                        self._risk_for_rule(primary), event_type, event_corpus
                    )
                    return PreFilterResult(
                        decision=AUTO_ESCALATE,
                        matched_rules=[h.rule_id for h in hits],
                        risk_level=risk_level,
                        event_type=event_type,
                        is_false_positive=False,
                        confidence="high" if has_strong else "medium",
                        reason=self._escalate_reason(hits, total_score, has_strong),
                        llm_skipped=True,
                        evidence=[h.to_dict() for h in hits],
                        total_score=total_score,
                    )
                # 证据不足：不终裁，交 LLM/人工复核
                return PreFilterResult(
                    decision=NEED_LLM,
                    matched_rules=[h.rule_id for h in hits],
                    risk_level="",
                    event_type="",
                    is_false_positive=False,
                    confidence="low",
                    reason=(
                        f"命中弱攻击线索（{', '.join(h.rule_id for h in hits)}，"
                        f"证据分 {total_score:.2f} < 阈值 {self.escalate_threshold}），"
                        f"证据不足以自动定级，转 LLM 深度研判"
                    ),
                    llm_skipped=False,
                    evidence=[h.to_dict() for h in hits],
                    total_score=total_score,
                )

            # 2) 无任何攻击证据时，才评估误报关闭
            fp_hit, fp_reason, fp_details = self._match_false_positive(
                event, event_corpus, observations
            )
            if fp_hit:
                return PreFilterResult(
                    decision=AUTO_CLOSE,
                    matched_rules=fp_details,
                    risk_level="low",
                    event_type="误报",
                    is_false_positive=True,
                    confidence="high" if len(fp_details) >= 3 else "medium",
                    reason=fp_reason,
                    llm_skipped=True,
                    evidence=[{"rule_id": rid, "description": fp_reason} for rid in fp_details],
                    total_score=0.0,
                )

            # 3) 证据不足 → 交给 LLM 深度研判
            return PreFilterResult(
                decision=NEED_LLM,
                risk_level="",
                event_type="",
                is_false_positive=False,
                confidence="low",
                reason="未命中任何高置信规则，进入 LLM 深度研判",
                llm_skipped=False,
                total_score=0.0,
            )
        except Exception as exc:  # noqa: BLE001 - 预筛器永不阻断主链路
            logger.warning("预筛器异常，安全回退 LLM 深度研判: %s", exc)
            return PreFilterResult(
                decision=NEED_LLM,
                confidence="low",
                reason=f"预筛器异常回退: {exc}",
                llm_skipped=False,
            )

    # ── 语料构建（v2：严格限定为事件自身字段）──────────────
    @staticmethod
    def _build_event_corpus(event) -> str:
        """仅拼接事件自身字段。

        v1 缺陷：把工具观测 details（他机历史日志、资产基线进程、历史告警）
        一并拼入，造成跨事件串台与基线悖论。v2 只保留事件本体描述。
        """
        parts = [
            getattr(event, "title", "") or "",
            getattr(event, "behavior", "") or "",
            getattr(event, "raw_log", "") or "",
            getattr(event, "process", "") or "",
            getattr(event, "change_ticket", "") or "",
            getattr(event, "destination_domain", "") or "",
            getattr(event, "destination_ip", "") or "",
            " ".join(getattr(event, "tags", []) or []),
        ]
        return " ".join(str(p) for p in parts if p).lower()

    # ── 关键词匹配 ────────────────────────────────────────
    @staticmethod
    def _normalize_keywords(rule: dict) -> dict:
        """兼容 v1（数组）与 v2（分级字典）两种规则格式。"""
        kw = rule.get("keywords")
        if isinstance(kw, dict):
            return {
                "strong": [str(k) for k in kw.get("strong", [])],
                "medium": [str(k) for k in kw.get("medium", [])],
                "weak": [str(k) for k in kw.get("weak", [])],
            }
        buckets = {"strong": [], "medium": [], "weak": []}
        for raw in kw or []:
            key = str(raw).lower()
            if key in STRONG_KEYWORDS:
                buckets["strong"].append(key)
            elif key in WEAK_KEYWORDS:
                buckets["weak"].append(key)
            else:
                buckets["medium"].append(key)
        return buckets

    @staticmethod
    def _contains(corpus: str, keyword: str) -> bool:
        """词边界匹配 + **否定语境护栏**。

        词边界：避免 'encrypt' 命中 'encrypted'、'net' 命中 'network'。
        边界仅加在**关键词首尾为字母数字**的一侧——否则代码式关键词永远匹配不上：
        ``iex(`` 后面必接字母（``IEX(New-Object``）、``.docm`` 前面必接文件名，
        若强行加边界会导致这两类特征形同虚设（实测 H-12 丢掉了 ``downloadstring`` 命中）。
        否定护栏：避免 'no admin$ access' 被当作管理共享访问
        （依据见 security_agent/textmatch.py）。

        含中文的关键词退化为子串匹配（中文无空格分词）。
        """
        key = keyword.lower()
        if re.search(r"[\u4e00-\u9fff]", key):
            return keyword_hit(corpus, key)

        lookbehind = r"(?<![a-z0-9_\-])" if key[0].isalnum() else ""
        lookahead = r"(?![a-z0-9])" if key[-1].isalnum() else ""
        pattern = lookbehind + re.escape(key) + lookahead
        for m in re.finditer(pattern, corpus):
            scope = _negation_scope(corpus, m.start())
            if not any(tok in scope for tok in NEGATION_TOKENS):
                return True
        return False

    def _match_attack_rule(self, rule: dict, event, corpus: str, observations: dict):
        """单条攻击规则匹配，返回 RuleHit 或 None。"""
        rule_type = rule.get("type", "keyword")
        weight = float(rule.get("weight", 2.5))

        # 结构化信号：威胁情报命中（不依赖关键词，避免语料污染）
        if rule_type == "intel_malicious":
            if not self._intel_malicious(observations):
                return None
            # 要求事件本身确实存在外联目标，否则情报与事件不匹配
            if rule.get("require_outbound", True):
                if not (getattr(event, "destination_ip", "") or getattr(event, "destination_domain", "")):
                    return None
            return RuleHit(
                rule_id=rule.get("id", "ATK-UNKNOWN"),
                description=rule.get("description", ""),
                weight=weight,
                score=weight,
                risk_level=rule.get("risk_level", "high"),
                event_type=rule.get("event_type", "通用异常行为"),
                # 情报命中属**上下文佐证**，不属攻击链阶段。标记为独立 stage，
                # 避免它在 _select_primary 中把真正体现行为的规则挤掉（实测 EVENT-010）。
                stage="intel",
                strong=["情报库判定目标为恶意"],
            )

        buckets = self._normalize_keywords(rule)
        strong = [k for k in buckets["strong"] if self._contains(corpus, k)]
        medium = [k for k in buckets["medium"] if self._contains(corpus, k)]
        weak = [k for k in buckets["weak"] if self._contains(corpus, k)]

        # 上下文关键词（如数据渗出需伴随敏感数据对象）
        ctx = [str(k).lower() for k in rule.get("context_keywords", [])]
        if ctx and not any(self._contains(corpus, k) for k in ctx):
            # 无敏感上下文时，弱化证据（只保留 strong）
            if not strong:
                medium, weak = [], []

        if not (strong or medium or weak):
            return None

        # 证据分：strong 满分；多个 medium 高置信；单个 medium 折半；仅 weak 极低
        if strong:
            score = weight
        elif len(medium) >= 2:
            score = weight * 0.8
        elif len(medium) == 1:
            score = weight * 0.5
        else:
            score = weight * 0.25

        return RuleHit(
            rule_id=rule.get("id", "ATK-UNKNOWN"),
            description=rule.get("description", ""),
            weight=weight,
            score=score,
            risk_level=rule.get("risk_level", "high"),
            event_type=rule.get("event_type", "通用异常行为"),
            stage=rule.get("stage", "execution"),
            strong=strong,
            medium=medium,
            weak=weak,
        )

    def _match_false_positive(self, event, corpus: str, observations: dict):
        """误报关闭判定：需多条件合取，且核心资产禁止自动关闭。

        返回 (是否关闭, 原因, 命中的规则ID列表)。
        """
        matched: list[str] = []
        reasons: list[str] = []
        weight_sum = 0.0
        only_weak = True

        for rule in self.false_positive_rules:
            rule_type = rule.get("type", "keyword")
            rule_id = rule.get("id", "FP-UNKNOWN")
            weight = float(rule.get("weight", 1.0))
            hit = False

            if rule_type == "change_ticket":
                hit = bool(getattr(event, "change_ticket", ""))
                if hit:
                    reasons.append(f"存在变更单 {event.change_ticket}")
            elif rule_type == "maintenance_window":
                hit = self._in_maintenance_window(observations) or any(
                    self._contains(corpus, k) for k in self._rule_keywords(rule)
                )
                if hit:
                    reasons.append("处于维护窗口或例行任务特征")
            elif rule_type == "baseline_process":
                hit = self._process_in_baseline(event, observations) and any(
                    self._contains(corpus, str(k).lower())
                    for k in rule.get("routine_keywords", [])
                )
                if hit:
                    reasons.append("进程属资产基线且行为为例行操作")
            else:  # keyword（白名单等）
                hit = any(self._contains(corpus, k) for k in self._rule_keywords(rule))
                if hit:
                    reasons.append(rule.get("description", "命中白名单特征"))

            if hit:
                matched.append(rule_id)
                weight_sum += weight
                if not rule.get("weak_alone", False):
                    only_weak = False

        if not matched:
            return False, "", []

        # 核心资产保护：高价值资产一律不自动关闭，交 LLM/人工复核
        criticality = self._asset_criticality(observations)
        if criticality in self.protected_criticality:
            return False, "", []

        # 多条件合取：至少 min_fp_conditions 条，且不能只有弱证据
        if len(matched) < self.min_fp_conditions or only_weak:
            return False, "", []

        return True, "；".join(reasons), matched

    # ── 结构化信号解析（不参与关键词匹配，杜绝污染）────────
    @staticmethod
    def _rule_keywords(rule: dict) -> list:
        buckets = PreFilterEngine._normalize_keywords(rule)
        return buckets["strong"] + buckets["medium"] + buckets["weak"]

    @staticmethod
    def _intel_malicious(observations: dict) -> bool:
        intel_obs = observations.get("intel")
        if intel_obs is None:
            return False
        return any(
            ("信誉: malicious" in detail) or ("恶意" in detail)
            for detail in intel_obs.details
        )

    @staticmethod
    def _asset_criticality(observations: dict) -> str:
        """从资产观测解析重要度（结构化解析，不做文本匹配）。"""
        asset_obs = observations.get("asset")
        if asset_obs is None:
            return ""
        for detail in asset_obs.details:
            if detail.startswith("重要性:"):
                return detail.split(":", 1)[1].strip().lower()
        return ""

    @staticmethod
    def _in_maintenance_window(observations: dict) -> bool:
        asset_obs = observations.get("asset")
        if asset_obs is None:
            return False
        return any(
            detail.startswith("维护窗口:") and "无" not in detail
            for detail in asset_obs.details
        )

    @staticmethod
    def _process_in_baseline(event, observations: dict) -> bool:
        """基线进程判定（仅用于误报减分，绝不作为攻击证据）。"""
        asset_obs = observations.get("asset")
        if asset_obs is None:
            return False
        process = str(getattr(event, "process", "")).lower()
        if not process:
            return False
        for detail in asset_obs.details:
            if not detail.startswith("基线进程:"):
                continue
            baseline = detail.split(":", 1)[1]
            if baseline.strip() in ("", "无"):
                return False
            names = [name.strip().lower() for name in baseline.split(",")]
            return process in names
        return False

    # ── 决策辅助 ──────────────────────────────────────────
    @staticmethod
    def _risk_for_rule(hit: RuleHit) -> str:
        """由命中规则推导风险等级；仅弱词命中时保守下调，避免弱证据定高级。"""
        if hit.evidence_ratio < 0.5:
            return _RISK_DOWNGRADE.get(hit.risk_level, hit.risk_level)
        return hit.risk_level

    @staticmethod
    def _select_primary(hits: list) -> "RuleHit":
        """选取用于定级/分类的主规则。

        依据 docs/GRADING_STANDARD.md 第 2.1 节：同一事件同时命中「执行阶段」与
        「投递阶段」规则时，**以已发生执行者为准**。若仅按证据分取最大，一条投递规则
        可能因为命中关键词更多而压过执行规则，把「文档已触发脚本执行」误记为
        「恶意载荷投递」（实测 H-12）。

        仅采纳 ``stage == "execution"`` 且命中强关键词的**关键词规则**；情报类命中
        （stage="intel"）属上下文佐证，不参与阶段竞争。
        """
        executed = [h for h in hits if h.stage == "execution" and h.strong]
        pool = executed or hits
        return max(pool, key=lambda h: (h.score, h.weight))

    @staticmethod
    def _event_type_for_rule(hit: RuleHit) -> str:
        return hit.event_type

    @staticmethod
    def _apply_interaction_downgrade(risk_level: str, event_type: str, corpus: str) -> str:
        """按分级标准判据③：**需用户交互**触发的执行链降一档（critical → high）。

        依据 docs/GRADING_STANDARD.md 第 1 节：不经用户交互的远程/自动下发执行说明
        攻击者已具备活跃控制能力 → critical；而钓鱼文档/邮件附件打开后才 spawn 脚本
        解释器，受害者交互是链路必需前提，故记 high。

        仅对「恶意脚本执行」生效——其他类型不因出现文档载体而改变（例如邮件网关
        拦截的附件仍应记为「恶意载荷投递」/high，不受此处影响）。
        """
        if event_type != "恶意脚本执行":
            return risk_level
        if any(marker in corpus for marker in INTERACTION_CARRIER_MARKERS):
            return _INTERACTION_DOWNGRADE.get(risk_level, risk_level)
        return risk_level

    @staticmethod
    def _escalate_reason(hits: list, total_score: float, has_strong: bool) -> str:
        detail = "；".join(
            f"{h.rule_id}[{'强' if h.strong else '中' if h.medium else '弱'}证据: {', '.join(h.all_hits[:3])}]"
            for h in hits
        )
        kind = "高特异攻击特征" if has_strong else "多规则交叉佐证"
        return f"{kind}命中，累计证据分 {total_score:.2f}（{detail}）"


# 内置默认规则：配置文件缺失/损坏时的兜底（与 data/prefilter_rules.json 保持一致）
BUILTIN_RULES = {
    "version": 2,
    "description": "确定性预筛内置默认规则（兜底）",
    "thresholds": {
        "escalate_weight": 2.5,
        "min_fp_conditions": 2,
        "protected_criticality": ["high", "critical"],
    },
    "attack_rules": [
        {
            "id": "ATK-PS-ENCODED",
            "description": "脚本解释器执行（编码命令下载执行 / 反弹 shell）",
            "keywords": ["encodedcommand", "downloadstring", "invoke-expression",
                         "/dev/tcp/", "reverse shell", "反弹 shell", "bash -i"],
            "weight": 3.5,
            "stage": "execution",
            "risk_level": "critical",
            "event_type": "恶意脚本执行",
        },
        {
            "id": "ATK-WEBSHELL",
            "description": "WebShell 上传/访问",
            "keywords": ["shell.jsp", "webshell", "cmd=whoami", "eval("],
            "weight": 3.5,
            "risk_level": "critical",
            "event_type": "WebShell 攻击",
        },
        {
            "id": "ATK-RANSOM",
            "description": "勒索加密活动",
            "keywords": [".encrypted", "encrypt", "ransomware"],
            "weight": 3.0,
            "risk_level": "critical",
            "event_type": "勒索软件加密",
        },
        {
            "id": "ATK-MACRO",
            "description": "恶意宏/载荷投递",
            "keywords": ["macro", "docm", "exploit payload"],
            "weight": 2.5,
            "stage": "delivery",
            "risk_level": "high",
            "event_type": "恶意载荷投递",
        },
        {
            "id": "ATK-OFFICE-MACRO",
            "description": "办公文档载荷投递（投递阶段；已实际执行脚本时由 stage=execution 规则胜出）",
            "keywords": ["winword", "docm", "ole_object", "macro-download", "宏文档", "宏附件"],
            "weight": 3.0,
            "stage": "delivery",
            "risk_level": "high",
            "event_type": "恶意载荷投递",
        },
        {
            "id": "ATK-WEB-EXPLOIT",
            "description": "Web 漏洞利用（注入/反序列化/目录穿越/文件上传等服务端利用）",
            "keywords": ["sql injection", "union select", "sqli", "path traversal",
                         "deserialization", "反序列化", "命令注入", "command injection"],
            "weight": 3.2,
            "stage": "execution",
            "risk_level": "high",
            "event_type": "Web 漏洞利用",
        },
        {
            "id": "ATK-CRED-DUMP",
            "description": "凭据转储/枚举",
            "keywords": ["enumeratecredentials", "mimikatz", "lsass", "minidump", "cred.dll"],
            "weight": 3.0,
            "risk_level": "critical",
            "event_type": "凭据转储",
        },
        {
            "id": "ATK-LATERAL",
            "description": "横向移动/管理共享访问",
            "keywords": ["admin$", "share=admin", "net.exe"],
            "weight": 2.5,
            "risk_level": "high",
            "event_type": "横向移动前置",
        },
        {
            "id": "ATK-C2-INTEL",
            "description": "已知恶意情报命中（C2/信标）",
            "type": "intel_malicious",
            "weight": 3.0,
            "risk_level": "high",
            "event_type": "已知 C2 情报命中",
        },
        {
            "id": "ATK-EXFIL",
            "description": "批量数据渗出",
            "keywords": ["批量导出", "导出全表", "upload to oss", "upload to s3", "bulk exfil"],
            "weight": 2.5,
            "risk_level": "high",
            "event_type": "数据渗出",
            "context_keywords": ["客户", "customer", "身份证", "手机号", "card"],
        },
    ],
    "false_positive_rules": [
        {"id": "FP-WHITELIST", "description": "命中白名单资产特征",
         "keywords": ["whitelist", "白名单"], "weight": 2.0},
        {"id": "FP-MAINTENANCE", "description": "维护窗口/例行任务特征",
         "type": "maintenance_window",
         "keywords": ["maintenance", "例行任务", "例行"], "weight": 1.5},
        {"id": "FP-CHANGE-TICKET", "description": "存在变更单关联（弱证据，不可单独成立）",
         "type": "change_ticket", "weight": 1.0, "weak_alone": True},
        {"id": "FP-BASELINE", "description": "事件进程命中基线进程且行为含例行特征",
         "type": "baseline_process", "weight": 1.5,
         "routine_keywords": ["例行", "maintenance", "backup", "备份", "同步", "sync",
                              "scan", "扫描", "routine", "批量"]},
    ],
}
