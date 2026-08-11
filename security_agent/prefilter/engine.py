"""确定性预筛器引擎（阶段 1 核心交付）。

目标：把"LLM 一律全量研判"改为"规则先筛、不确定才给 LLM"，
显著提升速度、降低成本、提高准确率（对标 SOC Triage Agent 的确定性快速通道）。

输出三态：
- AUTO_CLOSE    ：高置信误报，直接关闭，跳过 LLM
- AUTO_ESCALATE ：高置信攻击特征，直接定级，跳过 LLM
- NEED_LLM      ：证据不足，交给 LLM 深度研判

设计原则：
1. 攻击规则优先于误报规则 —— 安全优先，宁可升级也不误关真实攻击
2. 全部规则可配置（data/prefilter_rules.json），支持用户编辑
3. fail-open —— 任何异常安全回退 NEED_LLM，绝不阻断研判链路
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

AUTO_CLOSE = "AUTO_CLOSE"
AUTO_ESCALATE = "AUTO_ESCALATE"
NEED_LLM = "NEED_LLM"

# 内置默认规则：配置文件缺失/损坏时的兜底（与 data/prefilter_rules.json 保持一致）
BUILTIN_RULES = {
    "version": 1,
    "description": "确定性预筛内置默认规则（兜底）",
    "attack_rules": [
        {
            "id": "ATK-PS-ENCODED",
            "description": "PowerShell 编码命令下载执行",
            "keywords": ["encodedcommand", "downloadstring", "invoke-expression"],
            "risk_level": "critical",
            "event_type": "恶意脚本执行",
        },
        {
            "id": "ATK-WEBSHELL",
            "description": "WebShell 上传/访问",
            "keywords": ["shell.jsp", "webshell", "cmd=whoami", "eval("],
            "risk_level": "critical",
            "event_type": "WebShell 攻击",
        },
        {
            "id": "ATK-RANSOM",
            "description": "勒索加密活动",
            "keywords": [".encrypted", "encrypt", "ransomware"],
            "risk_level": "critical",
            "event_type": "勒索软件加密",
        },
        {
            "id": "ATK-MACRO",
            "description": "恶意宏/载荷投递",
            "keywords": ["macro", "docm", "exploit payload"],
            "risk_level": "high",
            "event_type": "恶意载荷投递",
        },
        {
            "id": "ATK-CRED-DUMP",
            "description": "凭据转储/枚举",
            "keywords": ["enumeratecredentials", "mimikatz", "lsass", "minidump", "cred.dll"],
            "risk_level": "high",
            "event_type": "凭据转储",
        },
        {
            "id": "ATK-LATERAL",
            "description": "横向移动/管理共享访问",
            "keywords": ["admin$", "share=admin", "net.exe"],
            "risk_level": "high",
            "event_type": "横向移动前置",
        },
        {
            "id": "ATK-C2-INTEL",
            "description": "已知恶意情报命中（C2/信标）",
            "type": "intel_malicious",
            "risk_level": "high",
            "event_type": "已知 C2 情报命中",
        },
    ],
    "false_positive_rules": [
        {
            "id": "FP-WHITELIST",
            "description": "命中白名单资产特征",
            "keywords": ["whitelist", "白名单"],
        },
        {
            "id": "FP-MAINTENANCE",
            "description": "维护窗口/例行任务特征",
            "type": "maintenance_window",
            "keywords": ["maintenance", "例行任务", "例行"],
        },
        {
            "id": "FP-CHANGE-TICKET",
            "description": "存在变更单关联",
            "type": "change_ticket",
        },
        {
            "id": "FP-BASELINE",
            "description": "事件进程命中基线进程且行为含例行特征",
            "type": "baseline_process",
            "routine_keywords": ["例行", "maintenance", "backup", "备份", "同步", "sync", "scan", "扫描", "routine", "批量"],
        },
    ],
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
        }


class PreFilterEngine:
    """确定性预筛引擎：毫秒级规则判定，输出三态决策。"""

    def __init__(self, rules: Optional[dict] = None):
        loaded = rules or self._load_rules()
        self.rules = loaded
        self.attack_rules = loaded.get("attack_rules", [])
        self.false_positive_rules = loaded.get("false_positive_rules", [])

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
            corpus = self._build_corpus(event, observations)

            # 1) 攻击规则优先（安全优先：宁可升级，不可误关真实攻击）
            for rule in self.attack_rules:
                if self._rule_matches(rule, event, corpus, observations):
                    return PreFilterResult(
                        decision=AUTO_ESCALATE,
                        matched_rules=[rule.get("id", "ATK-UNKNOWN")],
                        risk_level=rule.get("risk_level", "high"),
                        event_type=rule.get("event_type", "通用异常行为"),
                        is_false_positive=False,
                        confidence="high",
                        reason=rule.get("description", "命中高置信攻击特征"),
                        llm_skipped=True,
                    )

            # 2) 高置信误报特征
            for rule in self.false_positive_rules:
                if self._rule_matches(rule, event, corpus, observations):
                    return PreFilterResult(
                        decision=AUTO_CLOSE,
                        matched_rules=[rule.get("id", "FP-UNKNOWN")],
                        risk_level="low",
                        event_type="误报",
                        is_false_positive=True,
                        confidence="high",
                        reason=rule.get("description", "命中高置信误报特征"),
                        llm_skipped=True,
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
            )
        except Exception as exc:  # noqa: BLE001 - 预筛器永不阻断主链路
            logger.warning("预筛器异常，安全回退 LLM 深度研判: %s", exc)
            return PreFilterResult(
                decision=NEED_LLM,
                confidence="low",
                reason=f"预筛器异常回退: {exc}",
                llm_skipped=False,
            )

    def _build_corpus(self, event, observations: dict) -> str:
        """把事件字段 + 各工具观测拼接为小写语料，供关键词匹配。"""
        parts = [
            event.title,
            event.behavior,
            event.raw_log,
            event.process,
            event.change_ticket,
            event.destination_domain,
            event.destination_ip,
            " ".join(getattr(event, "tags", []) or []),
        ]
        for obs in observations.values():
            if obs is None:
                continue
            parts.append(obs.summary)
            parts.extend(obs.details)
        return " ".join(str(p) for p in parts if p).lower()

    def _rule_matches(self, rule: dict, event, corpus: str, observations: dict) -> bool:
        """单条规则判定：支持 keyword / intel_malicious / change_ticket / maintenance_window / baseline_process。"""
        rule_type = rule.get("type", "keyword")

        if rule_type == "intel_malicious":
            intel_obs = observations.get("intel")
            if intel_obs is None:
                return False
            return any(
                ("信誉: malicious" in detail) or ("恶意" in detail)
                for detail in intel_obs.details
            )

        if rule_type == "change_ticket":
            return bool(getattr(event, "change_ticket", ""))

        if rule_type == "maintenance_window":
            asset_obs = observations.get("asset")
            if asset_obs is not None and any(
                ("维护窗口" in detail) and ("无" not in detail)
                for detail in asset_obs.details
            ):
                return True
            return any(
                keyword in corpus
                for keyword in rule.get("keywords", [])
            )

        if rule_type == "baseline_process":
            # 基线进程只作为"例行任务"的辅助证据：进程在基线列表内 + 行为含例行特征
            process = str(getattr(event, "process", "")).lower()
            if not process or not self._process_in_baseline(process, observations.get("asset")):
                return False
            routine_keywords = [str(k).lower() for k in rule.get("routine_keywords", [])]
            return any(keyword in corpus for keyword in routine_keywords)

        # 默认 keyword 匹配
        keywords = [str(k).lower() for k in rule.get("keywords", [])]
        return any(keyword in corpus for keyword in keywords)

    @staticmethod
    def _process_in_baseline(process: str, asset_observation) -> bool:
        """从资产观测的"基线进程: xxx, yyy"行解析基线进程列表并匹配。"""
        if asset_observation is None:
            return False
        for detail in asset_observation.details:
            if not detail.startswith("基线进程:"):
                continue
            baseline = detail.split(":", 1)[1]
            if baseline.strip() in ("", "无"):
                return False
            names = [name.strip().lower() for name in baseline.split(",")]
            return process in names
        return False
