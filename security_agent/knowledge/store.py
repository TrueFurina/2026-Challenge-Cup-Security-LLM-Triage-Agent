import json
import re
from pathlib import Path

from security_agent.agent.models import (
    AssetRecord,
    HistoricalAlertRecord,
    IntelRecord,
    KnowledgeItem,
    LogRecord,
    SecurityEvent,
    ToolObservation,
)


class KnowledgeHub:
    def __init__(
        self,
        knowledge_items: list[KnowledgeItem],
        assets: list[AssetRecord],
        intel_records: list[IntelRecord],
        logs: list[LogRecord],
        history_alerts: list[HistoricalAlertRecord],
    ):
        self.knowledge_items = knowledge_items
        self.assets = {item.host: item for item in assets}
        self.intel_records = {item.indicator: item for item in intel_records}
        self.logs = logs
        self.history_alerts = history_alerts

    @classmethod
    def default(cls) -> "KnowledgeHub":
        root = Path(__file__).resolve().parent.parent / "data"
        knowledge_rows = json.loads((root / "knowledge.json").read_text(encoding="utf-8"))
        asset_rows = json.loads((root / "assets.json").read_text(encoding="utf-8"))
        intel_rows = json.loads((root / "intel.json").read_text(encoding="utf-8"))
        log_rows = json.loads((root / "logs.json").read_text(encoding="utf-8"))
        history_rows = json.loads((root / "history_alerts.json").read_text(encoding="utf-8"))
        return cls(
            knowledge_items=[KnowledgeItem(**row) for row in knowledge_rows],
            assets=[AssetRecord(**row) for row in asset_rows],
            intel_records=[IntelRecord(**row) for row in intel_rows],
            logs=[LogRecord(**row) for row in log_rows],
            history_alerts=[HistoricalAlertRecord(**row) for row in history_rows],
        )

    def retrieve_knowledge(
        self, event: SecurityEvent, top_k: int = 3
    ) -> tuple[list[KnowledgeItem], ToolObservation]:
        corpus = " ".join(
            [
                event.title,
                event.process,
                event.behavior,
                event.raw_log,
                event.user,
                event.destination_domain,
                event.destination_ip,
                " ".join(event.tags),
            ]
        ).lower()
        tokens = self._tokenize(corpus)
        ranked: list[tuple[int, KnowledgeItem, list[str]]] = []

        for item in self.knowledge_items:
            score, reasons = self._score_item(item, corpus, tokens)
            if score > 0:
                ranked.append((score, item, reasons))

        ranked.sort(
            key=lambda row: (
                -row[0],
                row[1].category,
                row[1].title,
            )
        )

        if not ranked:
            fallback = KnowledgeItem(
                title="通用研判建议",
                content="未命中特定规则时，优先核对资产重要性、日志上下文、账号行为和变更依据。",
                tags=["generic"],
                category="baseline",
            )
            observation = ToolObservation(
                tool_name="knowledge_retriever",
                summary="RAG 检索未命中特定知识，已回退到通用研判建议",
                details=[f"返回知识: {fallback.title}"],
            )
            return [fallback], observation

        top_items = ranked[:top_k]
        details = [
            self._format_detail(item, score, reasons)
            for score, item, reasons in top_items
        ]
        observation = ToolObservation(
            tool_name="knowledge_retriever",
            summary=f"RAG 风格检索返回 {len(top_items)} 条高相关知识（含 ATT&CK/CVE 依据）",
            details=details,
        )
        return [item for _, item, _ in top_items], observation

    @staticmethod
    def _format_detail(item, score: int, reasons: list[str]) -> str:
        """格式化知识命中详情：标题/分类/分数/ATT&CK/CVE/命中原因。"""
        attck = "/".join(item.attck_ids) if getattr(item, "attck_ids", []) else "无"
        cve = "/".join(item.cve_ids) if getattr(item, "cve_ids", []) else "无"
        return (
            f"{item.title} | 分类: {item.category} | 分数: {score} | "
            f"ATT&CK: {attck} | CVE: {cve} | 命中: {', '.join(reasons[:4])}"
        )

    def search_knowledge(self, event: SecurityEvent) -> list[KnowledgeItem]:
        items, _ = self.retrieve_knowledge(event)
        return items

    def get_asset(self, host: str) -> AssetRecord | None:
        return self.assets.get(host)

    def find_logs(self, host: str, user: str) -> list[LogRecord]:
        return [item for item in self.logs if item.host == host or item.user == user]

    def get_intel(self, *indicators: str) -> list[IntelRecord]:
        return [
            self.intel_records[indicator]
            for indicator in indicators
            if indicator and indicator in self.intel_records
        ]

    def find_history_alerts(self, host: str, user: str) -> list[HistoricalAlertRecord]:
        return [item for item in self.history_alerts if item.host == host or item.user == user]

    def _score_item(
        self, item: KnowledgeItem, corpus: str, tokens: set[str]
    ) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        item_text = f"{item.title} {item.content}".lower()

        for tag in item.tags:
            tag_lower = tag.lower()
            if tag_lower in corpus:
                score += 4
                reasons.append(f"tag:{tag}")

        item_tokens = self._tokenize(item_text)
        overlap = sorted(tokens & item_tokens)
        if overlap:
            score += min(len(overlap), 4)
            reasons.extend([f"token:{token}" for token in overlap[:4]])

        if item.category in {"attack", "response"} and any(
            marker in corpus for marker in ("powershell", "credential", "exploit", "webshell", "beacon")
        ):
            score += 1
            reasons.append(f"category:{item.category}")

        # 阶段 4：ATT&CK / CVE 依据加分（事件文本显式提及技术/漏洞编号时强匹配）
        for attck_id in getattr(item, "attck_ids", []) or []:
            if attck_id.lower() in corpus:
                score += 3
                reasons.append(f"attck:{attck_id}")
        for cve_id in getattr(item, "cve_ids", []) or []:
            if cve_id.lower() in corpus:
                score += 3
                reasons.append(f"cve:{cve_id}")

        return score, reasons

    def _tokenize(self, text: str) -> set[str]:
        return {
            token
            for token in re.split(r"[^a-z0-9_\-.]+", text.lower())
            if len(token) >= 3
        }
