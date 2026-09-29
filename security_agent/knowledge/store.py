import json
import re
from pathlib import Path

from security_agent.agent.models import (
    AssetRecord,
    HistoricalAlertRecord,
    HistoryAlertMatch,
    IntelRecord,
    KnowledgeItem,
    LogRecord,
    SecurityEvent,
    ToolObservation,
)

# 通用/角色账号词元：这类账号名**不具备身份唯一性**——`www-data` 是 Debian 的
# Web 服务账号、`svc_*` 是职能账号，全网各主机普遍重名。因此「账号同名」对它们
# 不构成关联，跨主机召回纯属噪声，必须排除。
#
# 实测依据：EVENT-006 / EVENT-022 / EVENT-033 三例的 user 均为 `www-data`，
# 经「账号同名」各召回一条异主机记录 HIST-008（DMZ-WEB-003，疑似 C2 信标 / high）；
# 而工具输出的详情行不含主机名，模型无从分辨该记录来自别的主机。
#
# 判据取「按 . _ - 分词后的任一词元命中」（非仅首段）：`svc.db`、`backup.svc`、
# `mail_daemon` 均判为角色账号；而 `ops.admin`、`finance.zhang`、`hr.li` 等
# 人类账号含人名/工号词元，不含这些角色词元，仍按个人账号处理（弱关联保留）。
_GENERIC_ACCOUNT_ROLE_TOKENS = {
    "svc", "service", "app", "web", "www", "db", "sql", "backup", "bak",
    "mail", "daemon", "cron", "monitor", "system", "local", "network",
    "root", "nobody", "guest", "administrator",
    # Windows 内置服务账号的**无空格**写法（`NT AUTHORITY\Network Service` 拆词后
    # 已由 service 覆盖，但 `DWM-1\LocalService` 拆出的是连写词元，需单独列出）
    "localservice", "networkservice",
}

_ACCOUNT_TOKEN_SPLIT = re.compile(r"[._\-\\/\s]+")


def is_generic_account(user: str) -> bool:
    """账号是否为通用/角色账号（跨主机同名不构成关联）。"""
    if not user:
        return False
    tokens = {tok for tok in _ACCOUNT_TOKEN_SPLIT.split(user.strip().lower()) if tok}
    return bool(tokens & _GENERIC_ACCOUNT_ROLE_TOKENS)


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

    def find_logs(self, host: str, user: str, event_id: str = "") -> list[LogRecord]:
        """检索关联日志，**事件作用域严格隔离**。

        规则（按数据集是否已标注判定，一旦标注即全局生效）：
        - 数据集**存在 event_id 标注** → 只返回归属该事件的日志；该事件无日志即返回空，
          **不得**回落主机/账号匹配。回落会把同主机其他事件的攻击证据灌进来
          （实测：EVENT-013 曾因此拿到 EVENT-001 的 WinRM / Invoke-Expression 日志，
          导致真 LLM 依「正确证据」判出错误结论——属评测装置缺陷）。
        - 数据集**完全无标注**（旧格式） → 回落主机/账号匹配，保持向后兼容。

        「有标注即严格」而非「作用域为空才回落」，是因为后者等价于没修：
        无自有日志的事件恰好会掉进回落分支，污染依旧。
        """
        annotated = any(item.event_id for item in self.logs)
        if annotated:
            return [item for item in self.logs if event_id and item.event_id == event_id]
        if event_id:
            scoped = [item for item in self.logs if item.event_id == event_id]
            if scoped:
                return scoped
        return [item for item in self.logs if item.host == host or item.user == user]

    def get_intel(self, *indicators: str) -> list[IntelRecord]:
        return [
            self.intel_records[indicator]
            for indicator in indicators
            if indicator and indicator in self.intel_records
        ]

    def find_history_alerts(self, host: str, user: str) -> list[HistoryAlertMatch]:
        """检索历史告警，返回**带关联强度**的匹配结果。

        与 `find_logs` 的事件作用域隔离不同：历史告警本身就是「这台主机 / 这个账号
        以前有没有类似告警」的**弱关联线索**，做严格隔离会让该能力失去意义。
        故保留召回，但按证据力分档并交由上层显式标注来源：

        - **same_host**：同主机历史行为，强关联（该主机的行为画像）。
        - **same_account**：仅账号同名，弱关联；**通用/角色账号不参与**
          （见 `is_generic_account`，避免 www-data 之类同名账号把异主机
          「疑似 C2 信标 high」当成该主机的历史）。

        结果按「强关联优先 → 时间倒序」排序，保证上层 `[:n]` 截断优先保留强证据。
        """
        generic = is_generic_account(user)
        matches: list[HistoryAlertMatch] = []
        for item in self.history_alerts:
            if item.host == host:
                matches.append(HistoryAlertMatch(item, "same_host"))
            elif user and item.user == user and not generic:
                matches.append(HistoryAlertMatch(item, "same_account"))
        matches.sort(key=lambda m: m.record.timestamp, reverse=True)  # 近者优先
        matches.sort(key=lambda m: m.relation != "same_host")  # 稳定排序：强关联置顶
        return matches

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
