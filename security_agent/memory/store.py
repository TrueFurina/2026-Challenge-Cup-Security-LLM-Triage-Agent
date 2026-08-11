"""MemoryStore：研判历史持久化 + 相似记忆检索（阶段 6）。

设计：
1. 持久化：每次研判 append 一条 JSONL 到 data/triage_history.jsonl
2. 检索：同主机 +3 / 同进程 +2 / 行为 token 重叠 +1，取 top_k
3. 上限：只保留最近 MAX_RECORDS 条（6.3）
4. fail-open：文件缺失/损坏/写入失败均安全降级，不影响主链路
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class MemoryStore:
    MAX_RECORDS = 200  # 记忆上限（6.3）

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (
            Path(__file__).resolve().parent.parent / "data" / "triage_history.jsonl"
        )

    # ── 写入 ──────────────────────────────────────────────
    def append(self, record: dict) -> None:
        """追加一条研判历史（fail-open：写入失败不抛异常）。"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "event_id": record.get("event_id", ""),
                "host": record.get("host", ""),
                "process": record.get("process", ""),
                "behavior": record.get("behavior", ""),
                "event_type": record.get("event_type", ""),
                "risk_level": record.get("risk_level", ""),
                "confidence": record.get("confidence", ""),
                "is_false_positive": bool(record.get("is_false_positive", False)),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._trim()
        except Exception as exc:  # noqa: BLE001 - 记忆写入失败不影响主链路
            logger.warning("记忆写入失败（已忽略）: %s", exc)

    # ── 检索 ──────────────────────────────────────────────
    def search(self, event, top_k: int = 3) -> list[dict]:
        """检索相似历史：同主机 +3 / 同进程 +2 / 行为 token 重叠 +1。"""
        records = self._load()
        if not records:
            return []
        corpus_tokens = self._tokenize(
            f"{getattr(event, 'behavior', '')} {getattr(event, 'raw_log', '')}"
        )
        current_id = getattr(event, "id", "")
        ranked: list[tuple[int, dict]] = []
        for rec in records:
            if rec.get("event_id") == current_id:
                continue  # 排除自身
            score = 0
            if rec.get("host") and rec.get("host") == getattr(event, "host", ""):
                score += 3
            if rec.get("process") and rec.get("process") == getattr(event, "process", ""):
                score += 2
            overlap = corpus_tokens & self._tokenize(rec.get("behavior", ""))
            score += min(len(overlap), 3)
            if score > 0:
                ranked.append((score, rec))
        ranked.sort(key=lambda row: -row[0])
        return [rec for _, rec in ranked[:top_k]]

    # ── 清理与统计 ────────────────────────────────────────
    def clear(self) -> int:
        """清空记忆，返回删除条数（fail-open）。"""
        records = self._load()
        count = len(records)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.warning("记忆清空失败: %s", exc)
            return 0
        return count

    def count(self) -> int:
        return len(self._load())

    # ── 内部 ──────────────────────────────────────────────
    def _trim(self) -> None:
        """只保留最近 MAX_RECORDS 条（6.3 记忆上限）。"""
        records = self._load()
        if len(records) <= self.MAX_RECORDS:
            return
        try:
            with self.path.open("w", encoding="utf-8") as fh:
                for rec in records[-self.MAX_RECORDS:]:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001
            logger.warning("记忆裁剪失败（已忽略）: %s", exc)

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # 跳过坏行
        except OSError:
            return []
        return records

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """轻量分词：非字母数字切分 + 中文按字符二元组（简化）。"""
        import re

        tokens = set(re.findall(r"[a-zA-Z0-9_]+", text.lower()))
        for char in text:
            if "\u4e00" <= char <= "\u9fff":
                tokens.add(char)
        return tokens
