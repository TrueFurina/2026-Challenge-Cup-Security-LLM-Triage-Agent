"""LedgerStore：研判证据链审计记录（阶段 8）。

每次研判生成 data/ledger/{event_id}.json，记录：
- steps：各阶段步骤（工具调用/预筛/LLM/后处理），含时间戳与耗时
- final_verdict：最终裁决（事件类型/风险/置信度/误报/结论）
- LLM 调用：prompt + response（通过 on_llm_call 回调注入）

设计：
1. fail-open：写入失败/目录不可写均不阻断主流程
2. 同一事件重复研判 → 覆盖旧 ledger（保留最新）
3. load() 供 Web 审计回放
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class LedgerStore:
    def __init__(self, root: Optional[Path] = None):
        self.root = root or (
            Path(__file__).resolve().parent.parent / "data" / "ledger"
        )

    # ── 生命周期 ──────────────────────────────────────────
    def begin(self, event_id: str, scenario: str = "") -> Optional["LedgerRecord"]:
        """创建新 ledger（fail-open：失败返回 None，不阻断主流程）。"""
        try:
            return LedgerRecord(store=self, event_id=event_id, scenario=scenario)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ledger 创建失败（已忽略）: %s", exc)
            return None

    def load(self, event_id: str) -> Optional[dict]:
        """加载指定事件的 ledger（供 Web 回放）。"""
        path = self.root / f"{event_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Ledger 加载失败: %s", exc)
            return None

    def list_event_ids(self) -> list[str]:
        """列出已有 ledger 的事件 ID（按修改时间倒序）。"""
        if not self.root.exists():
            return []
        try:
            files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return []
        return [path.stem for path in files]


class LedgerRecord:
    """单次研判的审计记录（写时 fail-open）。"""

    def __init__(self, store: LedgerStore, event_id: str, scenario: str = ""):
        self.store = store
        self.event_id = event_id
        self.scenario = scenario
        self.started_at = datetime.utcnow().isoformat() + "Z"
        self.steps: list[dict] = []
        self.final_verdict: dict = {}
        self._llm_index = 0

    def record_step(self, phase: str, **fields) -> None:
        """记录一个阶段步骤（工具调用/预筛/后处理等）。"""
        entry = {"phase": phase, "timestamp": datetime.utcnow().isoformat() + "Z"}
        entry.update(fields)
        self.steps.append(entry)

    def record_llm(self, prompt: str, response: str) -> None:
        """记录一次 LLM 调用（prompt + response 摘要）。"""
        self._llm_index += 1
        self.steps.append(
            {
                "phase": "llm",
                "llm_call": self._llm_index,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "llm_prompt": prompt[:2000],
                "llm_response": (response or "")[:2000],
            }
        )

    def finalize(self, verdict: dict) -> None:
        """写入最终裁决并落盘。"""
        self.final_verdict = verdict
        try:
            self.store.root.mkdir(parents=True, exist_ok=True)
            payload = {
                "event_id": self.event_id,
                "scenario": self.scenario,
                "started_at": self.started_at,
                "finalized_at": datetime.utcnow().isoformat() + "Z",
                "steps": self.steps,
                "final_verdict": verdict,
            }
            path = self.store.root / f"{self.event_id}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - 审计写入失败不阻断主流程
            logger.warning("Ledger 落盘失败（已忽略）: %s", exc)
