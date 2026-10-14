"""阶段 2 HITL：人工复核反馈的读写单一持有者。

为什么需要一个独立 store（而非让各调用方直接读 JSONL）：

Web 面板此前**内联手写了**回写逻辑（`web/server.py::_handle_review`），而 Agent
侧**从未读取**该文件的任何一行——`review_feedback.jsonl` 是一条**只写不读的死
数据**。叙事上宣称"HITL 闭环 / 反馈回写供误报记忆复用"，实际人工点下"确认/驳回"
后，除了页面多一行展示，对后续研判没有任何影响：同一个事件再跑一次，Agent 会
原样给出那个已被人否定的结论。

收归本 store 后，读写各有且仅有一处实现：
- 写：`web/server.py` 调 `append()`（含 decision 合法性校验）；
- 读：`orchestrator._triage` 调 `latest()` / `history()`，结果沿 context 流到
  Triage（提示词证据）与 Reviewer（复核状态门控）。

fail-open：文件缺失、坏行、写入失败均安全降级，**绝不因 HITL 中断研判链路**。
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from security_agent.agent.models import HumanFeedbackRecord

logger = logging.getLogger(__name__)

# 复核决定的取值域：confirm=人工采纳该裁决；reject=人工否定该裁决
DECISION_CONFIRM = "confirm"
DECISION_REJECT = "reject"
VALID_DECISIONS = (DECISION_CONFIRM, DECISION_REJECT)

FEEDBACK_FILENAME = "review_feedback.jsonl"


class HumanFeedbackStore:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or (
            Path(__file__).resolve().parent.parent / "data" / FEEDBACK_FILENAME
        )
        # 最近一次 load_all() 跳过的行数（坏行 / 非对象 / 非法 decision）。
        # 人工复核是 HITL 闭环的唯一输入源，静默丢行 = 闭环从读侧悄悄失效。
        self.skipped_lines = 0

    # ── 写入（供 Web 复核回写使用）────────────────────────
    def append(
        self,
        event_id: str,
        decision: str,
        note: str = "",
        event_type: str = "",
        risk_level: str = "",
        is_false_positive: Optional[bool] = None,
    ) -> bool:
        """追加一条人工复核反馈；decision 非法时拒绝写入并返回 False。

        `event_type / risk_level / is_false_positive` 是**被复核的那次裁决摘要**，
        由调用方（Web 表单隐藏域）从当时展示的结果带入。带摘要的反馈才能在后续
        研判中被判定"是否适用于本次新结论"，是读回能落到 review_status 的前提。
        """
        if decision not in VALID_DECISIONS or not event_id:
            logger.warning("非法复核反馈已拒绝: event_id=%r decision=%r", event_id, decision)
            return False
        entry = HumanFeedbackRecord(
            event_id=event_id,
            decision=decision,
            note=note or "",
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type or "",
            risk_level=risk_level or "",
            is_false_positive=is_false_positive,
        ).to_dict()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return True
        except Exception as exc:  # noqa: BLE001 - 回写失败不阻断研判主链路
            logger.warning("复核反馈写入失败（已忽略）: %s", exc)
            return False

    # ── 读取（供 Agent 研判链路使用）──────────────────────
    def latest(self, event_id: str) -> Optional[HumanFeedbackRecord]:
        """取该事件**最近一次**人工复核反馈；无则 None。"""
        matched = self.history(event_id)
        return matched[-1] if matched else None

    def history(self, event_id: str) -> list[HumanFeedbackRecord]:
        """按写入顺序返回该事件的全部反馈（后写的排在后）。"""
        return [
            record
            for record in self.load_all()
            if record.event_id == event_id
        ]

    def reject_count(self, event_id: str) -> int:
        """该事件被人工驳回的次数（用于「重复被驳回结论」判定强度）。"""
        return sum(1 for record in self.history(event_id) if record.decision == DECISION_REJECT)

    def count(self) -> int:
        return len(self.load_all())

    def load_all(self) -> list[HumanFeedbackRecord]:
        """加载全部人工反馈。

        坏行**必须警示而非静默跳过**：`latest()` 拿不到这一步就会降级为「无复核」，
        Reviewer 因而保持自动裁决，操作员的"驳回"在界面上写进去了、链路里却没生效，
        且全过程无任何报错——这是 HITL 闭环最难自查的一种失效。
        """
        self.skipped_lines = 0
        if not self.path.exists():
            return []
        records: list[HumanFeedbackRecord] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("复核反馈文件读取失败（本次按无反馈处理）: %s", exc)
            return []
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                self.skipped_lines += 1
                logger.warning(
                    "复核反馈第 %d 行无法解析，该条人工反馈已失效: %s", lineno, exc
                )
                continue
            if not isinstance(row, dict):
                self.skipped_lines += 1
                logger.warning("复核反馈第 %d 行不是 JSON 对象，该条人工反馈已失效", lineno)
                continue
            decision = row.get("decision")
            if decision not in VALID_DECISIONS:
                self.skipped_lines += 1
                logger.warning(
                    "复核反馈第 %d 行 decision 非法(%r)，该条人工反馈已失效",
                    lineno,
                    decision,
                )
                continue  # 非法决定值不计入（防止脏数据污染门控）
            records.append(
                HumanFeedbackRecord(
                    event_id=str(row.get("event_id", "")),
                    decision=decision,
                    note=str(row.get("note", "") or ""),
                    timestamp=str(row.get("timestamp", "") or ""),
                    event_type=str(row.get("event_type", "") or ""),
                    risk_level=str(row.get("risk_level", "") or ""),
                    # 旧记录无该字段 → None（摘要未知），保证向后兼容
                    is_false_positive=(
                        row["is_false_positive"]
                        if isinstance(row.get("is_false_positive"), bool)
                        else None
                    ),
                )
            )
        return records
