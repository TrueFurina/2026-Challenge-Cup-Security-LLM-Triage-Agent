import json
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from security_agent.ai import client as llm_client


@dataclass
class EvaluationCase:
    event_id: str
    title: str
    expected_risk_level: str
    expected_false_positive: bool
    expected_event_type: str
    category: str
    # 垂类场景标签：用于按场景分组统计（命题书要求覆盖渗透测试/应急响应/漏洞挖掘/逆向分析多场景，
    # 分场景指标是「通用性」的取证依据）。旧用例无此字段时回落到默认场景。
    scenario: str = "应急响应·威胁研判"


class EvaluationService:
    REQUIRED_OUTPUT_FIELDS = [
        "event_type",
        "verdict",
        "risk_level",
        "confidence",
        "evidence",
        "recommendations",
        "knowledge_hits",
        "tool_observations",
        "execution_log",
    ]

    def __init__(self, cases: list[EvaluationCase]):
        self._cases = cases

    @classmethod
    def default(cls) -> "EvaluationService":
        path = Path(__file__).resolve().parent.parent / "data" / "evaluation_cases.json"
        rows = json.loads(path.read_text(encoding="utf-8"))
        return cls(cases=[EvaluationCase(**row) for row in rows])

    def evaluate(self, app) -> dict:
        """执行全量评测。

        评测全程运行在 `SecurityAgent.evaluation_sandbox()` 内：研判记忆**读写双向隔离**。
        不隔离会让同一份代码跑出不同数字——写入让上轮裁决经同主机检索回注提示词
        （自己污染自己，EVENT-013 曾被同主机 EVENT-001 的历史裁决带错），
        读取让任何存量记忆影响本轮结果。隔离实现由 Agent 侧单一持有，
        评测入口与离线评测脚本共用，避免两处漂移。
        """
        with app.evaluation_sandbox():
            return self._evaluate_inner(app)

    def _evaluate_inner(self, app) -> dict:
        case_results = []
        total_duration_ms = 0.0
        risk_hits = 0
        false_positive_hits = 0
        event_type_hits = 0
        completeness_total = 0.0
        prefilter_snapshot = dict(getattr(app, "prefilter_stats", {}))
        llm_snapshot = llm_client.get_usage_stats()

        for case in self._cases:
            started = perf_counter()
            result = app.triage_event(case.event_id).to_dict()
            duration_ms = (perf_counter() - started) * 1000
            total_duration_ms += duration_ms

            risk_match = result["risk_level"] == case.expected_risk_level
            false_positive_match = (
                result["is_false_positive"] == case.expected_false_positive
            )
            event_type_match = result["event_type"] == case.expected_event_type
            completeness = self._calculate_completeness(result)
            prefilter_decision = result.get("prefilter_decision", "NEED_LLM")

            risk_hits += int(risk_match)
            false_positive_hits += int(false_positive_match)
            event_type_hits += int(event_type_match)
            completeness_total += completeness

            case_results.append(
                {
                    "event_id": case.event_id,
                    "title": case.title,
                    "category": case.category,
                    "prefilter_decision": prefilter_decision,
                    "actual_confidence": result.get("confidence", ""),
                    "expected_risk_level": case.expected_risk_level,
                    "actual_risk_level": result["risk_level"],
                    "risk_match": risk_match,
                    "expected_false_positive": case.expected_false_positive,
                    "actual_false_positive": result["is_false_positive"],
                    "false_positive_match": false_positive_match,
                    "expected_event_type": case.expected_event_type,
                    "actual_event_type": result["event_type"],
                    "event_type_match": event_type_match,
                    "output_completeness": round(completeness, 3),
                    "tool_count": len(result["tool_observations"]),
                    "duration_ms": round(duration_ms, 2),
                }
            )

        total_cases = len(self._cases)
        passed_cases = sum(
            1
            for item in case_results
            if item["risk_match"] and item["false_positive_match"] and item["event_type_match"]
        )
        summary = {
            "total_cases": total_cases,
            "risk_level_accuracy": round(risk_hits / total_cases, 3) if total_cases else 0.0,
            "false_positive_accuracy": round(false_positive_hits / total_cases, 3)
            if total_cases
            else 0.0,
            "event_type_accuracy": round(event_type_hits / total_cases, 3)
            if total_cases
            else 0.0,
            "output_completeness": round(completeness_total / total_cases, 3)
            if total_cases
            else 0.0,
            "avg_duration_ms": round(total_duration_ms / total_cases, 2)
            if total_cases
            else 0.0,
            "passed_cases": passed_cases,
            "pass_rate": round(passed_cases / total_cases, 3) if total_cases else 0.0,
            "prefilter": self._prefilter_stats(app, prefilter_snapshot),
            "false_positive_closure_rate": self._fp_closure_rate(case_results),
            "cost_estimate": self._cost_estimate(llm_snapshot),
            "llm_usage": self._llm_usage_delta(llm_snapshot),
            "confidence_calibration": self._confidence_calibration(case_results),
        }
        return {
            "summary": summary,
            "category_breakdown": self._build_category_breakdown(case_results),
            "cases": case_results,
        }

    def evaluate_modes(self, app) -> dict:
        """三模式对比评测：纯规则 / 纯 LLM / 预筛+LLM 混合。

        论证"混合架构最优"：纯规则零成本但准确率低；纯 LLM 准确率中但成本高慢；
        混合模式准确率高且成本低——赛题 XH-202614 核心论证材料。
        """
        from security_agent.prefilter import NEED_LLM, PreFilterEngine, PreFilterResult

        class NoPreFilter(PreFilterEngine):
            """禁用预筛：全部走 LLM 深度研判。"""

            def prefilter(self, *args, **kwargs):
                return PreFilterResult(decision=NEED_LLM, llm_skipped=False)

        modes: dict[str, dict] = {}

        # 模式 1：纯规则 —— 禁用预筛 + 强制 AI 回退（模拟无 LLM）
        app_rules = self._clone_app(app)
        app_rules.prefilter_engine = NoPreFilter()
        app_rules.force_rule_fallback = True
        modes["rules"] = self.evaluate(app_rules)

        # 模式 2：纯 LLM —— 禁用预筛，全走 LLM
        app_llm = self._clone_app(app)
        app_llm.prefilter_engine = NoPreFilter()
        modes["llm"] = self.evaluate(app_llm)

        # 模式 3：混合（默认）—— 预筛 + LLM
        modes["hybrid"] = self.evaluate(app)

        return {
            "modes": modes,
            "comparison": self._build_mode_comparison(modes),
            # 顶层透出混合模式逐案例明细，供报告渲染（混淆矩阵/逐案例表）
            "summary": modes["hybrid"]["summary"],
            "category_breakdown": modes["hybrid"]["category_breakdown"],
            "cases": modes["hybrid"]["cases"],
        }

    @staticmethod
    def _clone_app(app) -> "object":
        """复制应用（浅拷贝属性对象，避免模式间 prefilter_stats 串扰）。"""
        import copy

        clone = copy.copy(app)
        clone.prefilter_stats = {"auto_close": 0, "auto_escalate": 0, "need_llm": 0}
        return clone

    @staticmethod
    def _build_mode_comparison(modes: dict) -> dict:
        """三模式对比表：通过率/风险/FP/类型/耗时/成本 + 混淆矩阵。"""
        rows = {}
        for name, report in modes.items():
            s = report["summary"]
            # 混淆矩阵（误报判定 2×2）
            cases = report.get("cases", [])
            tp = sum(1 for c in cases if c["expected_false_positive"] and c["actual_false_positive"])
            fn = sum(1 for c in cases if c["expected_false_positive"] and not c["actual_false_positive"])
            fp = sum(1 for c in cases if not c["expected_false_positive"] and c["actual_false_positive"])
            tn = sum(1 for c in cases if not c["expected_false_positive"] and not c["actual_false_positive"])
            rows[name] = {
                "pass_rate": s["pass_rate"],
                "risk_level_accuracy": s["risk_level_accuracy"],
                "false_positive_accuracy": s["false_positive_accuracy"],
                "event_type_accuracy": s["event_type_accuracy"],
                "avg_duration_ms": s["avg_duration_ms"],
                "cost_estimate": s.get("cost_estimate", 0.0),
                # LLM 实际请求次数（实测计数）；无该字段时回退到预筛 NEED_LLM 计数
                "llm_calls": (s.get("llm_usage") or {}).get(
                    "requests", s.get("prefilter", {}).get("need_llm", 0)
                ),
                "llm_usage": s.get("llm_usage", {}),
                "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
            }
        return rows

    @staticmethod
    def _fp_closure_rate(case_results: list[dict]) -> float:
        """误报关闭率：预筛 AUTO_CLOSE 且判定为误报的案例 / 全部预期误报案例。"""
        expected_fp = [item for item in case_results if item["expected_false_positive"]]
        if not expected_fp:
            return 0.0
        closed = sum(
            1
            for item in expected_fp
            if item["prefilter_decision"] == "AUTO_CLOSE" and item["actual_false_positive"]
        )
        return round(closed / len(expected_fp), 3)

    @staticmethod
    def _cost_estimate(llm_snapshot: dict) -> float:
        """成本估算（元）：基于本轮**实测** token 用量 × 可配置单价假设。

        token 数取自 LLM 响应的 usage 字段真实累计（见 security_agent.ai.client
        的用量计量），不再是「调用次数 × 固定金额」的硬编码近似——后者会让报告中
        的成本数字与真实开销脱钩。单价为显式假设，可用环境变量
        SECURITY_AGENT_PROMPT_PRICE_PER_M / SECURITY_AGENT_COMPLETION_PRICE_PER_M
        （元/百万 token）覆盖。无 LLM 调用时返回 0.0。
        """
        return llm_client.estimate_cost_yuan(EvaluationService._llm_usage_delta(llm_snapshot))

    @staticmethod
    def _llm_usage_delta(snapshot: dict) -> dict:
        """本轮评测相对快照的 LLM 用量增量（实测计数，供报告与成本口径使用）。"""
        current = llm_client.get_usage_stats()
        return {
            key: current.get(key, 0) - snapshot.get(key, 0)
            for key in (
                "requests",
                "failed_requests",
                "prompt_tokens",
                "completion_tokens",
                "reasoning_tokens",
                "truncated_responses",
            )
        }

    @staticmethod
    def _confidence_calibration(case_results: list[dict]) -> dict:
        """置信度校准：不同置信度档位的综合正确率（验证"高置信是否更准"）。"""
        groups: dict[str, list[dict]] = {}
        for item in case_results:
            groups.setdefault(item.get("actual_confidence", ""), []).append(item)
        result = {}
        for level, items in groups.items():
            ok = sum(
                1
                for it in items
                if it["risk_match"] and it["false_positive_match"] and it["event_type_match"]
            )
            result[level] = round(ok / len(items), 3) if items else 0.0
        return result

    def _prefilter_stats(self, app, snapshot: dict) -> dict:
        """预筛器统计：本评测批次内的分流情况与 LLM 调用节省率。"""
        current = dict(getattr(app, "prefilter_stats", {}))
        auto_close = current.get("auto_close", 0) - snapshot.get("auto_close", 0)
        auto_escalate = current.get("auto_escalate", 0) - snapshot.get("auto_escalate", 0)
        need_llm = current.get("need_llm", 0) - snapshot.get("need_llm", 0)
        total = auto_close + auto_escalate + need_llm
        prefiltered = auto_close + auto_escalate
        return {
            "auto_close": auto_close,
            "auto_escalate": auto_escalate,
            "need_llm": need_llm,
            "prefilter_pass_rate": round(prefiltered / total, 3) if total else 0.0,
            "llm_call_savings_rate": round(prefiltered / total, 3) if total else 0.0,
        }

    def _calculate_completeness(self, result: dict) -> float:
        filled = 0
        for key in self.REQUIRED_OUTPUT_FIELDS:
            value = result.get(key)
            if isinstance(value, list):
                filled += int(len(value) > 0)
            else:
                filled += int(value not in (None, "", {}))
        return filled / len(self.REQUIRED_OUTPUT_FIELDS)

    def _build_category_breakdown(self, case_results: list[dict]) -> list[dict]:
        """分类统计（按场景类别 + 按风险等级 + 按事件类型 + 按资产重要度）。"""
        # 按场景类别
        by_category = self._group_stats(case_results, "category")
        # 按风险等级
        by_risk = self._group_stats(case_results, "actual_risk_level")
        # 按事件类型
        by_type = self._group_stats(case_results, "actual_event_type")
        # 按预期误报（资产重要度近似）
        by_fp = {
            "expected_fp": self._group_stats([c for c in case_results if c["expected_false_positive"]], "category"),
            "expected_non_fp": self._group_stats([c for c in case_results if not c["expected_false_positive"]], "category"),
        }
        return by_category

    @staticmethod
    def _group_stats(case_results: list[dict], key: str) -> list[dict]:
        grouped = {}
        for item in case_results:
            grouped.setdefault(item.get(key, "unknown"), []).append(item)
        rows = []
        for label, items in grouped.items():
            total = len(items)
            rows.append({
                "label": label,
                "total_cases": total,
                "risk_level_accuracy": round(sum(1 for i in items if i["risk_match"]) / total, 3) if total else 0.0,
                "false_positive_accuracy": round(sum(1 for i in items if i["false_positive_match"]) / total, 3) if total else 0.0,
                "pass_rate": round(sum(1 for i in items if i["risk_match"] and i["false_positive_match"] and i["event_type_match"]) / total, 3) if total else 0.0,
            })
        return rows
