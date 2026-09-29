"""真实 LLM 全量评测：32 例标准评测 + 三模式对比，并统计真实 token 成本。"""
from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.getLogger("security_agent").setLevel(logging.ERROR)

import security_agent.ai.client as C  # noqa: E402

_REAL = C.httpx
USAGE: list[dict] = []


class _Proxy:
    def __getattr__(self, name):
        return getattr(_REAL, name)

    def post(self, *a, **k):
        resp = _REAL.post(*a, **k)
        try:
            b = resp.json()
            u = b.get("usage") or {}
            ch = (b.get("choices") or [{}])[0]
            USAGE.append({
                "p": u.get("prompt_tokens", 0),
                "c": u.get("completion_tokens", 0),
                "r": (u.get("completion_tokens_details") or {}).get("reasoning_tokens", 0),
                "finish": ch.get("finish_reason"),
                "clen": len((ch.get("message") or {}).get("content") or ""),
            })
        except Exception as exc:  # noqa: BLE001
            USAGE.append({"err": repr(exc)})
        return resp


C.httpx = _Proxy()

from security_agent.app import build_app  # noqa: E402


def marker(result: dict) -> str:
    for line in result.get("execution_log") or []:
        if "AI 大模型已完成综合研判" in line:
            return "AI"
        if "规则引擎回退" in line:
            return "RULE"
    return "?"


def main() -> None:
    app = build_app()
    print(f"model={C._resolve_settings()['model']} max_out={C._resolve_settings()['max_output_tokens']}")
    print("=" * 72)

    before = len(USAGE)
    r = app.evaluate_cases()
    s = r["summary"]
    used = USAGE[before:]
    print("[standard/hybrid-LLM] pass_rate=%.3f total=%d passed=%d risk=%.3f fp=%.3f et=%.3f"
          % (s["pass_rate"], s["total_cases"], s["passed_cases"],
             s["risk_level_accuracy"], s["false_positive_accuracy"], s["event_type_accuracy"]))
    print("   llm_calls=%d  prompt_tok=%d  completion_tok=%d  reasoning_tok=%d"
          % (len(used), sum(u.get("p", 0) for u in used),
             sum(u.get("c", 0) for u in used), sum(u.get("r", 0) for u in used)))
    ai_n = sum(1 for u in used if u.get("clen", 0) > 0)
    print("   calls_with_body=%d  truncated=%d" % (ai_n, sum(1 for u in used if u.get("finish") == "length")))

    fails = [c for c in r["cases"]
             if not (c["risk_match"] and c["false_positive_match"] and c["event_type_match"])]
    print("   FAILS: %d" % len(fails))
    for c in fails:
        print("     %s exp(risk=%s fp=%s type=%s) got(risk=%s fp=%s type=%s) prefilter=%s"
              % (c["event_id"], c["expected_risk_level"], c["expected_false_positive"],
                 c["expected_event_type"], c["actual_risk_level"], c["actual_false_positive"],
                 c["actual_event_type"], c.get("prefilter_decision")))

    print("=" * 72)
    if "modes" not in sys.argv:
        tot_p = sum(u.get("p", 0) for u in USAGE)
        tot_c = sum(u.get("c", 0) for u in USAGE)
        print("GRAND TOTAL: calls=%d prompt_tok=%d completion_tok=%d" % (len(USAGE), tot_p, tot_c))
        print("   est cost @ ¥2/¥8 per M = ¥%.4f" % (tot_p / 1e6 * 2.0 + tot_c / 1e6 * 8.0))
        return

    before = len(USAGE)
    modes = app.evaluation_service.evaluate_modes(app)
    used = USAGE[before:]
    for name, rep in modes["modes"].items():
        ms = rep["summary"]
        print("%-8s pass=%.3f risk=%.3f fp=%.3f et=%.3f avg_ms=%.0f cost=%s"
              % (name, ms["pass_rate"], ms["risk_level_accuracy"],
                 ms["false_positive_accuracy"], ms["event_type_accuracy"],
                 ms["avg_duration_ms"], ms.get("cost_estimate")))
    print("   modes llm_calls=%d prompt_tok=%d completion_tok=%d"
          % (len(used), sum(u.get("p", 0) for u in used), sum(u.get("c", 0) for u in used)))

    tot_p = sum(u.get("p", 0) for u in USAGE)
    tot_c = sum(u.get("c", 0) for u in USAGE)
    print("=" * 72)
    print("GRAND TOTAL: calls=%d prompt_tok=%d completion_tok=%d" % (len(USAGE), tot_p, tot_c))
    for rate_in, rate_out, label in [(1.0, 2.0, "¥1/¥2 per M"), (2.0, 8.0, "¥2/¥8 per M")]:
        cost = tot_p / 1e6 * rate_in + tot_c / 1e6 * rate_out
        print("   est cost @ %s = ¥%.4f" % (label, cost))


if __name__ == "__main__":
    main()
