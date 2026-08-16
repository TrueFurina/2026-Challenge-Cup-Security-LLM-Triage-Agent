# 2026 Challenge Cup - Security LLM Triage Agent

Multi-Agent Security Alert False Positive Elimination System

> **中文版说明**: [README.zh.md](README.zh.md)

An AI-powered security incident triage and false-positive elimination agent for the 2026 "Challenge Cup" (赛题 XH-202614 / XH-202609). It uses an **LLM as the core decision engine**, backed by a deterministic pre-filter, confidence gating with human-in-the-loop review, multi-agent collaboration, RAG knowledge grounding, false-positive memory, and a full investigation ledger.

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?logo=python&logoColor=white)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 🎯 Highlights

- **LLM decision engine** — the model is the core judge (not decoration): three-mode comparison (rules vs. pure LLM vs. prefilter+LLM hybrid) proves hybrid wins at **90% pass rate** on real DeepSeek while cutting cost
- **Deterministic pre-filter** — 3-state triage (AUTO_CLOSE / AUTO_ESCALATE / NEED_LLM) with configurable rules, **saving 70% of LLM calls**
- **Confidence gating + HITL** — low-confidence results are not auto-dispatched; human review is written back
- **Multi-agent collaboration** — Triage → Hunt → Respond → Report, each independently testable with fail-open degradation
- **RAG knowledge grounding** — 21 knowledge entries with MITRE ATT&CK / CVE mapping injected into prompts to reduce hallucination
- **False-positive memory** — similar historical verdicts are injected into the prompt so the same FP never repeats
- **Investigation Ledger** — every triage records its full evidence chain (tool calls, LLM prompt/response, final verdict) and is replayable in the web UI
- **MCP integration** — 10 security tools exposed as MCP (Model Context Protocol) via a zero-dependency stdio server

## 🚀 Quick Start

```bash
cd "E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体"

# 1. Verify the environment (no API key required — falls back to rules)
python scripts/_verify_syntax.py     # 43/43 syntax OK
python scripts/_prefilter_test.py    # 25/25 prefilter tests

# 2. Run the full evaluation (real DeepSeek if DEEPSEEK_API_KEY is set)
python -m security_agent.cli evaluate

# 3. Launch the dark-mode web dashboard
python -m security_agent.cli serve --port 8080
# Open http://127.0.0.1:8080
```

> **Zero-dependency mode**: without an API key the agent runs on the deterministic rule engine (fail-open) — everything still works, just no LLM reasoning.

## 🧠 Architecture

```
Event input
   │
   ▼
① Deterministic Pre-Filter (milliseconds)
   ├─ AUTO_CLOSE      → FP auto-closed (no LLM)
   ├─ AUTO_ESCALATE   → attack directly rated (no LLM)
   └─ NEED_LLM        → deep LLM triage
   │
   ▼
② LLM Triage (DeepSeek/Qwen) + confidence gating + FP memory + RAG grounding
   │
   ▼
③ Multi-Agent Collaboration: Triage → Hunt → Respond → Report
   │
   ▼
④ Closure & Audit: Investigation Ledger + FP memory persistence + MCP exposure
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## 🧪 Evaluation

- **10 standard cases**, real DeepSeek: pass rate **0.9** (risk 0.9 / FP 1.0 / type 1.0 / completeness 1.0)
- Three-mode comparison: `python -m security_agent.cli report --format md` (rules vs. LLM vs. hybrid, with confusion matrix)
- 10 test scripts, **208/208 passing** (prefilter/hitl/agents/knowledge/eval/memory/mcp/ledger/web)

## 📁 Repository Layout

```
security_agent/
├── ai/            # LLM client (fail-open) + triage engine + enricher
├── prefilter/     # deterministic 3-state pre-filter + rules
├── agents/        # Triage/Hunt/Respond/Report + coordinator
├── memory/        # false-positive memory (append/search/clear)
├── ledger/        # investigation audit trail
├── mcp/           # MCP server (stdio, zero-dependency)
├── evaluation/    # eval service (three-mode comparison)
├── web/           # dark-mode dashboard + audit replay
└── data/          # alerts / assets / intel / knowledge / rules
docs/              # 15+ technical documents (architecture, AI module, eval, ...)
scripts/           # test & verification scripts
```

## 🔗 Competition Topics

- **XH-202614** — AI + Security LLM Platform Agent Research (LLM as core decision engine)
- **XH-202609** — General Cyber Security Agent with Autonomous Decision (closed loop: prefilter + multi-agent + HITL)

## 🤝 License

[MIT](LICENSE) © Minjiang University Team

---

## License & Usage Notice

**Source-Available · All Rights Reserved**

This project is source-available and all rights are reserved by the author. The code is provided for **viewing and evaluation purposes only** — access does not grant any right to copy, modify, redistribute, use commercially, or create derivative works. Unauthorized reuse may carry legal risk. Contact the author for explicit written permission before any other use.

**本仓库为「源码可查、权利保留」项目（source-available / all-rights-reserved）。代码仅供查看与评估，未授权任何复制、再分发、修改、商用或衍生创作。擅自借用代码存在法律风险；如有需要请先联系作者获取明确书面许可。**

