import html
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from security_agent.app import build_app
from security_agent.config import AppConfig
from security_agent.reporting.render import render_markdown_report

# 阶段 9：三模式对比结果缓存（避免每次刷新都跑真实 LLM 全量评测）
_MODE_COMPARISON_CACHE: dict = {"data": None, "ts": 0}


def _page(title: str, body: str) -> bytes:
    doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #0a1128;
      --panel: #111c33;
      --panel-2: #0e1830;
      --ink: #e8ecf3;
      --muted: #7a8bb0;
      --accent: #00ff9d;
      --accent-2: #00b3ff;
      --line: #233454;
      --good: #00ff9d;
      --warn: #ffb454;
      --bad: #ff5d5d;
      --shadow: rgba(0, 0, 0, 0.35);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 15% -10%, rgba(0,179,255,0.18), transparent 40%),
        radial-gradient(circle at 90% 110%, rgba(0,255,157,0.12), transparent 35%),
        linear-gradient(180deg, #0d1730 0%, var(--bg) 60%);
    }}
    .shell {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 28px 20px 40px;
    }}
    .hero, .grid, .two-col {{
      display: grid;
      gap: 18px;
    }}
    .hero {{
      grid-template-columns: 1.45fr 1fr;
      margin-bottom: 18px;
    }}
    .grid {{
      grid-template-columns: 340px 1fr;
      align-items: start;
    }}
    .two-col {{
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
    .card {{
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 22px;
      box-shadow: 0 12px 30px var(--shadow);
    }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{
      margin-bottom: 10px;
      font-size: 34px;
      line-height: 1.1;
      letter-spacing: -0.03em;
      color: #fff;
    }}
    h2 {{ color: #dfe8ff; }}
    .tag {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(0,255,157,0.10);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      border: 1px solid rgba(0,255,157,0.25);
    }}
    .lede {{
      color: var(--muted);
      line-height: 1.7;
      max-width: 62ch;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      margin-top: 14px;
    }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
      background: rgba(0,179,255,0.05);
    }}
    .stat strong {{
      display: block;
      font-size: 22px;
      margin-bottom: 6px;
      color: var(--accent);
    }}
    .alert-list {{
      display: grid;
      gap: 12px;
    }}
    .alert-item {{
      display: block;
      text-decoration: none;
      color: inherit;
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      background: rgba(0,179,255,0.06);
      transition: transform 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
    }}
    .alert-item:hover {{
      transform: translateY(-1px);
      border-color: var(--accent);
      box-shadow: 0 10px 20px rgba(0,179,255,0.08);
    }}
    .sev {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }}
    .sev-high, .sev-critical {{ background: rgba(161,45,47,0.12); color: var(--bad); }}
    .sev-medium {{ background: rgba(167,109,0,0.12); color: var(--warn); }}
    .sev-low {{ background: rgba(42,127,98,0.12); color: var(--good); }}
    .meta {{
      color: var(--muted);
      font-size: 13px;
      margin-top: 8px;
    }}
    .toolbar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 12px;
      align-items: center;
    }}
    .btn {{
      display: inline-block;
      padding: 10px 14px;
      border-radius: 12px;
      text-decoration: none;
      font-weight: 600;
      border: 1px solid var(--line);
      color: var(--ink);
      background: #1a2744;
    }}
    .btn-primary {{
      background: var(--accent);
      color: #06281a;
      border-color: var(--accent);
    }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}
    .metric-card {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
      background: rgba(0,179,255,0.06);
    }}
    .metric-card strong {{
      display: block;
      font-size: 22px;
      margin-bottom: 6px;
    }}
    .metric-card span {{
      color: var(--muted);
      font-size: 13px;
    }}
    .table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    .table th, .table td {{
      text-align: left;
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      vertical-align: top;
    }}
    .table th {{
      color: var(--muted);
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .result-block {{
      border-top: 1px solid var(--line);
      padding-top: 16px;
      margin-top: 16px;
    }}
    .kv {{
      display: grid;
      grid-template-columns: 170px 1fr;
      gap: 8px 14px;
      margin-bottom: 16px;
    }}
    .kv div:nth-child(odd) {{
      color: var(--muted);
      font-size: 14px;
    }}
    .timeline {{
      display: grid;
      gap: 12px;
      margin: 0;
      padding: 0;
      list-style: none;
    }}
    .timeline li {{
      position: relative;
      padding: 14px 14px 14px 48px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(0,179,255,0.06);
    }}
    .timeline li::before {{
      content: attr(data-step);
      position: absolute;
      left: 12px;
      top: 12px;
      width: 24px;
      height: 24px;
      border-radius: 999px;
      background: var(--accent);
      color: #fff;
      font-size: 12px;
      line-height: 24px;
      text-align: center;
      font-weight: 700;
    }}
    .trace, .obs-list, .agent-grid {{
      display: grid;
      gap: 10px;
    }}
    .trace-item, .obs-item, .agent-item {{
      background: rgba(0,255,157,0.05);
      border-left: 4px solid var(--accent-2);
      padding: 12px 14px;
      border-radius: 0 12px 12px 0;
    }}
    .agent-flow {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      align-items: stretch;
    }}
    .agent-stage {{
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 12px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background:
        linear-gradient(180deg, rgba(17,28,51,0.98) 0%, rgba(14,24,48,0.96) 100%);
      box-shadow: 0 10px 24px rgba(0, 0, 0, 0.35);
      min-height: 100%;
      overflow: hidden;
    }}
    .agent-stage::after {{
      content: "";
      position: absolute;
      inset: auto 0 0 0;
      height: 4px;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
    }}
    .agent-stage:not(:last-child)::before {{
      content: "→";
      position: absolute;
      right: -12px;
      top: 24px;
      z-index: 2;
      width: 24px;
      height: 24px;
      border-radius: 999px;
      background: var(--accent);
      color: #fff;
      font-weight: 700;
      line-height: 24px;
      text-align: center;
      box-shadow: 0 6px 16px rgba(0,179,255,0.24);
    }}
    .agent-stage-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }}
    .agent-stage h3 {{
      margin-bottom: 4px;
      font-size: 20px;
      line-height: 1.1;
    }}
    .agent-kicker {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}
    .agent-index {{
      flex: 0 0 auto;
      width: 30px;
      height: 30px;
      border-radius: 999px;
      background: rgba(0,179,255,0.12);
      color: var(--accent);
      font-weight: 800;
      font-size: 13px;
      line-height: 30px;
      text-align: center;
    }}
    .agent-role {{
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }}
    .agent-focus {{
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(0,179,255,0.06);
      color: var(--ink);
      font-size: 14px;
      line-height: 1.5;
    }}
    .agent-subtitle {{
      margin: 0 0 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .module-badges, .tool-badges {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .module-badge, .tool-badge {{
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(0,179,255,0.10);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
    }}
    ul {{
      padding-left: 18px;
      line-height: 1.65;
    }}
    pre {{
      overflow: auto;
      background: #161a20;
      color: #e8ecf3;
      padding: 16px;
      border-radius: 14px;
      font-size: 13px;
      line-height: 1.5;
    }}
    textarea, select {{
      font: inherit;
    }}
    .footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 13px;
    }}
    .review-banner {{
      padding: 12px 14px;
      border-radius: 14px;
      font-weight: 600;
      margin-bottom: 14px;
      border: 1px solid;
    }}
    .review-pending {{ background: rgba(167,109,0,0.12); color: var(--warn); border-color: rgba(167,109,0,0.35); }}
    .review-confirmed {{ background: rgba(42,127,98,0.12); color: var(--good); border-color: rgba(42,127,98,0.35); }}
    .review-rejected {{ background: rgba(161,45,47,0.12); color: var(--bad); border-color: rgba(161,45,47,0.35); }}
    .review-form {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; align-items: center; }}
    .review-form input[type="text"] {{ flex: 1 1 180px; padding: 9px 12px; border: 1px solid var(--line); border-radius: 10px; }}
    .score-row {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
    .score-label {{ color: var(--muted); font-size: 14px; }}
    .score-value {{ font-size: 18px; font-weight: 700; color: var(--accent); }}
    .score-track {{ height: 12px; border-radius: 999px; background: #0a1430; border: 1px solid var(--line); overflow: hidden; }}
    .score-fill {{ height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--accent-2), var(--accent)); transition: width 400ms ease; }}
    .mode-bar {{ margin: 10px 0; }}
    .mode-bar-label {{ display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px; }}
    .mode-bar-track {{ height: 10px; border-radius: 999px; background: #0a1430; border: 1px solid var(--line); overflow: hidden; }}
    .mode-bar-fill {{ height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--accent-2), var(--accent)); }}
    @media (max-width: 960px) {{
      .hero, .grid, .two-col {{
        grid-template-columns: 1fr;
      }}
      .metric-grid {{
        grid-template-columns: 1fr;
      }}
      .agent-flow {{
        grid-template-columns: 1fr;
      }}
      .agent-stage:not(:last-child)::before {{
        content: "↓";
        right: auto;
        left: 24px;
        top: auto;
        bottom: -12px;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    {body}
    <div class="footer">Scenario: 安全事件初步研判 + 误报剔除</div>
  </div>
</body>
</html>"""
    return doc.encode("utf-8")


class SecurityAgentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(self._render_home(parse_qs(parsed.query)))
            return
        if parsed.path == "/api/config":
            self._send_json(self._config_payload())
            return
        if parsed.path == "/api/evaluation":
            self._send_json(build_app().evaluate_cases())
            return
        if parsed.path == "/api/ledger":
            self._handle_ledger_api(parse_qs(parsed.query))
            return
        if parsed.path == "/ledger":
            self._render_ledger_page(parse_qs(parsed.query))
            return
        if parsed.path == "/generate-modes":
            self._handle_generate_modes()
            return
        if parsed.path == "/api/evaluation-modes":
            self._send_json(self._mode_comparison_data())
            return
        self.send_error(404, "Not Found")

    # ── 阶段 9.3：三模式对比图表 ─────────────────────────
    def _mode_comparison_data(self) -> dict:
        """返回三模式对比数据（带缓存；无缓存时返回空结构）。"""
        cached = _MODE_COMPARISON_CACHE.get("data")
        if cached is not None:
            return cached
        return {"comparison": {}, "generated": False}

    def _handle_generate_modes(self):
        """生成三模式对比（真实 LLM 全量评测，约 1-2 分钟），缓存后跳回首页。"""
        global _MODE_COMPARISON_CACHE
        try:
            app = build_app()
            app.record_history = False
            app.record_ledger = False
            report = app.evaluation_service.evaluate_modes(app)
            _MODE_COMPARISON_CACHE = {"data": report, "ts": datetime.now().timestamp()}
        except Exception as exc:  # noqa: BLE001 - 生成失败不崩溃
            _MODE_COMPARISON_CACHE = {
                "data": {"comparison": {}, "error": str(exc), "generated": False},
                "ts": datetime.now().timestamp(),
            }
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def _render_mode_comparison(self) -> str:
        """三模式对比区块：有缓存渲染纯 CSS 柱状图，否则显示生成按钮。"""
        data = self._mode_comparison_data()
        comparison = data.get("comparison", {})
        if not comparison:
            return f"""
<div class="result-block">
  <h3>三模式对比评测</h3>
  <p class="lede">对比 纯规则 / 纯 LLM / 预筛+LLM 混合 三种模式的准确率、耗时与成本（赛题论证核心数据）。首次生成需运行真实 LLM 全量评测（约 1-2 分钟）。</p>
  <div class="toolbar">
    <a class="btn btn-primary" href="/generate-modes">生成三模式对比</a>
    <a class="btn" href="/api/evaluation">查看当前评测 JSON</a>
  </div>
</div>
"""
        bars = []
        confusion_blocks = []
        for mode_name, mode in comparison.items():
            pass_rate = mode.get("pass_rate", 0)
            cost = mode.get("cost_estimate", 0)
            duration = mode.get("avg_duration_ms", 0)
            width = max(1, int(pass_rate * 100))
            bars.append(
                f"""
  <div class="mode-bar">
    <div class="mode-bar-label">
      <span>{html.escape(mode_name)}（通过率 {pass_rate:.0%} | 成本 {cost} 元 | {duration:.0f} ms）</span>
    </div>
    <div class="mode-bar-track"><div class="mode-bar-fill" style="width:{width}%"></div></div>
  </div>
"""
            )
            # 混淆矩阵（2×2）
            cm = mode.get("confusion", {})
            if cm:
                confusion_blocks.append(
                    f"""
<div class="card" style="margin-top: 10px;">
  <h4>{html.escape(mode_name)} — 误报判定混淆矩阵</h4>
  <table class="table" style="max-width: 380px;">
    <thead><tr><th>实际 \ 预期</th><th>预期误报</th><th>预期非误报</th></tr></thead>
    <tbody>
      <tr><td>判定误报</td><td class="sev sev-low">{cm.get('tp', 0)}</td><td class="sev sev-high">{cm.get('fp', 0)}</td></tr>
      <tr><td>判定非误报</td><td class="sev sev-high">{cm.get('fn', 0)}</td><td class="sev sev-low">{cm.get('tn', 0)}</td></tr>
    </tbody>
  </table>
</div>
"""
                )
        return f"""
<div class="result-block">
  <h3>三模式对比评测</h3>
  <p class="lede">对比 纯规则 / 纯 LLM / 预筛+LLM 混合 三种模式（通过率越高条越长）。</p>
  {''.join(bars)}
  <h3 style="margin-top: 16px;">混淆矩阵（误报识别能力）</h3>
  {''.join(confusion_blocks) if confusion_blocks else '<p class="lede">暂无混淆矩阵数据</p>'}
  <div class="toolbar">
    <a class="btn btn-primary" href="/generate-modes">重新生成</a>
    <a class="btn" href="/api/evaluation-modes">查看对比 JSON</a>
  </div>
</div>
"""

    # ── 阶段 8：Investigation Ledger 审计回放 ─────────────
    def _handle_ledger_api(self, query: dict):
        """返回事件 ledger JSON（评审可核查）。"""
        from security_agent.ledger import LedgerStore

        event_id = query.get("event_id", [""])[0]
        ledger = LedgerStore().load(event_id)
        if ledger is None:
            self._send_json({"error": f"未找到事件 {event_id} 的审计记录"}, status=404)
            return
        self._send_json(ledger)

    def _render_ledger_page(self, query: dict):
        """审计回放页：按事件查看完整调查过程。"""
        from security_agent.ledger import LedgerStore

        store = LedgerStore()
        event_id = query.get("event_id", [""])[0]
        ledger = store.load(event_id) if event_id else None
        event_ids = store.list_event_ids()

        selector = "".join(
            f'<option value="{html.escape(eid)}"{" selected" if eid == event_id else ""}>{html.escape(eid)}</option>'
            for eid in event_ids
        )

        if ledger is None:
            body = f"""
<section class="hero">
  <div class="card">
    <span class="tag">Investigation Ledger</span>
    <h1>审计追踪（阶段 8）</h1>
    <p class="lede">记录每次研判的完整证据链：工具调用 / LLM prompt / LLM 响应 / 最终裁决，可回放、可审计。</p>
    <form class="toolbar" method="get" action="/ledger">
      <select name="event_id">{selector}</select>
      <button class="btn btn-primary" type="submit">查看审计记录</button>
    </form>
  </div>
</section>
<section class="card">
  <h2>选择事件</h2>
  <p>尚未选择事件，或该事件暂无审计记录。请从上方选择。</p>
</section>
"""
            self._send_html(_page("审计追踪", body))
            return

        steps_html = []
        for idx, step in enumerate(ledger.get("steps", []), start=1):
            phase = step.get("phase", "")
            tool = step.get("tool", "")
            summary = step.get("summary", "")
            decision = step.get("decision", "")
            detail_lines = ""
            if step.get("llm_prompt"):
                detail_lines += (
                    f'<div class="trace-item"><strong>Prompt:</strong> '
                    f'<pre>{html.escape(step["llm_prompt"])}</pre></div>'
                )
            if step.get("llm_response"):
                detail_lines += (
                    f'<div class="trace-item"><strong>Response:</strong> '
                    f'<pre>{html.escape(step["llm_response"])}</pre></div>'
                )
            if step.get("details"):
                detail_lines += "<ul>" + "".join(
                    f"<li>{html.escape(d)}</li>" for d in step["details"]
                ) + "</ul>"
            title = f"{phase}"
            if tool:
                title += f" / {tool}"
            if decision:
                title += f" / {decision}"
            steps_html.append(
                f'<li data-step="{idx}"><strong>{html.escape(title)}</strong>'
                f'<div class="meta">{html.escape(str(step.get("timestamp", "")))}</div>'
                f'{f"<p>{html.escape(summary)}</p>" if summary else ""}'
                f"{detail_lines}</li>"
            )

        verdict = ledger.get("final_verdict", {})
        verdict_rows = "".join(
            f"<div>{html.escape(str(k))}</div><div>{html.escape(str(v))}</div>"
            for k, v in verdict.items()
        )

        body = f"""
<section class="hero">
  <div class="card">
    <span class="tag">Investigation Ledger</span>
    <h1>审计追踪：{html.escape(event_id)}</h1>
    <p class="lede">开始 {html.escape(str(ledger.get('started_at', '')))} → 完成 {html.escape(str(ledger.get('finalized_at', '')))}</p>
    <form class="toolbar" method="get" action="/ledger">
      <select name="event_id">{selector}</select>
      <button class="btn btn-primary" type="submit">查看其他事件</button>
      <a class="btn" href="/api/ledger?event_id={html.escape(event_id)}">导出 JSON</a>
    </form>
  </div>
</section>
<section class="two-col">
  <div class="card">
    <h2>调查过程（{len(ledger.get('steps', []))} 步）</h2>
    <ol class="timeline">{''.join(steps_html)}</ol>
  </div>
  <div class="card">
    <h2>最终裁决</h2>
    <div class="kv">{verdict_rows}</div>
    <div class="result-block">
      <h3>结构化记录</h3>
      <pre>{html.escape(json.dumps(ledger, ensure_ascii=False, indent=2))}</pre>
    </div>
  </div>
</section>
"""
        self._send_html(_page("审计追踪", body))

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/analyze-input":
            self._handle_submission()
            return
        if parsed.path == "/export-report":
            self._handle_export()
            return
        if parsed.path == "/review-event":
            self._handle_review()
            return
        self.send_error(404, "Not Found")

    # ── 阶段 2：HITL 复核回写 ─────────────────────────────
    def _review_feedback_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "data" / "review_feedback.jsonl"

    def _latest_review(self, event_id: str):
        """读取复核回写记录，返回该事件最新的复核记录；无记录返回 None。"""
        path = self._review_feedback_path()
        if not path.exists():
            return None
        latest = None
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event_id") == event_id:
                latest = record
        return latest

    def _handle_review(self):
        """人工复核反馈回写：确认/驳回 → 追加到 review_feedback.jsonl。"""
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)
        event_id = form.get("event_id", [""])[0]
        decision = form.get("decision", [""])[0]
        note = form.get("note", [""])[0]
        if not event_id or decision not in {"confirm", "reject"}:
            self._send_html(_page("复核失败", "<h2>复核失败</h2><p>缺少事件 ID 或非法的复核决定。</p>"))
            return

        path = self._review_feedback_path()
        record = {
            "event_id": event_id,
            "decision": decision,
            "note": note,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            self._send_html(_page("复核失败", f"<h2>复核失败</h2><p>回写失败: {html.escape(str(exc))}</p>"))
            return

        # 复核后回到首页并选中该事件，展示最新复核状态
        self.send_response(302)
        self.send_header("Location", f"/?event_id={html.escape(event_id)}")
        self.end_headers()

    def log_message(self, format, *args):
        return

    def _render_home(self, query: dict) -> bytes:
        app = build_app()
        events = list(app.list_events())
        selected_id = query.get("event_id", [""])[0]
        submission_type = query.get("submission_type", ["json"])[0]
        submitted_payload = query.get("payload", [""])[0]
        selected_event = None
        result = None
        error = None

        if selected_id:
            selected_event = next((item for item in events if item.id == selected_id), None)
            if selected_event is None:
                error = f"未找到事件 ID: {selected_id}"
            else:
                try:
                    result = app.triage_event(selected_id).to_dict()
                except Exception as exc:
                    error = str(exc)

        upload_panel = self._render_upload_panel(submission_type, submitted_payload)
        event_cards = "".join(
            self._render_event_card(item, item.id == selected_id) for item in events
        )
        result_html = self._render_result(result, selected_event, error)
        config = self._config_payload()
        evaluation = app.evaluate_cases()
        evaluation_panel = self._render_evaluation_panel(evaluation)

        # 阶段 9：大屏顶部指标卡（从评测汇总提取）
        summary = evaluation.get("summary", {})
        prefilter = summary.get("prefilter", {})
        metric_cards = "".join(
            f'<div class="metric-card"><strong>{value}</strong><span>{label}</span></div>'
            for label, value in [
                ("样例事件", len(events)),
                ("综合通过率", f"{summary.get('pass_rate', 0):.0%}"),
                ("LLM 调用节省率", f"{prefilter.get('llm_call_savings_rate', 0):.0%}"),
                ("预筛自动关闭", prefilter.get("auto_close", 0)),
            ]
        )

        body = f"""
<section class="hero">
  <div class="card">
    <span class="tag">AI + Security Agent</span>
    <h1>安全事件初步研判与误报剔除</h1>
    <p class="lede">这个版本将原有 demo 包装成分阶段 Agent 流程：Monitor Agent 负责接收事件，Context Agent 负责补齐上下文，Triage Agent 负责初步研判与误报剔除，Report Agent 负责形成结构化输出和报告。</p>
    <div class="toolbar">
      <a class="btn btn-primary" href="/">查看全部事件</a>
      <a class="btn" href="/ledger">审计回放</a>
      <a class="btn" href="/api/config">查看配置 JSON</a>
    </div>
  </div>
  <div class="card">
    <h2>运行配置</h2>
    <div class="stats">
      <div class="stat"><strong>{len(events)}</strong>样例事件</div>
      <div class="stat"><strong>{"Real" if config["use_real_llm"] else "Mock"}</strong>模型模式</div>
      <div class="stat"><strong>{html.escape(config["llm_provider"])}</strong>当前后端</div>
      <div class="stat"><strong>{html.escape(config["llm_model"])}</strong>当前模型</div>
      <div class="stat"><strong>{"On" if config["command_tool_enabled"] else "Off"}</strong>命令工具</div>
    </div>
  </div>
</section>
<section class="metric-grid" style="margin-bottom: 18px;">
  {metric_cards}
</section>
<section class="card" style="margin-bottom: 18px;">
  {evaluation_panel}
</section>
<section class="grid">
  <div class="card">
    <h2>事件列表</h2>
    <div class="alert-list">{event_cards}</div>
  </div>
  <div class="card">
    {result_html}
  </div>
</section>
<section class="card" style="margin-top: 18px;">
  {upload_panel}
</section>
"""
        return _page("安全事件初步研判与误报剔除", body)

    def _render_upload_panel(self, submission_type: str, submitted_payload: str) -> str:
        json_selected = "selected" if submission_type == "json" else ""
        log_selected = "selected" if submission_type == "log" else ""
        sample_json = html.escape(
            submitted_payload
            or json.dumps(
                {
                    "title": "上传事件样例",
                    "severity": "medium",
                    "host": "UPLOAD-HOST",
                    "user": "alice",
                    "process": "powershell.exe",
                    "behavior": "PowerShell 执行脚本并发起外联",
                    "raw_log": "powershell.exe -EncodedCommand AAAA downloadstring payload",
                    "destination_domain": "example.test",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return f"""
<h2>上传事件 JSON / 日志文本</h2>
<p class="lede">选择本地 JSON 或日志文本文件后，浏览器会先读取内容并填入输入框，再由后端按临时事件进行研判，不会覆盖样例事件数据。</p>
<div class="toolbar">
  <input type="file" id="upload-file" accept=".json,.txt,.log">
</div>
<form method="post" action="/analyze-input">
  <div class="kv" style="margin-top: 16px;">
    <div>输入类型</div>
    <div>
      <select name="submission_type" style="padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: #1a2744; color: var(--ink);">
        <option value="json" {json_selected}>事件 JSON</option>
        <option value="log" {log_selected}>日志文本</option>
      </select>
    </div>
  </div>
  <textarea id="payload" name="payload" rows="14" style="width: 100%; border: 1px solid var(--line); border-radius: 16px; padding: 14px; font: 13px/1.5 Consolas, monospace; background: rgba(0,179,255,0.06);">{sample_json}</textarea>
  <div class="toolbar">
    <button class="btn btn-primary" type="submit">分析上传内容</button>
  </div>
</form>
<script>
  const input = document.getElementById('upload-file');
  const payload = document.getElementById('payload');
  input.addEventListener('change', (event) => {{
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {{
      payload.value = reader.result || '';
    }};
    reader.readAsText(file, 'utf-8');
  }});
</script>
"""

    def _render_evaluation_panel(self, evaluation: dict) -> str:
        summary = evaluation["summary"]
        categories = "".join(
            "<tr><td>{category}</td><td>{total}</td><td>{risk}</td><td>{fp}</td><td>{passed}</td></tr>".format(
                category=html.escape(item["category"]),
                total=item["total_cases"],
                risk=f'{item["risk_level_accuracy"]:.1%}',
                fp=f'{item["false_positive_accuracy"]:.1%}',
                passed=f'{item["pass_rate"]:.1%}',
            )
            for item in evaluation["category_breakdown"]
        )
        return f"""
<h2>评测面板</h2>
<p class="lede">基于内置的 10 个标准案例，自动统计风险分级、误报识别、事件类型和输出完整性指标，用于说明当前原型不是只依赖单个成功案例演示。</p>
<div class="metric-grid">
  <div class="metric-card"><strong>{summary["total_cases"]}</strong><span>评测案例数</span></div>
  <div class="metric-card"><strong>{summary["risk_level_accuracy"]:.1%}</strong><span>风险分级准确率</span></div>
  <div class="metric-card"><strong>{summary["false_positive_accuracy"]:.1%}</strong><span>误报识别准确率</span></div>
  <div class="metric-card"><strong>{summary["event_type_accuracy"]:.1%}</strong><span>事件类型准确率</span></div>
  <div class="metric-card"><strong>{summary["output_completeness"]:.1%}</strong><span>输出完整率</span></div>
  <div class="metric-card"><strong>{summary["avg_duration_ms"]} ms</strong><span>平均分析耗时</span></div>
</div>
{self._render_mode_comparison()}
<div class="toolbar">
  <a class="btn" href="/api/evaluation">查看评测 JSON</a>
</div>
<div class="result-block">
  <h3>分类结果</h3>
  <table class="table">
    <thead>
      <tr>
        <th>类别</th>
        <th>案例数</th>
        <th>风险分级</th>
        <th>误报识别</th>
        <th>综合通过率</th>
      </tr>
    </thead>
    <tbody>{categories}</tbody>
  </table>
</div>
"""

    def _render_event_card(self, event, active: bool) -> str:
        severity = event.severity.lower()
        style = (
            ' style="border-color: var(--accent); box-shadow: 0 10px 20px rgba(0,179,255,0.10);"'
            if active
            else ""
        )
        return (
            f'<a class="alert-item" href="/?event_id={html.escape(event.id)}"{style}>'
            f'<div><span class="sev sev-{severity}">{html.escape(event.severity)}</span></div>'
            f"<h3>{html.escape(event.title)}</h3>"
            f'<div class="meta">{html.escape(event.id)} | {html.escape(event.host)} | {html.escape(event.user)}</div>'
            "</a>"
        )

    def _render_result(self, result: dict | None, event, error: str | None) -> str:
        if error:
            return f"<h2>分析结果</h2><p>{html.escape(error)}</p>"
        if result is None or event is None:
            return (
                "<h2>分析结果</h2>"
                "<p class=\"lede\">从左侧选择一个安全事件。系统会通过分阶段 Agent 链路完成初步研判，并展示事件类型、风险等级、误报判断、工具观测和结构化输出。</p>"
            )

        evidence = "".join(f"<li>{html.escape(item)}</li>" for item in result["evidence"])
        recommendations = "".join(f"<li>{html.escape(item)}</li>" for item in result["recommendations"])
        hits = "".join(f"<li>{html.escape(item)}</li>" for item in result["knowledge_hits"])
        logs = "".join(f"<li>{html.escape(item)}</li>" for item in result["execution_log"])
        plans = "".join(
            f'<li data-step="{idx}">{html.escape(item)}</li>'
            for idx, item in enumerate(result["plan_steps"], start=1)
        )
        reasoning = "".join(
            f'<div class="trace-item">{html.escape(item)}</div>'
            for item in result["reasoning_summary"]
        )
        module_trace = "".join(
            f'<span class="module-badge">{html.escape(item)}</span>'
            for item in result["module_trace"]
        )
        phase_agents = "".join(
            self._render_phase_agent_card(item, idx)
            for idx, item in enumerate(result["phase_agents"], start=1)
        )
        observations = "".join(
            "<div class=\"obs-item\"><strong>{tool}</strong><ul>{details}</ul></div>".format(
                tool=html.escape(item["summary"]),
                details="".join(f"<li>{html.escape(detail)}</li>" for detail in item["details"]) or "<li>无</li>",
            )
            for item in result["tool_observations"]
        )
        raw = html.escape(json.dumps(result, ensure_ascii=False, indent=2))
        false_positive = "是" if result["is_false_positive"] else "否"

        # 阶段 2：HITL —— 优先读取复核回写记录，已人工复核则显示复核结果
        latest_review = self._latest_review(result["event_id"])
        review_banner = ""
        if latest_review is not None:
            note_html = f"<small>（{html.escape(latest_review.get('note', ''))}）</small>" if latest_review.get("note") else ""
            if latest_review.get("decision") == "confirm":
                review_banner = f'<div class="review-banner review-confirmed">✅ 已人工确认（事件成立）{note_html}</div>'
            else:
                review_banner = f'<div class="review-banner review-rejected">⛔ 已人工驳回（判定误报）{note_html}</div>'
        elif result.get("needs_human_review", False) or result.get("review_status") == "pending_review":
            review_banner = f"""
<div class="review-banner review-pending">
  ⚠️ <strong>待人工复核</strong>：本结果置信度低（{html.escape(result.get("confidence", ""))}），未自动处置，需人工确认。
  <form class="review-form" method="post" action="/review-event">
    <input type="hidden" name="event_id" value="{html.escape(result["event_id"])}">
    <input type="text" name="note" placeholder="复核意见（可选）">
    <button class="btn btn-primary" type="submit" name="decision" value="confirm">确认（事件成立）</button>
    <button class="btn" type="submit" name="decision" value="reject">驳回（判定误报）</button>
  </form>
</div>
"""

        export_block = ""
        if not str(result["event_id"]).startswith("UPLOAD-"):
            export_block = f"""
<div class="result-block">
  <h3>导出报告</h3>
  {self._render_export_controls(event_id=result["event_id"], submission_type="", payload="")}
</div>
"""

        return f"""
<h2>分析结果</h2>
{review_banner}
<div class="kv">
  <div>事件标题</div><div>{html.escape(event.title)}</div>
  <div>场景</div><div>{html.escape(result["scenario"])}</div>
  <div>事件类型</div><div>{html.escape(result["event_type"])}</div>
  <div>研判结论</div><div>{html.escape(result["verdict"])}</div>
  <div>风险等级</div><div>{html.escape(result["risk_level"])}</div>
  <div>置信度</div><div>{html.escape(result["confidence"])}（{result.get("confidence_score", 0.7)}）</div>
  <div>疑似误报</div><div>{false_positive}</div>
</div>
{self._render_decision_visual(result)}
<div class="result-block">
  <h3>四模块链路</h3>
  <div class="module-badges">{module_trace}</div>
</div>
<div class="result-block">
  <h3>分阶段 Agent 流程</h3>
  <div class="agent-flow">{phase_agents}</div>
</div>
<div class="result-block">
  <h3>任务规划</h3>
  <ol class="timeline">{plans}</ol>
</div>
<div class="result-block">
  <h3>推理摘要</h3>
  <div class="trace">{reasoning}</div>
</div>
<div class="result-block">
  <h3>工具观测</h3>
  <div class="obs-list">{observations}</div>
</div>
<div class="two-col">
  <div class="result-block">
    <h3>证据链</h3>
    <ul>{evidence}</ul>
  </div>
  <div class="result-block">
    <h3>处置建议</h3>
    <ul>{recommendations}</ul>
  </div>
</div>
<div class="two-col">
  <div class="result-block">
    <h3>知识命中</h3>
    <ul>{hits}</ul>
  </div>
  <div class="result-block">
    <h3>执行日志</h3>
    <ul>{logs}</ul>
  </div>
</div>
<div class="result-block">
  <h3>结构化输出</h3>
  <pre>{raw}</pre>
</div>
{export_block}
"""

    # ── 阶段 9.2：AI 决策可视化 ──────────────────────────
    def _render_decision_visual(self, result: dict) -> str:
        """展示 risk_score 数值条 + 置信度徽章 + 研判路径（预筛/LLM/规则回退）。"""
        risk_score = result.get("risk_score", 0) or 0
        risk_level = result.get("risk_level", "medium")
        confidence = result.get("confidence", "medium")
        confidence_score = result.get("confidence_score", 0.7)
        decision = result.get("prefilter_decision", "NEED_LLM")

        # 研判路径标签
        if decision in ("AUTO_CLOSE", "AUTO_ESCALATE"):
            path_badge = '<span class="tool-badge">⚡ 预筛直达（确定性规则）</span>'
        else:
            path_badge = '<span class="tool-badge">🤖 LLM 深度研判</span>'

        # 置信度颜色
        conf_class = {
            "high": "sev-low",
            "medium": "sev-medium",
            "low": "sev-high",
        }.get(confidence, "sev-medium")

        # risk_score 数值条（0-100）
        bar_width = max(0, min(100, int(risk_score)))
        score_bar = (
            '<div class="score-track"><div class="score-fill" style="width:{}%"></div></div>'
        ).format(bar_width)

        return f"""
<div class="result-block">
  <h3>AI 决策可视化</h3>
  <div class="score-row">
    <div class="score-label">risk_score</div>
    <div class="score-value">{risk_score}/100</div>
  </div>
  {score_bar}
  <div class="toolbar" style="margin-top: 10px;">
    <span class="sev {conf_class}">置信度: {confidence}（{confidence_score}）</span>
    {path_badge}
    <span class="sev sev-{risk_level}">风险: {risk_level}</span>
  </div>
</div>
"""

    def _render_phase_agent_card(self, agent: dict, index: int) -> str:
        tool_badges = ""
        if agent["used_tools"]:
            tool_badges = "<div class=\"tool-badges\">{}</div>".format(
                "".join(
                    f'<span class="tool-badge">{html.escape(tool)}</span>'
                    for tool in agent["used_tools"]
                )
            )
        outputs = "".join(f"<li>{html.escape(item)}</li>" for item in agent["outputs"])
        return f"""
<div class="agent-stage">
  <div class="agent-stage-head">
    <div>
      <div class="agent-kicker">Phase Agent</div>
      <h3>{html.escape(agent["name"])}</h3>
      <p class="agent-role">{html.escape(agent["role"])}</p>
    </div>
    <div class="agent-index">{index}</div>
  </div>
  <div class="agent-focus">{html.escape(agent["focus"])}</div>
  <div>
    <p class="agent-subtitle">使用工具</p>
    {tool_badges or '<span class="tool-badge">无</span>'}
  </div>
  <div>
    <p class="agent-subtitle">阶段输出</p>
    <ul>{outputs}</ul>
  </div>
</div>
"""

    def _handle_submission(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)
        submission_type = form.get("submission_type", ["json"])[0]
        payload = form.get("payload", [""])[0]
        app = build_app()
        try:
            result = app.triage_submission(payload=payload, source_type=submission_type).to_dict()
            event_stub = type("SubmittedEvent", (), {"title": "上传内容分析结果"})()
            content = self._render_result(result, event_stub, None)
            body = f"""
<section class="hero">
  <div class="card">
    <span class="tag">Upload Analysis</span>
    <h1>上传内容分析结果</h1>
    <p class="lede">本次分析基于临时提交的事件 JSON 或日志文本生成，不会写回样例数据集。</p>
    <div class="toolbar">
      <a class="btn btn-primary" href="/">返回首页</a>
    </div>
  </div>
</section>
<section class="card">
  {content}
</section>
<section class="card" style="margin-top: 18px;">
  <h2>导出报告</h2>
  {self._render_export_controls('', submission_type, payload)}
</section>
<section class="card" style="margin-top: 18px;">
  {self._render_upload_panel(submission_type, payload)}
</section>
"""
            self._send_html(_page("上传内容分析结果", body))
        except Exception as exc:
            query = {
                "submission_type": [submission_type],
                "payload": [payload],
            }
            page = self._render_home(query).decode("utf-8")
            page = page.replace(
                '<section class="card" style="margin-top: 18px;">',
                f'<section class="card" style="margin-top: 18px;"><p>{html.escape(str(exc))}</p>',
                1,
            )
            self._send_html(page.encode("utf-8"))

    def _render_export_controls(self, event_id: str, submission_type: str, payload: str) -> str:
        hidden = []
        if event_id:
            hidden.append(f'<input type="hidden" name="event_id" value="{html.escape(event_id)}">')
        if submission_type:
            hidden.append(
                f'<input type="hidden" name="submission_type" value="{html.escape(submission_type)}">'
            )
        if payload:
            hidden.append(f'<input type="hidden" name="payload" value="{html.escape(payload)}">')
        hidden_inputs = "".join(hidden)
        return f"""
<div class="toolbar">
  <form method="post" action="/export-report">
    {hidden_inputs}
    <input type="hidden" name="format" value="md">
    <button class="btn btn-primary" type="submit">导出 Markdown</button>
  </form>
  <form method="post" action="/export-report">
    {hidden_inputs}
    <input type="hidden" name="format" value="json">
    <button class="btn" type="submit">导出 JSON</button>
  </form>
</div>
"""

    def _handle_export(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)
        export_format = form.get("format", ["md"])[0]
        event_id = form.get("event_id", [""])[0]
        submission_type = form.get("submission_type", [""])[0]
        payload = form.get("payload", [""])[0]
        app = build_app()

        if event_id:
            result = app.triage_event(event_id).to_dict()
        else:
            result = app.triage_submission(payload=payload, source_type=submission_type).to_dict()

        if export_format == "json":
            filename = f"{result['event_id']}_report.json"
            content = json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")
            self._send_download(content, "application/json; charset=utf-8", filename)
            return

        filename = f"{result['event_id']}_report.md"
        content = render_markdown_report(result).encode("utf-8")
        self._send_download(content, "text/markdown; charset=utf-8", filename)

    def _send_download(self, body: bytes, content_type: str, filename: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _config_payload(self) -> dict:
        config = AppConfig.from_env()
        return {
            "use_real_llm": config.use_real_llm,
            "llm_provider": config.llm_provider,
            "llm_base_url": config.llm_base_url,
            "llm_model": config.llm_model,
            "llm_timeout_seconds": config.llm_timeout_seconds,
            "command_tool_enabled": config.command_tool_enabled,
        }

    def _send_html(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "127.0.0.1", port: int = 8080):
    server = ThreadingHTTPServer((host, port), SecurityAgentHandler)
    print(f"Serving security agent demo at http://{host}:{port}")
    server.serve_forever()
