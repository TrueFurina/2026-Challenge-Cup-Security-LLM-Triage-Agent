import json


def render_evaluation_report(evaluation: dict, fmt: str = "md") -> str:
    """渲染评测报告（三模式对比 + 混淆矩阵 + 逐案例明细）。

    Args:
        evaluation: EvaluationService.evaluate_modes() 或 evaluate() 返回的 dict。
        fmt: "md"（Markdown）或 "html"。
    """
    if fmt == "html":
        return _render_evaluation_html(evaluation)
    return _render_evaluation_markdown(evaluation)


def _mode_table_markdown(modes: dict) -> str:
    """三模式对比表（Markdown）。"""
    if not modes:
        return "_未提供模式对比数据_"
    keys = [
        "pass_rate",
        "risk_level_accuracy",
        "false_positive_accuracy",
        "event_type_accuracy",
        "avg_duration_ms",
        "cost_estimate",
        "llm_calls",
    ]
    labels = {
        "pass_rate": "综合通过率",
        "risk_level_accuracy": "风险分级准确率",
        "false_positive_accuracy": "误报识别准确率",
        "event_type_accuracy": "事件类型准确率",
        "avg_duration_ms": "平均耗时(ms)",
        "cost_estimate": "成本估算(元)",
        "llm_calls": "LLM 调用次数",
    }
    header = "| 指标 | " + " | ".join(modes.keys()) + " |"
    sep = "|------|" + "------|" * len(modes)
    rows = [header, sep]
    for key in keys:
        cells = []
        for mode in modes.values():
            value = mode.get(key, "")
            if isinstance(value, float):
                value = round(value, 3)
            cells.append(str(value))
        rows.append(f"| {labels.get(key, key)} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def _confusion_markdown(case_results: list[dict]) -> str:
    """误报判定混淆矩阵（2×2，Markdown）。"""
    matrix = {
        (True, True): 0,   # 预期误报 & 判定误报（TP）
        (True, False): 0,  # 预期误报 & 判定非误报（FN）
        (False, True): 0,  # 预期非误报 & 判定误报（FP）
        (False, False): 0,  # 预期非误报 & 判定非误报（TN）
    }
    for item in case_results:
        key = (item["expected_false_positive"], item["actual_false_positive"])
        matrix[key] += 1
    return (
        "| 实际 \\ 预期 | 预期误报 | 预期非误报 |\n"
        "|------------|---------|-----------|\n"
        f"| 判定误报   | {matrix[(True, True)]} | {matrix[(False, True)]} |\n"
        f"| 判定非误报 | {matrix[(True, False)]} | {matrix[(False, False)]} |"
    )


def _render_evaluation_markdown(evaluation: dict) -> str:
    lines: list[str] = ["# 评测报告", ""]

    # 模式对比
    if "modes" in evaluation:
        lines.append("## 三模式对比（纯规则 / 纯 LLM / 混合）")
        lines.append("")
        lines.append(_mode_table_markdown(evaluation["modes"]))
        lines.append("")
    else:
        lines.append("## 评测汇总")
        lines.append("")
        summary = evaluation.get("summary", {})
        for key, value in summary.items():
            lines.append(f"- {key}: {value}")
        lines.append("")

    # 逐案例明细
    cases = evaluation.get("cases", [])
    if cases:
        lines.append("## 逐案例明细")
        lines.append("")
        lines.append("| 案例 | 预筛决策 | 实际风险 | 预期风险 | 误报判定 | 事件类型匹配 |")
        lines.append("|------|---------|---------|---------|---------|-------------|")
        for item in cases:
            lines.append(
                f"| {item['event_id']} | {item.get('prefilter_decision', '-')} | "
                f"{item['actual_risk_level']} | {item['expected_risk_level']} | "
                f"{'是' if item['actual_false_positive'] else '否'} | "
                f"{'✅' if item['event_type_match'] else '❌'} |"
            )
        lines.append("")
        lines.append("## 误报判定混淆矩阵")
        lines.append("")
        lines.append(_confusion_markdown(cases))
        lines.append("")

    return "\n".join(lines)


def _render_evaluation_html(evaluation: dict) -> str:
    """评测报告（HTML，含表格样式）。"""
    md = _render_evaluation_markdown(evaluation)
    import html as html_mod

    def md_table_to_html(md_text: str) -> str:
        # 简单转换 Markdown 表格 → HTML table
        rows_html = []
        for line in md_text.splitlines():
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                tag = "th" if any("-" in c and set(c) <= {"-", ":"} for c in cells) else "td"
                rows_html.append(
                    "<tr>" + "".join(f"<{tag}>{html_mod.escape(c)}</{tag}>" for c in cells) + "</tr>"
                )
        return "<table>" + "".join(rows_html) + "</table>"

    body_parts = []
    for block in md.split("## "):
        if not block.strip():
            continue
        lines = block.strip().splitlines()
        title = lines[0].strip()
        rest = "\n".join(lines[1:]).strip()
        body_parts.append(f"<h2>{html_mod.escape(title)}</h2>")
        if rest:
            if rest.startswith("|"):
                body_parts.append(md_table_to_html(rest))
            else:
                body_parts.append(f"<pre>{html_mod.escape(rest)}</pre>")

    doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>评测报告</title>
  <style>
    body {{ font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; margin: 32px; color: #1b1e23; }}
    table {{ border-collapse: collapse; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #d9d1c3; padding: 8px 12px; text-align: left; }}
    th {{ background: #f3efe5; }}
    h2 {{ margin-top: 28px; color: #0e6ba8; }}
    pre {{ background: #161a20; color: #e8ecf3; padding: 14px; border-radius: 10px; overflow: auto; }}
  </style>
</head>
<body>
  <h1>安全事件智能体评测报告</h1>
  {''.join(body_parts)}
</body>
</html>"""
    return doc


def render_markdown_report(result: dict) -> str:
    lines: list[str] = [
        "# 安全事件研判报告",
        "",
        "## 基本信息",
        "",
        f"- 事件 ID: {result['event_id']}",
        f"- 场景: {result['scenario']}",
        f"- 事件类型: {result['event_type']}",
        f"- 风险等级: {result['risk_level']}",
        f"- 置信度: {result['confidence']}",
        f"- 疑似误报: {'是' if result['is_false_positive'] else '否'}",
        f"- 研判结论: {result['verdict']}",
        "",
        "## 四模块链路",
        "",
    ]
    lines.extend([f"- {item}" for item in result["module_trace"]])
    lines.extend(["", "## 分阶段 Agent 流程", ""])
    for agent in result["phase_agents"]:
        lines.append(f"### {agent['name']}")
        lines.append(f"- 角色: {agent['role']}")
        lines.append(f"- 关注点: {agent['focus']}")
        if agent["used_tools"]:
            lines.append(f"- 使用工具: {', '.join(agent['used_tools'])}")
        if agent["outputs"]:
            lines.extend([f"- 输出: {item}" for item in agent["outputs"]])
        lines.append("")
    lines.extend(["## 任务规划", ""])
    lines.extend([f"{idx}. {item}" for idx, item in enumerate(result["plan_steps"], start=1)])
    lines.extend(["", "## 推理摘要", ""])
    lines.extend([f"- {item}" for item in result["reasoning_summary"]])
    lines.extend(["", "## 证据链", ""])
    lines.extend([f"- {item}" for item in result["evidence"]])
    lines.extend(["", "## 处置建议", ""])
    lines.extend([f"- {item}" for item in result["recommendations"]])
    lines.extend(["", "## 知识命中", ""])
    lines.extend([f"- {item}" for item in result["knowledge_hits"]])
    lines.extend(["", "## 工具观测", ""])
    for item in result["tool_observations"]:
        lines.append(f"### {item['tool_name']}")
        lines.append(f"- 摘要: {item['summary']}")
        if item["details"]:
            lines.extend([f"- {detail}" for detail in item["details"]])
        lines.append("")
    lines.extend(["## 执行日志", ""])
    lines.extend([f"- {item}" for item in result["execution_log"]])
    lines.extend(
        [
            "",
            "## 结构化结果",
            "",
            "```json",
            json.dumps(result, ensure_ascii=False, indent=2),
            "```",
            "",
        ]
    )
    return "\n".join(lines)
