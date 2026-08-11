import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from security_agent.app import build_app
from security_agent.config import AppConfig
from security_agent.reporting.render import render_evaluation_report
from security_agent.web.server import run_server


def cmd_list_events() -> int:
    app = build_app()
    for item in app.list_events():
        print(f"{item.id}: {item.title} [{item.severity}]")
    return 0


def cmd_analyze(event_id: str) -> int:
    app = build_app()
    result = app.triage_event(event_id)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_coordinate(event_id: str) -> int:
    """阶段 3：多 Agent 顺序协作（Triage → Hunt → Respond → Report）。"""
    app = build_app()
    report = app.coordinate_event(event_id)
    print(f"=== 多 Agent 协作链路（{event_id}） ===")
    for record in report["agent_records"]:
        status = "⚠️ 降级" if record["error"] else "✅"
        print(f"\n[{status}] {record['name']}（{record['role']}） {record['duration_ms']}ms")
        if record["used_tools"]:
            print(f"  工具: {', '.join(record['used_tools'])}")
        for finding in record["findings"]:
            print(f"  - {finding}")
    print(f"\n=== 最终报告 ===")
    final = report["final_report"]
    for key in ("event_id", "event_type", "risk_level", "confidence", "is_false_positive", "verdict"):
        if key in final:
            print(f"  {key}: {final[key]}")
    print(f"\n总耗时: {report['total_duration_ms']}ms | 全部 Agent 正常: {report['agents_ok']}")
    return 0


def cmd_config() -> int:
    config = AppConfig.from_env()
    print(
        json.dumps(
            {
                "use_real_llm": config.use_real_llm,
                "llm_provider": config.llm_provider,
                "llm_base_url": config.llm_base_url,
                "llm_model": config.llm_model,
                "llm_timeout_seconds": config.llm_timeout_seconds,
                "command_tool_enabled": config.command_tool_enabled,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_clear_memory() -> int:
    """清空误报记忆（阶段 6.3）。"""
    from security_agent.memory import MemoryStore

    store = MemoryStore()
    removed = store.clear()
    print(f"已清空误报记忆，删除 {removed} 条历史研判记录。")
    return 0


def cmd_evaluate() -> int:
    app = build_app()
    report = app.evaluate_cases()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def cmd_report(fmt: str) -> int:
    """导出评测报告（Markdown/HTML，含三模式对比 + 混淆矩阵）。"""
    app = build_app()
    evaluation = app.evaluation_service.evaluate_modes(app)
    content = render_evaluation_report(evaluation, fmt=fmt)

    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "html":
        filename = reports_dir / f"evaluation_{ts}.html"
    else:
        filename = reports_dir / f"evaluation_{ts}.md"
    filename.write_text(content, encoding="utf-8")
    print(f"评测报告已导出: {filename}")
    return 0


def cmd_serve(host: str, port: int) -> int:
    run_server(host=host, port=port)
    return 0


def cmd_serve_mcp() -> int:
    """启动 MCP server（stdio，阶段 7 前沿加分项）。"""
    from security_agent.app import build_app
    from security_agent.config import AppConfig
    from security_agent.mcp import McpServer

    config = AppConfig.from_env()
    app = build_app()
    server = McpServer(tool_registry=app.tool_registry)
    print(f"MCP server 启动（{len(app.tool_registry.tools)} 个工具），等待 stdio 请求...", file=sys.stderr)
    server.serve_stdio()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="安全事件初步研判与误报剔除智能体 Demo"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-events", help="列出样例安全事件")
    list_parser.set_defaults(handler=lambda args: cmd_list_events())

    analyze_parser = subparsers.add_parser("analyze", help="分析指定安全事件")
    analyze_parser.add_argument("--event-id", required=True, help="安全事件 ID")
    analyze_parser.set_defaults(handler=lambda args: cmd_analyze(args.event_id))

    coordinate_parser = subparsers.add_parser(
        "coordinate", help="多 Agent 顺序协作（Triage → Hunt → Respond → Report）"
    )
    coordinate_parser.add_argument("--event-id", required=True, help="安全事件 ID")
    coordinate_parser.set_defaults(handler=lambda args: cmd_coordinate(args.event_id))

    config_parser = subparsers.add_parser("config", help="查看当前配置")
    config_parser.set_defaults(handler=lambda args: cmd_config())

    clear_memory_parser = subparsers.add_parser("clear-memory", help="清空误报记忆（阶段 6.3）")
    clear_memory_parser.set_defaults(handler=lambda args: cmd_clear_memory())

    evaluate_parser = subparsers.add_parser("evaluate", help="运行内置案例评测")
    evaluate_parser.set_defaults(handler=lambda args: cmd_evaluate())

    report_parser = subparsers.add_parser("report", help="导出评测报告（三模式对比 + 混淆矩阵）")
    report_parser.add_argument(
        "--format",
        default="md",
        choices=["md", "html"],
        help="报告格式（默认 md）",
    )
    report_parser.set_defaults(handler=lambda args: cmd_report(args.format))

    serve_parser = subparsers.add_parser("serve", help="启动本地 Web 演示界面")
    serve_parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    serve_parser.add_argument("--port", default=8080, type=int, help="监听端口")
    serve_parser.set_defaults(handler=lambda args: cmd_serve(args.host, args.port))

    serve_mcp_parser = subparsers.add_parser("serve-mcp", help="启动 MCP server（stdio，阶段 7）")
    serve_mcp_parser.set_defaults(handler=lambda args: cmd_serve_mcp())

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
