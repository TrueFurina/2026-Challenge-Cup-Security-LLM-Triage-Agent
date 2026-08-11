"""
启动 Web 演示界面
用法:
    python scripts/run_web.py                    # 交互式（按 Enter 停止）
    python scripts/run_web.py --bg               # 后台静默启动
    python scripts/run_web.py --host 0.0.0.0     # 指定主机
    python scripts/run_web.py --port 9090        # 指定端口
"""
import argparse
import os
import subprocess
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_interactive(host: str, port: int):
    """交互式启动，按 Enter 停止"""
    print(f"Starting Web UI at http://{host}:{port}")
    print("Press Enter to stop the server...")
    p = subprocess.Popen(
        [sys.executable, "-m", "security_agent.cli", "serve", "--host", host, "--port", str(port)],
        cwd=PROJECT_DIR,
    )
    input()
    p.terminate()
    print("Server stopped")


def run_background(host: str, port: int, silent: bool = False):
    """后台静默启动"""
    kwargs: dict = {"cwd": PROJECT_DIR}
    if silent:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen(
        [sys.executable, "-m", "security_agent.cli", "serve", "--host", host, "--port", str(port)],
        **kwargs,
    )
    if not silent:
        print(f"Server started on http://{host}:{port} (PID: {p.pid})")


def main():
    parser = argparse.ArgumentParser(description="启动安全事件研判智能体 Web 界面")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", default=8080, type=int, help="监听端口 (默认 8080)")
    parser.add_argument("--bg", action="store_true", help="后台静默启动（不阻塞）")
    parser.add_argument("--silent", action="store_true", help="完全静默（无输出，需配合 --bg）")
    args = parser.parse_args()

    if args.bg:
        run_background(args.host, args.port, silent=args.silent)
    else:
        run_interactive(args.host, args.port)


if __name__ == "__main__":
    main()
