"""依赖安装脚本"""
import subprocess
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_DIR)
print("Working dir:", os.getcwd())

pkgs = ["langchain", "langchain-openai", "langchain-community", "openai"]
cmd = [sys.executable, "-m", "pip", "install"] + pkgs + ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"]
print("Installing:", " ".join(pkgs))
r = subprocess.run(cmd, capture_output=True, text=True)
print(r.stdout[-500:] if len(r.stdout) > 500 else r.stdout)
if r.stderr:
    print("STDERR:", r.stderr[-500:] if len(r.stderr) > 500 else r.stderr)
print("Exit code:", r.returncode)
