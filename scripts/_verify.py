"""快速验证脚本：列出事件、分析 EVENT-001、运行评测"""
import subprocess
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_DIR)
sys.path.insert(0, PROJECT_DIR)

print("=== List Events ===")
r = subprocess.run(
    [sys.executable, "-m", "security_agent.cli", "list-events"],
    capture_output=True, text=True, cwd=PROJECT_DIR,
)
print(r.stdout)
if r.stderr:
    print("ERR:", r.stderr[-300:] if len(r.stderr) > 300 else r.stderr)

print("=== Analyze EVENT-001 ===")
r = subprocess.run(
    [sys.executable, "-m", "security_agent.cli", "analyze", "--event-id", "EVENT-001"],
    capture_output=True, text=True, timeout=30, cwd=PROJECT_DIR,
)
out = r.stdout
if len(out) > 2000:
    print(out[:1000] + "\n... (truncated) ...\n" + out[-500:])
else:
    print(out)
if r.stderr:
    print("ERR:", r.stderr[-300:] if len(r.stderr) > 300 else r.stderr)

print("=== Evaluate ===")
r = subprocess.run(
    [sys.executable, "-m", "security_agent.cli", "evaluate"],
    capture_output=True, text=True, timeout=60, cwd=PROJECT_DIR,
)
out2 = r.stdout
if len(out2) > 1000:
    print(out2[:800] + "\n... (truncated) ...\n" + out2[-300:])
else:
    print(out2)
if r.stderr:
    print("ERR:", r.stderr[-300:] if len(r.stderr) > 300 else r.stderr)

print("=== DONE ===")
