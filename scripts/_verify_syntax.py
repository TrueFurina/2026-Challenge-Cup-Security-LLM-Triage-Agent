"""验证所有 Python 文件语法"""
import sys
import os
import py_compile
import glob

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from security_agent.console import use_utf8_stdio  # noqa: E402
use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩

files = glob.glob(os.path.join(PROJECT_DIR, "security_agent", "**", "*.py"), recursive=True)
ok = 0
fail = 0
for f in sorted(files):
    rel = os.path.relpath(f, PROJECT_DIR)
    try:
        py_compile.compile(f, doraise=True)
        print(f"  OK  {rel}")
        ok += 1
    except py_compile.PyCompileError as e:
        print(f"  FAIL {rel}: {e}")
        fail += 1

print(f"\n=== {ok} passed, {fail} failed ===")
sys.exit(1 if fail else 0)
