"""Python 语法兼容性调试脚本"""
import sys
import os
import subprocess

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_DIR)
sys.path.insert(0, PROJECT_DIR)

# Test if Python has issues with implicit string concat + CSS-like content
tests = [
    ('simple implicit concat', "x = ('a' 'b'); assert x == 'ab'"),
    ('concat with + inside ()', "x = ('a' + 'b' + 'c'); assert x == 'abc'"),
    ('implicit + explicit mixed', "x = ('a' 'b' + 'c'); assert x == 'abc'"),
    ('180deg in string', "x = '180deg'; assert x == '180deg'"),
    ('1px in string', "x = '1px solid'; assert x == '1px solid'"),
    ('linear-gradient in string', "x = 'linear-gradient(180deg,#fff,#000)'; assert '180deg' in x"),
    ('mixed with gradient',
     "x = ('<div style=\"background:linear-gradient(180deg,#fff,#000)\">' "
     "'more'); assert '180deg' in x and 'more' in x"),
]

for name, code in tests:
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"{'OK' if ok else 'FAIL'} {name}: {r.stderr.strip() if r.stderr else ''}")

print("\n--- Now testing the actual file ---")
r = subprocess.run(
    [sys.executable, "-c", "import py_compile; py_compile.compile(r'security_agent/web/server.py', doraise=True)"],
    capture_output=True, text=True, cwd=PROJECT_DIR,
)
print(f"server.py compile: {'OK' if r.returncode == 0 else 'FAIL'}")
if r.stderr:
    print(r.stderr)

# Try to import the module
r = subprocess.run(
    [sys.executable, "-c", "from security_agent.web.server import run_server; print('Import OK')"],
    capture_output=True, text=True, cwd=PROJECT_DIR,
)
print(f"Import: {'OK' if r.returncode == 0 else 'FAIL'}")
if r.stderr:
    print(r.stderr[-500:] if len(r.stderr) > 500 else r.stderr)
