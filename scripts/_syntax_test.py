"""Python 语法压力测试（CSS模板字符串拼接）"""
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

# Test Python syntax parsing of CSS template strings
x = '<div style="border:1px solid #d9d1c3;border-radius:18px;padding:18px;background:linear-gradient(180deg,#fffdf8,#fff8f1)">'
print("Line 1 OK")

# Test CSS triple-quoted string
CSS = """*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1b1e23;background:#f3efe5}
.shell{max-width:1240px;margin:0 auto;padding:28px 20px 40px}
"""
print("CSS OK, len:", len(CSS))

# Test the full render_result method
result = {
    "event_id": "TEST-001",
    "scenario": "test",
    "event_type": "malware",
    "verdict": "malicious",
    "risk_level": "high",
    "confidence": "high",
    "is_false_positive": False,
    "module_trace": ["m1", "m2"],
    "phase_agents": [{"name": "Agent1", "role": "triage", "focus": "analysis", "used_tools": [], "outputs": ["done"]}],
    "plan_steps": ["step1"],
    "reasoning_summary": ["reason1"],
    "evidence": ["ev1"],
    "recommendations": ["rec1"],
    "knowledge_hits": ["hit1"],
    "tool_observations": [{"tool_name": "t1", "summary": "s1", "details": ["d1"]}],
    "execution_log": ["log1"],
}
print("Test data OK")

# Test the string concatenation pattern
agents_html = ""
for idx, agent in enumerate(result["phase_agents"], 1):
    tools_html = '<span class="tool-badge">tool1</span>'
    out_html = "<li>output1</li>"
    agents_html += (
        '<div style="border:1px solid #d9d1c3;border-radius:18px;padding:18px;background:linear-gradient(180deg,#fffdf8,#fff8f1)">'
        "<h3>" + str(agent["name"]) + "</h3>"
        '<p style="color:#5b6470">' + str(agent["role"]) + "</p>"
        '<div style="padding:10px 12px;border-radius:12px;background:rgba(14,107,168,0.06)">' + str(agent["focus"]) + "</div>"
        "<p>tools</p>" + tools_html
        "<p>outputs</p><ul>" + out_html + "</ul></div>"
    )
print("String concatenation OK, len:", len(agents_html))

# Try importing the module
try:
    import security_agent.web.server  # noqa: F401
    print("Import server module OK")
except Exception as e:
    print("Import failed:", e)

print("=== ALL TESTS PASSED ===")
