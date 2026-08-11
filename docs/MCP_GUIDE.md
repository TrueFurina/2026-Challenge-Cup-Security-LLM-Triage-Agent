# 🔌 MCP 接入指南（阶段 7）

> **说明**：Security-Agent 通过 stdio + JSON-RPC 2.0 暴露 MCP 服务，标准 MCP client（Claude Desktop、自研 agent 等）可直接发现并调用安全工具。

## 快速启动

```bash
python -m security_agent.cli serve-mcp
```

启动后从 stdin 逐行读取 JSON-RPC 请求，处理结果写回 stdout。

## 协议方法

| 方法 | 说明 |
|------|------|
| `initialize` | 协议握手（protocolVersion: 2024-11-05，capabilities.tools） |
| `tools/list` | 返回工具清单（从 ToolRegistry 动态生成） |
| `tools/call` | 调用指定工具（name + arguments） |

## 工具清单（10 个）

| 工具 | 用途 |
|------|------|
| `asset_lookup` | 资产画像查询 |
| `log_lookup` | 关联日志查询 |
| `intel_lookup` | 威胁情报查询 |
| `history_alert_lookup` | 历史告警查询 |
| `false_positive_check` | 误报线索检查 |
| `incident_triage` | 事件研判（AI + 规则回退） |
| `playbook_matcher` | 处置预案匹配 |
| `ticket_generator` | 工单生成 |
| `host_isolation_simulator` | 主机隔离动作模拟 |
| `ioc_search` | IOC 情报搜索 |

## 请求/响应示例

```json
// 请求：发现工具
{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

// 响应
{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "asset_lookup", "description": "...", "inputSchema": {...}}, ...]}}

// 请求：调用工具
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ioc_search", "arguments": {"event": {"destination_ip": "203.0.113.50"}}}}

// 响应
{"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "[{\"indicator\": ...}]"}], "isError": false}}
```

## 接入 Claude / GPT / 自研 Agent

### Claude Desktop
在 Claude Desktop 配置中添加 MCP server（stdio 类型），command 指向：
```
python -m security_agent.cli serve-mcp
```
启动目录需为项目根目录（`E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体`）。

### 自研 Agent（Python 示例）

```python
import json
import subprocess

proc = subprocess.Popen(
    ["python", "-m", "security_agent.cli", "serve-mcp"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
)

def rpc(method, params=None, req_id=1):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params:
        msg["params"] = params
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

tools = rpc("tools/list")          # 发现工具
result = rpc("tools/call", {"name": "ioc_search", "arguments": {}}, 2)
print(result)
```

## 设计说明

- **纯标准库实现**：不依赖 `mcp` python 包，`pip install` 失败不影响主流程
- **动态注册**：新增工具无需改 MCP 层，`tools/list` 自动发现
- **fail-open**：未知工具/执行异常均返回 `isError`，进程不退出
