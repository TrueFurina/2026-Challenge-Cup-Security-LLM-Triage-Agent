# 使用说明

> **版本**：v2.0（修正路径 + 加入 AI 模块 / 本地微调说明）

## 运行环境

当前项目使用 Python 运行，核心功能不依赖第三方库。AI 研判引擎依赖 `httpx`（可选，缺失时自动降级为规则引擎）。

建议在项目根目录下执行命令：

```powershell
cd E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体
```

## 启动 Web 界面

```powershell
python -m security_agent.cli serve --port 8080
```

然后在浏览器中打开：

```text
http://127.0.0.1:8080
```

如果 `8080` 被占用，可以改成其他端口：

```powershell
python -m security_agent.cli serve --port 8090
```

## CLI 使用方式

### 查看样例事件

```powershell
python -m security_agent.cli list-events
```

### 分析指定事件

```powershell
python -m security_agent.cli analyze --event-id EVENT-001
python -m security_agent.cli analyze --event-id EVENT-002
python -m security_agent.cli analyze --event-id EVENT-003
```

### 查看当前配置

```powershell
python -m security_agent.cli config
```

### 运行评测

```powershell
python -m security_agent.cli evaluate
```

### 语法检查

```powershell
python scripts/_verify_syntax.py
```

---

## ★ 使用 AI 研判引擎（DeepSeek）

> **注意**：AI 研判引擎优先读取 `DEEPSEEK_API_KEY` 环境变量，本机已配置。未配置时自动回退规则引擎（fail-open）。

### 方法 A：环境变量

```powershell
# PowerShell
$env:DEEPSEEK_API_KEY="your_deepseek_api_key"
python -m security_agent.cli analyze --event-id EVENT-001
```

### 方法 B：永久设置

```powershell
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', 'your_key', 'User')
# 重启终端生效
```

### 切换其他模型

```powershell
$env:DEEPSEEK_API_KEY=""
$env:SECURITY_AGENT_LLM_API_KEY="your_dashscope_key"
$env:SECURITY_AGENT_LLM_PROVIDER="qwen"
$env:SECURITY_AGENT_LLM_MODEL="qwen-plus"
python -m security_agent.cli analyze --event-id EVENT-001
```

### 完全离线（Mock / 规则引擎）

```powershell
# 不设置任何 API Key，系统自动用 MockLLM + 规则引擎
python -m security_agent.cli analyze --event-id EVENT-001
```

---

## Web 页面如何输入

### 1. 分析内置样例事件

- 打开首页
- 在左侧选择一个事件
- 页面右侧会展示分析结果

### 2. 分析上传内容

- 在页面下方找到"上传事件 JSON / 日志文本"
- 选择本地 `.json`、`.txt` 或 `.log` 文件
- 浏览器会把内容自动读入文本框
- 点击"分析上传内容"

### 3. 导出报告

在分析结果页中可以直接导出：

- `Markdown`
- `JSON`

---

## 环境变量参考

| 变量 | 说明 | 默认 |
|------|------|------|
| `DEEPSEEK_API_KEY` | DeepSeek 密钥（AI 引擎主用） | 无 |
| `SECURITY_AGENT_LLM_API_KEY` | 通用 LLM 密钥（回退） | 无 |
| `SECURITY_AGENT_LLM_PROVIDER` | `deepseek` / `qwen` / `generic` | deepseek |
| `SECURITY_AGENT_LLM_BASE_URL` | 自定义端点 | 提供商默认 |
| `SECURITY_AGENT_LLM_MODEL` | 模型名 | 提供商默认 |
| `SECURITY_AGENT_LLM_TIMEOUT` | 超时秒数 | 45 |
| `SECURITY_AGENT_ENABLE_COMMAND_TOOL` | 启用命令工具 | 0 |

## 常见问题

### 页面打不开

- 确认命令行中服务已经启动
- 检查端口是否被占用
- 更换端口重新启动

### 启用真实模型时报错

常见原因：

- 没有设置 `DEEPSEEK_API_KEY` 或 `SECURITY_AGENT_LLM_API_KEY`
- 请求地址或模型名称配置错误
- 网络不可达（此时自动回退规则引擎，不崩溃）

### 分析结果没有变化

如果当前没有配置 API Key，系统使用规则引擎/Mock，不是实时联网模型。配置 `DEEPSEEK_API_KEY` 后重启命令即可启用 AI 研判。
