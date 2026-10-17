# XH-202609 Security-Agent 部署镜像
# 说明：项目运行零重依赖——代码仅可选 import httpx（真实 LLM 调用用）。
# pyproject.toml 中声明的 langchain/openai 为历史遗留、实际代码未引用，部署时不安装，避免镜像臃肿与装崩。
FROM python:3.13-slim

WORKDIR /app

# 仅复制运行必需文件（含源代码与数据）
COPY . .

# 唯一运行时依赖：httpx（缺失时自动回退规则引擎 / Mock 模式，仍可零依赖运行）
RUN pip install --no-cache-dir httpx

EXPOSE 8080

# 容器化需绑定 0.0.0.0 才能被宿主机/外部访问
CMD ["python", "-m", "security_agent.cli", "serve", "--host", "0.0.0.0", "--port", "8080"]
