"""统一 LLM 客户端封装。

支持 DeepSeek（默认主用）、Qwen 与通用 OpenAI 兼容端点。
设计遵循失败开放（fail-open）原则：任何错误（未配置密钥、网络异常、
HTTP 错误、响应格式异常）都返回 None，绝不向上抛出异常，
由调用方决定回退到规则引擎或默认结果。

密钥解析优先级：
    1. 环境变量 DEEPSEEK_API_KEY（DeepSeek 主用）
    2. 环境变量 SECURITY_AGENT_LLM_API_KEY（通用）
    3. 回退到现有 AppConfig（security_agent.config）中的配置
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

try:  # httpx 为可选依赖，缺失时 AI 能力自动降级为不可用
    import httpx
except ImportError:  # pragma: no cover - 依赖缺失的兜底路径
    httpx = None

from security_agent.config import AppConfig, _resolve_provider_defaults

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 45
CONNECT_TIMEOUT_SECONDS = 10.0


# ── 对外核心 API ──────────────────────────────────────────


def ai_chat(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    on_llm_call: Optional[Callable[[str, Optional[str]], None]] = None,
) -> Optional[str]:
    """调用统一 LLM 端点，返回模型回复文本（失败开放）。

    Args:
        messages: OpenAI 风格消息列表，如 [{"role": "user", "content": "..."}]
        system: 可选的系统提示词，插入到消息最前面
        temperature: 采样温度，默认 0.3
        max_tokens: 最大输出 token 数
        on_llm_call: 可选回调 (prompt_text, response_text)，用于审计记录（阶段 8 Ledger）

    Returns:
        模型回复文本；任何错误（未配置密钥、网络异常、解析失败）均返回 None。
    """
    if not isinstance(messages, list) or not messages:
        logger.warning("ai_chat: messages 参数无效，返回 None")
        return None
    try:
        settings = _resolve_settings()
        if not settings["api_key"]:
            logger.warning(
                "未配置 LLM API Key（DEEPSEEK_API_KEY / SECURITY_AGENT_LLM_API_KEY），AI 能力不可用"
            )
            return None
        prompt_text = _with_system(messages, system)
        content = _post_chat(
            prompt_text,
            temperature=temperature,
            max_tokens=max_tokens,
            settings=settings,
        )
        if on_llm_call is not None:
            try:
                on_llm_call(json.dumps(prompt_text, ensure_ascii=False), content)
            except Exception as exc:  # noqa: BLE001 - 审计回调异常不影响主流程
                logger.warning("LLM 调用审计回调异常（已忽略）: %s", exc)
        if content is None:
            logger.warning("LLM 返回了空内容")
        return content
    except Exception as exc:  # noqa: BLE001 - 失败开放：任何异常都不外抛
        logger.warning("AI 调用失败（fail-open 返回 None）: %s", exc)
        return None


def ai_chat_json(
    messages: list[dict],
    system: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    on_llm_call: Optional[Callable[[str, Optional[str]], None]] = None,
) -> Optional[dict]:
    """调用统一 LLM 端点并解析 JSON 对象回复（失败开放）。

    自动剥离 ```json ... ``` 代码围栏，并尝试从文本中提取首个完整 JSON 对象。
    任何失败均返回 None。

    Args:
        参数含义同 ai_chat；temperature 默认 0.1 以获得更高确定性。
    """
    content = ai_chat(
        messages,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
        on_llm_call=on_llm_call,
    )
    if content is None:
        return None
    try:
        obj = _extract_json_object(content)
    except Exception as exc:  # noqa: BLE001 - 解析异常也走失败开放
        logger.warning("JSON 解析异常（fail-open 返回 None）: %s", exc)
        return None
    if obj is None:
        logger.warning("LLM 返回内容无法解析为 JSON 对象")
    return obj


# ── 配置解析 ──────────────────────────────────────────────


def _resolve_settings() -> dict:
    """按优先级解析 LLM 端点配置（每次调用实时读取，支持运行时变更环境变量）。"""
    config = AppConfig.from_env()

    deepseek_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    generic_key = os.getenv("SECURITY_AGENT_LLM_API_KEY", "").strip()
    api_key = deepseek_key or generic_key or config.llm_api_key

    provider_env = os.getenv("SECURITY_AGENT_LLM_PROVIDER", "").strip().lower()
    if provider_env:
        provider = provider_env
    else:
        # DeepSeek 为主用提供商：设置了 DEEPSEEK_API_KEY 且未显式指定时默认走 DeepSeek
        provider = "deepseek" if deepseek_key else "generic"

    # 端点与模型：显式环境变量优先，否则使用提供商默认值。
    # （AppConfig 中的 base_url/model 本身也源自相同环境变量，直接读取等价且不会
    #   因 config 的 generic 默认值而遮蔽 DeepSeek/Qwen 提供商默认端点）
    default_base_url, default_model = _resolve_provider_defaults(provider)
    base_url = os.getenv("SECURITY_AGENT_LLM_BASE_URL", "").strip() or default_base_url
    model = os.getenv("SECURITY_AGENT_LLM_MODEL", "").strip() or default_model
    try:
        timeout_seconds = max(
            int(
                os.getenv("SECURITY_AGENT_LLM_TIMEOUT", "").strip()
                or config.llm_timeout_seconds
                or DEFAULT_TIMEOUT_SECONDS
            ),
            1,
        )
    except ValueError:
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    if httpx is not None:
        timeout = httpx.Timeout(
            connect=CONNECT_TIMEOUT_SECONDS,
            read=float(timeout_seconds),
            write=CONNECT_TIMEOUT_SECONDS,
            pool=CONNECT_TIMEOUT_SECONDS,
        )
    else:
        timeout = float(timeout_seconds)

    return {
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "timeout": timeout,
    }


# ── HTTP 调用 ─────────────────────────────────────────────


def _post_chat(
    messages: list[dict],
    temperature: float,
    max_tokens: int,
    settings: dict,
) -> Optional[str]:
    """向 OpenAI 兼容端点发起一次 chat/completions 请求。"""
    if httpx is None:
        logger.warning("httpx 未安装，无法发起 LLM 请求")
        return None

    payload = {
        "model": settings["model"],
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings['api_key']}",
    }
    response = httpx.post(
        settings["base_url"],
        json=payload,
        headers=headers,
        timeout=settings["timeout"],
    )
    response.raise_for_status()
    return _extract_content(response.json())


def _with_system(messages: list[dict], system: Optional[str]) -> list[dict]:
    """将系统提示词插入消息开头（若已有 system 消息则覆盖其内容）。"""
    if not system:
        return messages
    if messages and messages[0].get("role") == "system":
        return [{**messages[0], "content": system}, *messages[1:]]
    return [{"role": "system", "content": system}, *messages]


def _extract_content(data: Any) -> Optional[str]:
    """从 OpenAI 兼容响应中防御性提取文本内容。"""
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):  # 部分多模态端点以分片数组返回文本
        parts = [
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        return "".join(parts).strip() or None
    return None


def _extract_json_object(content: str) -> Optional[dict]:
    """从 LLM 文本中提取 JSON 对象：剥离代码围栏，必要时截取首尾花括号。"""
    if not isinstance(content, str):
        return None

    text = content.strip()
    if text.startswith("```"):  # 剥离 markdown 代码围栏
        lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

    return None
