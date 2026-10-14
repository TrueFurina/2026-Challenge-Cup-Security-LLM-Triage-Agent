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

# 推理型模型（如 deepseek-v4-flash）先产出 reasoning_content，且推理 token 同样
# 计入 max_tokens 预算。预算偏小时推理尚未结束正文已被截断：content 为空或只剩
# 半截 JSON，调用方随即静默回退规则引擎——表面「已接入真 LLM」，实际 AI 未生效。
# 故对输出预算设下限。max_tokens 只是上限、按实际生成计费，调高不产生额外成本。
# 如需覆盖，设置环境变量 SECURITY_AGENT_LLM_MAX_TOKENS（设为 0 可关闭下限）。
DEFAULT_MAX_OUTPUT_TOKENS = 8000

# ── 用量计量 ──────────────────────────────────────────────
# token 数为实测计数（取自 API 响应的 usage 字段），不是事后推断；
# 单价为显式假设，可用环境变量覆盖。评测报告中的成本必须基于此计量，
# 不得再使用「单次调用 ≈ 固定金额」之类的硬编码近似。
_USAGE: dict[str, int] = {
    "requests": 0,
    "failed_requests": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "reasoning_tokens": 0,
    "truncated_responses": 0,
    # 发生了计量失败的次数：正常必须恒为 0。非 0 意味着上面的 token/成本
    # 存在漏计，评测报告中的「调用数 / 成本」随即失去可信度，不得对外引用。
    "metering_failures": 0,
}

DEFAULT_PROMPT_PRICE_PER_MILLION = 2.0  # 元/百万 token（假设值，可按实际合同价覆盖）
DEFAULT_COMPLETION_PRICE_PER_MILLION = 8.0


def get_usage_stats() -> dict:
    """返回本进程累计的 LLM 用量快照（实测计数）。"""
    return dict(_USAGE)


def reset_usage_stats() -> None:
    """清零用量统计（分模式评测时使用，避免模式间串扰）。"""
    for key in _USAGE:
        _USAGE[key] = 0


def estimate_cost_yuan(stats: Optional[dict] = None) -> float:
    """按实测 token 用量估算成本（元）。

    返回值为**估算**：token 数实测，单价假设可由
    SECURITY_AGENT_PROMPT_PRICE_PER_M / SECURITY_AGENT_COMPLETION_PRICE_PER_M
    （元/百万 token）覆盖，默认取 DeepSeek 公开价目量级。
    """
    stats = _USAGE if stats is None else stats
    price_in = _read_price_env("SECURITY_AGENT_PROMPT_PRICE_PER_M", DEFAULT_PROMPT_PRICE_PER_MILLION)
    price_out = _read_price_env(
        "SECURITY_AGENT_COMPLETION_PRICE_PER_M", DEFAULT_COMPLETION_PRICE_PER_MILLION
    )
    cost = (
        stats.get("prompt_tokens", 0) / 1_000_000 * price_in
        + stats.get("completion_tokens", 0) / 1_000_000 * price_out
    )
    return round(cost, 6)


def _read_price_env(name: str, fallback: float) -> float:
    try:
        raw = os.getenv(name, "").strip()
        return float(raw) if raw else fallback
    except ValueError:
        return fallback


def _record_usage(data: Any) -> None:
    """累计一次成功请求的真实 token 用量；异常不影响主流程。

    计量失败**必须可见**：`get_usage_stats()` 是评测报告「调用数 / 成本」的唯一
    出处（`evaluation/service.py`、`_holdout_eval.py` 均取自此处）。此前整段被
    `except: pass` 包住且不计数，一旦 provider 换了响应结构（usage 不是 dict、
    choices 不是 list 等），一次**真实发生的付费调用**会从统计里凭空消失，报告
    里的数字没人能发现有漏——这与「token 预算耗尽致 LLM 静默回退」同族的隐性问题。

    因此：request 计数移到 try 之外（"发过几次请求"是最基础的事实，不应依赖响应
    解析是否成功）；解析失败则累加 `metering_failures` 并告警。**评测时该值必须为
    0**，否则本次 token/成本数字不可引用。
    """
    _USAGE["requests"] += 1
    try:
        usage = data.get("usage") or {}
        choice = (data.get("choices") or [{}])[0]
        _USAGE["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
        _USAGE["completion_tokens"] += int(usage.get("completion_tokens") or 0)
        _USAGE["reasoning_tokens"] += int(
            (usage.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0
        )
        if choice.get("finish_reason") == "length":
            _USAGE["truncated_responses"] += 1
    except Exception as exc:  # noqa: BLE001 - 计量失败不得影响研判主流程
        _USAGE["metering_failures"] += 1
        logger.warning("LLM 用量计量失败（该次调用未计入 token/成本统计）: %s", exc)


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
        _USAGE["failed_requests"] += 1
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

    try:
        max_output_tokens = max(
            int(
                os.getenv("SECURITY_AGENT_LLM_MAX_TOKENS", "").strip()
                or DEFAULT_MAX_OUTPUT_TOKENS
            ),
            0,
        )
    except ValueError:
        max_output_tokens = DEFAULT_MAX_OUTPUT_TOKENS

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
        "max_output_tokens": max_output_tokens,
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

    # 应用输出预算下限（推理型模型的 reasoning_content 也占预算，见模块顶部说明）
    effective_max_tokens = max(int(max_tokens), int(settings.get("max_output_tokens", 0)))
    payload = {
        "model": settings["model"],
        "messages": messages,
        "temperature": temperature,
        "max_tokens": effective_max_tokens,
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
    data = response.json()
    _record_usage(data)
    content = _extract_content(data)
    if content is None:
        _log_empty_response(data, effective_max_tokens)
    return content


def _log_empty_response(data: Any, max_tokens: int) -> None:
    """定位「LLM 返回空内容」的真实原因，避免截断被静默当成普通失败。

    推理型模型最常见的空返回并非网络或密钥问题，而是输出预算被 reasoning_content
    吃满导致正文截断；此处显式区分并给出可操作的提示。
    """
    try:
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        finish_reason = choice.get("finish_reason")
        reasoning = message.get("reasoning_content") or ""
        content = message.get("content") or ""
        usage = data.get("usage") or {}
        reasoning_tokens = (usage.get("completion_tokens_details") or {}).get(
            "reasoning_tokens", 0
        )
    except Exception:  # noqa: BLE001 - 日志路径不应抛出
        logger.warning("LLM 返回空内容，且响应结构无法解析")
        return

    if finish_reason == "length":
        logger.warning(
            "LLM 输出被截断：max_tokens=%s 已被耗尽（其中推理 %s token，正文仅 %s 字符）。"
            "推理型模型需为 reasoning_content 预留预算，可用环境变量 "
            "SECURITY_AGENT_LLM_MAX_TOKENS 提高上限",
            max_tokens,
            reasoning_tokens,
            len(content),
        )
    elif reasoning and not content:
        logger.warning(
            "LLM 仅返回 reasoning_content，正文为空（finish_reason=%s，推理 %s token）",
            finish_reason,
            reasoning_tokens,
        )
    else:
        logger.warning("LLM 响应中未找到可用正文（finish_reason=%s）", finish_reason)


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
