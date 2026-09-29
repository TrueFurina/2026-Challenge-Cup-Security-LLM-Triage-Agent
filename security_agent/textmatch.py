"""关键词匹配的公共护栏：**否定语境**识别。

为什么需要
----------
真实告警文本里大量出现否定表述，例如：

    "no admin$ access"                    → 恰好出现 ``admin$``（横向移动规则词）
    "no exploit payload"                  → 恰好出现 ``exploit payload``（投递规则词）
    "source workstation not in admin group baseline" → 恰好出现 ``baseline``（误报线索词）

朴素的 `substring in corpus` 会把**否定句**当成命中，造成两个方向的错误：

1. **正常运维被误判为攻击** —— "no admin$ access" 反被当作管理共享访问，正常核查升为 high；
2. **攻击被运维线索洗白** —— "not in ... baseline" 反被当作基线内行为，生成误报线索。

这两类错误在独立 holdout 集上都被实测复现（见 `reports/holdout_rules.json` 的
H-02 / H-03 / H-09），因此把否定判定抽成本模块，供规则引擎、预筛器、误报检查工具
**共用一份实现**，避免三处各自实现后再次漂移。

用法
----
    from security_agent.textmatch import keyword_hit, matched_keywords

    keyword_hit(corpus, "admin$")          # -> False（该处是否定语境）
    matched_keywords(corpus, PATTERNS)     # -> 仅返回非否定语境的命中词
"""
from __future__ import annotations

# 否定标记。英文按「词 + 空格」匹配，避免把 "north"/"notify" 之类误判为否定；
# 中文直接子串匹配（这些字在安全日志语境下几乎只表否定）。
NEGATION_TOKENS = (
    "no ", "not ", "without ", "never ", "none ", "n/a", "nil ",
    "无", "未", "非", "不", "没有", "禁止", "拒绝", "不存在", "未见",
)

# 否定作用窗口上限：只作为**成本上限**，真正的作用域由子句边界决定（见下）。
NEGATION_WINDOW = 60

# 子句边界：否定的作用域是**它所在的子句**，而不是固定字符数。
# 早期版本用固定窗口（14 → 28 字符），两头都出错：
#   - 太短：漏判 "source workstation not in admin group baseline"（距 19 字符）→ 否定句被当作误报线索；
#   - 太长：跨子句误伤——"服务器上出现远程下发的编码命令执行，无交互会话。powershell.exe -EncodedCommand"
#     中的「无交互会话」其实是在描述攻击（无人值守），却被当成否定而否掉了 encodedcommand 命中。
# 改为「回退到最近一个子句边界」后，两种误判同时消除。
CLAUSE_DELIMITERS = (";", "；", "。", "，", ",", "|", "\n", "\r", "！", "？")


def _negation_scope(corpus: str, index: int) -> str:
    """返回关键词之前、**同一子句内**的文本（用于判定否定）。"""
    start = max(0, index - NEGATION_WINDOW)
    segment = corpus[start:index]
    cut = 0
    for delim in CLAUSE_DELIMITERS:
        pos = segment.rfind(delim)
        if pos >= 0:
            cut = max(cut, pos + len(delim))
    return segment[cut:]


def keyword_hit(corpus: str, keyword: str) -> bool:
    """关键词是否在**非否定语境**中出现。

    同一关键词在语料中可能多次出现，只要有一次未被否定即算命中；
    全部出现处均被否定时才返回 False。
    """
    if not corpus or not keyword:
        return False
    key = keyword.lower()
    start = 0
    while True:
        idx = corpus.find(key, start)
        if idx < 0:
            return False
        scope = _negation_scope(corpus, idx)
        if not any(tok in scope for tok in NEGATION_TOKENS):
            return True
        start = idx + len(key)


def matched_keywords(corpus: str, keywords) -> list[str]:
    """返回语料中**非否定语境**命中的关键词列表（保持输入顺序）。"""
    return [k for k in keywords if keyword_hit(corpus, k)]
