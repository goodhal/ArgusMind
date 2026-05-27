# -*- coding: utf-8 -*-
# @name: json_parse
# @auth: rainy-autumn@outlook.com
# @version:
"""从 AI 响应等字符串中提取并解析为 JSON 结构，借助 json_repair 容错。"""
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

import json_repair


# 常见 AI 返回的 JSON 代码块标记
JSON_BLOCK_PATTERNS = [
    re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL | re.IGNORECASE),
    re.compile(r"<json>\s*\n?(.*?)\n?</json>", re.DOTALL | re.IGNORECASE),
]


def extract_json_candidate(text: str) -> Optional[str]:
    """
    从字符串中尝试提取可能是 JSON 的片段（如 ```json ... ``` 或 <json>...</json>）。
    若未匹配到代码块，返回去除首尾空白后的全文。
    """
    if not text or not text.strip():
        return None
    text = text.strip()
    for pat in JSON_BLOCK_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip()
    return text


def parse_json(
    raw: str,
    *,
    extract_first: bool = True,
    default: Any = None,
) -> Any:
    """
    将字符串解析为 JSON 结构，适合从 AI 响应中提取 JSON。

    - 先用 extract_json_candidate 提取可能的 JSON 片段（可选）
    - 再用 json_repair 解析，对尾逗号、单引号、注释等常见问题容错

    :param raw: 原始字符串（可能包含 markdown 代码块等）
    :param extract_first: 为 True 时先尝试从 ```json ... ``` 等块中提取内容
    :param default: 解析失败时返回的默认值；为 None 时解析失败会抛异常
    :return: 解析后的对象（dict/list 等），失败且 default 非 None 时返回 default
    """
    candidate = extract_json_candidate(raw) if extract_first else raw.strip()
    if not candidate:
        if default is not None:
            return default
        raise ValueError("No JSON content to parse")
    try:
        return json_repair.loads(candidate)
    except Exception as e:
        if default is not None:
            return default
        raise ValueError(f"Failed to parse JSON: {e}") from e

