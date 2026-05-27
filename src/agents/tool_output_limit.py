# -*- coding: utf-8 -*-
"""Agent 工具返回体体积上限：超出部分落盘，对话中仅保留截断结果与提示。"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

TOOL_OUTPUT_MAX_BYTES = 12 * 1024

_NOTICE_PLACEHOLDER = (
    "[提示] 工具返回内容超过单次输出上限，截断掉的后续内容已写入临时文件"
    "（路径见 meta.overflow_output_path）。"
)


def _serialize_bytes(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))


def _fits(shell: Dict[str, Any], data: Any, max_bytes: int) -> bool:
    return _serialize_bytes({**shell, "data": data}) <= max_bytes


def _split_data(
    data: Any,
    *,
    shell: Dict[str, Any],
    notice: str,
    max_bytes: int,
) -> Tuple[Any, Optional[Any]]:
    """返回 (保留在对话中的 data, 被截掉的部分)；未截断时 overflow 为 None。"""
    if _fits(shell, data, max_bytes):
        return data, None

    if isinstance(data, list):
        items = list(data)
        lo, hi = 0, len(items)
        best_mid = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            candidate = [notice] + items[:mid]
            if _fits(shell, candidate, max_bytes):
                best_mid = mid
                lo = mid + 1
            else:
                hi = mid - 1
        kept = [notice] + items[:best_mid]
        overflow = items[best_mid:] if best_mid < len(items) else None
        if not _fits(shell, kept, max_bytes):
            kept = [notice[: max(1, max_bytes // 4)]]
            overflow = items
        return kept, overflow or None

    if isinstance(data, str):
        prefix = notice + "\n"
        lo, hi = 0, len(data)
        best_mid = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            candidate = prefix + data[:mid]
            if _fits(shell, candidate, max_bytes):
                best_mid = mid
                lo = mid + 1
            else:
                hi = mid - 1
        kept = prefix + data[:best_mid]
        overflow = data[best_mid:] if best_mid < len(data) else None
        return kept, overflow or None

    if isinstance(data, dict):
        preview = json.dumps(data, ensure_ascii=False, default=str)
        lo, hi = 0, len(preview)
        best_mid = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            candidate = {"_output_truncated_notice": notice, "preview": preview[:mid]}
            if _fits(shell, candidate, max_bytes):
                best_mid = mid
                lo = mid + 1
            else:
                hi = mid - 1
        kept = {"_output_truncated_notice": notice, "preview": preview[:best_mid]}
        overflow = preview[best_mid:] if best_mid < len(preview) else None
        return kept, overflow or None

    text = json.dumps(data, ensure_ascii=False, default=str)
    prefix = notice + "\n"
    lo, hi = 0, len(text)
    best_mid = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = prefix + text[:mid]
        if _fits(shell, candidate, max_bytes):
            best_mid = mid
            lo = mid + 1
        else:
            hi = mid - 1
    kept = prefix + text[:best_mid]
    overflow = text[best_mid:] if best_mid < len(text) else None
    return kept, overflow or None


def _write_overflow(path: Path, overflow: Any) -> int:
    if isinstance(overflow, list):
        body = "\n".join(str(line) for line in overflow)
    elif isinstance(overflow, str):
        body = overflow
    else:
        body = json.dumps(overflow, ensure_ascii=False, default=str)
    path.write_text(body, encoding="utf-8")
    return len(body.encode("utf-8"))


def _apply_final_notice(kept: Any, placeholder: str, final_notice: str) -> Any:
    if isinstance(kept, list) and kept and kept[0] == placeholder:
        kept = list(kept)
        kept[0] = final_notice
        return kept
    if isinstance(kept, str) and kept.startswith(placeholder):
        return final_notice + kept[len(placeholder) :]
    if isinstance(kept, dict) and kept.get("_output_truncated_notice") == placeholder:
        return {**kept, "_output_truncated_notice": final_notice}
    return kept


def limit_tool_result(
    result: Dict[str, Any],
    tmp_dir: Path,
    *,
    tool_name: str = "",
    max_bytes: int = TOOL_OUTPUT_MAX_BYTES,
) -> Dict[str, Any]:
    """
    若工具返回 dict 序列化后超过 max_bytes，将截断掉的后续内容写入 tmp_dir，
    对话中仅返回不超过上限的开头部分及提示。
    """
    if not isinstance(result, dict):
        return result
    original_bytes = _serialize_bytes(result)
    if original_bytes <= max_bytes:
        return result

    tmp_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]+", "_", tool_name or "tool").strip("_")[:64] or "tool"
    out_path = tmp_dir / f"tool_output_overflow_{safe}_{int(time.time() * 1000)}.txt"

    meta = dict(result.get("meta") or {})
    shell: Dict[str, Any] = {
        "success": result.get("success"),
        "error": result.get("error"),
        "meta": meta,
    }
    if result.get("error_code") is not None:
        shell["error_code"] = result["error_code"]

    kept, overflow = _split_data(
        result.get("data"),
        shell=shell,
        notice=_NOTICE_PLACEHOLDER,
        max_bytes=max_bytes,
    )

    overflow_bytes = 0
    if overflow:
        overflow_bytes = _write_overflow(out_path, overflow)

    final_notice = (
        f"[提示] 工具返回内容超过单次输出上限（{max_bytes} 字节），"
        f"截断掉的后续内容已写入临时文件：{out_path}。"
        f"全文共 {original_bytes} 字节，溢出约 {overflow_bytes} 字节；以下仅含开头部分。"
    )
    kept = _apply_final_notice(kept, _NOTICE_PLACEHOLDER, final_notice)

    meta.update(
        {
            "output_truncated": True,
            "overflow_output_path": str(out_path),
            "original_output_bytes": original_bytes,
            "overflow_output_bytes": overflow_bytes,
        }
    )
    shell["data"] = kept
    if _serialize_bytes(shell) > max_bytes:
        shell["data"] = _split_data(
            None,
            shell=shell,
            notice=final_notice,
            max_bytes=max_bytes,
        )[0]
    return shell
