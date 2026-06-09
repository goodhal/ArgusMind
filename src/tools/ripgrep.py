# -*- coding: utf-8 -*-
"""基于 ripgrep 的代码搜索与文件枚举工具；`rg` 路径由 `src.tools.bootstrap` 负责解析/自动安装。
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, List, Optional, Union

from src.tools.base import (
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_UNAVAILABLE,
    BaseTool,
    ToolResult,
)
from src.tools.filesystem import _resolve_under_project
from src.tools.bootstrap import ensure_ripgrep_path


def _coerce_base(base: Optional[Union[str, Path]]) -> Optional[Path]:
    if base is None:
        return None
    p = Path(base) if isinstance(base, str) else base
    return p.expanduser().resolve(strict=False)

logger = logging.getLogger(__name__)


def _normalize_globs(glob: Optional[Union[str, List[str]]]) -> List[str]:
    if glob is None:
        return []
    if isinstance(glob, str):
        s = glob.strip()
        if not s:
            return []
        return [g.strip() for g in s.replace("\n", ",").split(",") if g.strip()]
    out: List[str] = []
    for g in glob:
        t = str(g).strip()
        if t:
            out.append(t)
    return out


def _run_rg(
    argv: List[str],
    cwd: str,
    *,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    exe = ensure_ripgrep_path()
    return subprocess.run(
        [exe, *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )


class RipgrepFilesTool(BaseTool):
    """在项目根约束下，用 ripgrep --files 列出文件路径。"""

    _parameters_schema = [
        {
            "name": "root",
            "type": "string",
            "description": "起始目录；相对路径时相对于项目根，不传则默认项目根",
            "required": False,
        },
        {
            "name": "glob",
            "type": "array",
            "description": "可选，额外的 ripgrep --glob 模式列表（如 [\"**/*.py\"]）；也可传逗号分隔字符串",
            "required": False,
        },
        {
            "name": "hidden",
            "type": "boolean",
            "description": "是否包含隐藏文件，默认 true",
            "required": False,
        },
        {
            "name": "follow",
            "type": "boolean",
            "description": "是否跟随符号链接，默认 false",
            "required": False,
        },
        {
            "name": "max_depth",
            "type": "integer",
            "description": "可选，目录最大深度（ripgrep --max-depth）",
            "required": False,
        },
    ]

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "ripgrep_files"

    @property
    def description(self) -> str:
        return (
            "使用 ripgrep 在目录下枚举文件路径（rg --files），默认排除 .git；"
            "适合大仓库，比纯 Python glob 更快。"
        )

    def run(
        self,
        root: Optional[Union[str, Path]] = None,
        glob: Optional[Union[str, List[str]]] = None,
        hidden: bool = True,
        follow: bool = False,
        max_depth: Optional[int] = None,
        **kwargs: Any,
    ) -> ToolResult:
        if root is None:
            root = self._base_path or "."
        path, resolve_err = _resolve_under_project(root, self._base_path)
        if resolve_err:
            return ToolResult(
                success=False,
                error=resolve_err,
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"root": str(path)},
            )
        if not path.is_dir():
            return ToolResult(
                success=False,
                error=f"路径不是目录: {path}",
                error_code=ERROR_CODE_NOT_FOUND,
                meta={"root": str(path)},
            )

        globs = _normalize_globs(glob)
        argv: List[str] = ["--files", "--glob=!.git/*"]
        if follow:
            argv.append("--follow")
        if hidden:
            argv.append("--hidden")
        if max_depth is not None:
            if max_depth < 0:
                return ToolResult(
                    success=False,
                    error="max_depth 必须 >= 0",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )
            argv.append(f"--max-depth={max_depth}")
        for g in globs:
            argv.append(f"--glob={g}")
        argv.append(str(path.resolve()))

        try:
            proc = _run_rg(argv, cwd=str(path.resolve()))
        except FileNotFoundError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_UNAVAILABLE,
                meta={"root": str(path)},
            )
        except RuntimeError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path)},
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                error="ripgrep --files 执行超时",
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path)},
            )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            return ToolResult(
                success=False,
                error=f"ripgrep 失败: {err}",
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path), "returncode": proc.returncode},
            )

        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return ToolResult(
            success=True,
            data=lines,
            meta={"root": str(path), "count": len(lines)},
        )


class RipgrepSearchTool(BaseTool):
    """在项目根约束下，用 ripgrep --json 按正则搜索内容。"""

    _parameters_schema = [
        {
            "name": "root",
            "type": "string",
            "description": "搜索根目录；相对路径时相对于项目根，不传则默认项目根",
            "required": False,
        },
        {
            "name": "pattern",
            "type": "string",
            "description": "ripgrep 正则模式（Rust 正则语法）",
            "required": True,
        },
        {
            "name": "glob",
            "type": "array",
            "description": "可选，额外的 --glob 过滤；可为字符串列表或逗号分隔字符串",
            "required": False,
        },
        {
            "name": "limit",
            "type": "integer",
            "description": "可选，最多匹配次数（--max-count），控制输出量",
            "required": False,
        },
        {
            "name": "follow",
            "type": "boolean",
            "description": "是否跟随符号链接，默认 false",
            "required": False,
        },
    ]

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "ripgrep_search"

    @property
    def description(self) -> str:
        return (
            "在目录下用 ripgrep 搜索文件内容（rg --json），默认排除 .git、搜索隐藏文件；"
            "返回结构化匹配列表（路径、行号、行文本、子匹配区间）。"
        )

    @staticmethod
    def _parse_match(obj: dict) -> Optional[dict]:
        if obj.get("type") != "match":
            return None
        data = obj.get("data") or {}
        path_o = data.get("path") or {}
        lines_o = data.get("lines") or {}
        subs = []
        for sm in data.get("submatches") or []:
            m = sm.get("match") or {}
            subs.append(
                {
                    "text": m.get("text", ""),
                    "start": sm.get("start"),
                    "end": sm.get("end"),
                }
            )
        return {
            "path": path_o.get("text", ""),
            "line_number": data.get("line_number"),
            "line": lines_o.get("text", ""),
            "submatches": subs,
        }

    def run(
        self,
        root: Optional[Union[str, Path]] = None,
        pattern: str = "",
        glob: Optional[Union[str, List[str]]] = None,
        limit: Optional[int] = None,
        follow: bool = False,
        **kwargs: Any,
    ) -> ToolResult:
        if root is None:
            root = self._base_path or "."
        path, resolve_err = _resolve_under_project(root, self._base_path)
        if resolve_err:
            return ToolResult(
                success=False,
                error=resolve_err,
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"root": str(path)},
            )
        if not path.is_dir():
            return ToolResult(
                success=False,
                error=f"路径不是目录: {path}",
                error_code=ERROR_CODE_NOT_FOUND,
                meta={"root": str(path)},
            )
        if not (pattern or "").strip():
            return ToolResult(
                success=False,
                error="pattern 不能为空",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"root": str(path)},
            )

        # 简单的正则表达式语法校验：仅检查括号匹配，然后交由 Python re 做基本验证
        try:
            # 先移除转义字符（如 \(、\)、\[、\{ 等），以免转义字面量干扰计数
            _bare = re.sub(r'\\(.)', '', pattern)

            # 检查未闭合的括号
            open_parens = _bare.count("(")
            close_parens = _bare.count(")")
            if open_parens != close_parens:
                return ToolResult(
                    success=False,
                    error=f"正则表达式括号不匹配（{open_parens} 个开括号，{close_parens} 个闭括号）: {pattern}",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )

            # 检查未闭合的方括号
            open_brackets = _bare.count("[")
            close_brackets = _bare.count("]")
            if open_brackets != close_brackets:
                return ToolResult(
                    success=False,
                    error=f"正则表达式方括号不匹配（{open_brackets} 个开方括号，{close_brackets} 个闭方括号）: {pattern}",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )

            # 检查未闭合的花括号
            open_braces = _bare.count("{")
            close_braces = _bare.count("}")
            if open_braces != close_braces:
                return ToolResult(
                    success=False,
                    error=f"正则表达式花括号不匹配（{open_braces} 个开花括号，{close_braces} 个闭花括号）: {pattern}",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )

            # 尝试用 Python 正则解析器验证基本语法
            # 注意：Python re 与 Rust regex 语法有差异，此校验仅为兜底，
            # 即便失败也仍交由 ripgrep 自身处理
            re.compile(pattern)
        except re.error as e:
            # Python re 校验失败时仅记录，不阻断——让 ripgrep 自身做最终校验
            logger.debug("正则语法 Python 校验不通过（将交由 ripgrep 处理）: %s — %s", pattern, e)

        globs = _normalize_globs(glob)
        argv: List[str] = ["--json", "--hidden", "--glob=!.git/*"]
        if follow:
            argv.append("--follow")
        for g in globs:
            argv.append(f"--glob={g}")
        if limit is not None:
            if limit < 1:
                return ToolResult(
                    success=False,
                    error="limit 必须 >= 1",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )
            argv.append(f"--max-count={limit}")
        argv.append("--")
        argv.append(pattern)
        argv.append(str(path.resolve()))

        try:
            proc = _run_rg(argv, cwd=str(path.resolve()))
        except FileNotFoundError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_UNAVAILABLE,
                meta={"root": str(path)},
            )
        except RuntimeError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path)},
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                error="ripgrep 搜索超时",
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path)},
            )

        # ripgrep：0 有匹配，1 无匹配，2 错误
        if proc.returncode not in (0, 1):
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            return ToolResult(
                success=False,
                error=f"ripgrep 失败: {err}",
                error_code=ERROR_CODE_EXTERNAL,
                meta={"root": str(path), "returncode": proc.returncode},
            )

        matches: List[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed = self._parse_match(obj)
            if parsed is not None:
                matches.append(parsed)

        return ToolResult(
            success=True,
            data=matches,
            meta={"root": str(path), "match_count": len(matches)},
        )
