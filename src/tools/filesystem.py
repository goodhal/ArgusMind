"""文件系统工具：按功能拆分为独立工具类"""
from pathlib import Path
from typing import List, Optional, Tuple, Union

from src.tools.base import (
    BaseTool,
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_PERMISSION_DENIED,
    ToolResult,
)

_READ_FILE_MAX_BYTES = 10 * 1024


def _as_path(raw: Union[str, Path]) -> Path:
    return Path(raw) if isinstance(raw, str) else raw


def _coerce_base(base: Optional[Union[str, Path]]) -> Optional[Path]:
    if base is None:
        return None
    return _as_path(base).expanduser().resolve(strict=False)


def _resolve_under_project(
    raw: Union[str, Path], base: Optional[Path]
) -> Tuple[Path, Optional[str]]:
    """
    将 LLM 传入的路径解析为实际 Path。
    - 已是绝对路径：原样使用（不校验是否在项目内）。
    - 相对路径：若配置了 base（项目根），则 (base / raw).resolve，且禁止解析结果跳出 base。
    - 相对路径且无 base：保持 pathlib 默认行为（相对进程 cwd）。
    返回 (path, error_message)；error_message 非空时表示应拒绝本次访问。
    """
    p = _as_path(raw)
    if p.is_absolute():
        return p.expanduser().resolve(strict=False), None
    if base is None:
        return p, None
    base_r = base.resolve(strict=False)
    resolved = (base_r / p).resolve(strict=False)
    try:
        resolved.relative_to(base_r)
    except ValueError:
        return resolved, "路径解析后超出项目根目录（请勿使用 .. 等跳出仓库根路径）"
    return resolved, None


def _count_lines_stream(path: Path) -> int:
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for _ in f:
            n += 1
    return n


def _lines_with_line_prefix(
    lines: List[str], *, start_line: int, width_for_line_numbers: int
) -> List[str]:
    """与 read_lines 一致：每行「{行号}| {原文}」，行号列宽由 width_for_line_numbers 位数决定。"""
    if not lines:
        return []
    width = max(1, len(str(width_for_line_numbers)))
    return [f"{ln:{width}d}|{text}" for ln, text in enumerate(lines, start=start_line)]


class ReadFileTool(BaseTool):
    """UTF-8 全文读取；大文件易占满上下文，应优先用 ReadLinesTool 按需读行。超过单次读取字节上限时只返回开头一段并在 data 首条给出截断说明。"""

    _parameters_schema = [
        {
            "name": "file_path",
            "type": "string",
            "description": "文件路径：绝对路径",
            "required": True,
        },
    ]

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "read_file"

    @property
    def description(self) -> str:
        return (
            "读取指定路径文件的文本（UTF-8）。为控制上下文体积，应优先使用 read_lines "
            "按行范围读取关键片段；仅在必须通读全文、或文件很小可一次读完时再使用本工具。"
            "超过单次读取上限时仅返回文件开头一段；截断时 data 首条为中文提示（全文大小/行数、本次读取字节/行数），"
            "其余每行形如「  12| 行内容」（与 read_lines 一致）。"
            "成功时 meta 含 file_size_bytes、total_lines、lines_read、bytes_read、truncated。"
        )

    @property
    def usage(self) -> str:
        return (
            "read_file(file_path: str | Path) -> ToolResult。"
            "示例：run(file_path='D:/proj/src/main.py') 或 run(file_path='src/main.py')（相对项目根）"
        )

    def run(self, file_path: Union[str, Path, None] = None, **kwargs) -> ToolResult:
        # 兼容 LLM 传 path/filepath/file 而非 file_path 的情况
        if file_path is None:
            file_path = kwargs.pop("path", None) or kwargs.pop("filepath", None) or kwargs.pop("file", None)
        if file_path is None:
            return ToolResult(
                success=False,
                error="缺少 file_path 参数",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        path, resolve_err = _resolve_under_project(file_path, self._base_path)
        if resolve_err:
            return ToolResult(
                success=False,
                error=resolve_err,
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"path": str(path)},
            )
        try:
            if not path.exists():
                return ToolResult(
                    success=False,
                    error=f"文件不存在: {path}",
                    error_code=ERROR_CODE_NOT_FOUND,
                    meta={"path": str(path)},
                )
            if not path.is_file():
                return ToolResult(
                    success=False,
                    error=f"路径不是文件: {path}",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"path": str(path)},
                )
            total_size = path.stat().st_size
            if total_size <= _READ_FILE_MAX_BYTES:
                content = path.read_text(encoding="utf-8")
                total_lines = len(content.splitlines())
                lines_read = total_lines
                bytes_read = total_size
                truncated = False
            else:
                with open(path, "rb") as f:
                    raw = f.read(_READ_FILE_MAX_BYTES)
                bytes_read = len(raw)
                content = raw.decode("utf-8", errors="replace")
                total_lines = _count_lines_stream(path)
                lines_read = len(content.splitlines())
                truncated = True
            body_lines = content.splitlines()
            numbered = _lines_with_line_prefix(
                body_lines,
                start_line=1,
                width_for_line_numbers=max(total_lines, 1),
            )
            if truncated:
                notice = (
                    f"[提示] 文件大小超过单次读取上限（{_READ_FILE_MAX_BYTES} 字节），已截断返回开头部分。"
                    f"全文共 {total_size} 字节、{total_lines} 行；"
                    f"本次读取 {bytes_read} 字节、{lines_read} 行。"
                )
                numbered = [notice] + numbered
            return ToolResult(
                success=True,
                data=numbered,
                meta={
                    "path": str(path),
                    "file_size_bytes": total_size,
                    "total_lines": total_lines,
                    "lines_read": lines_read,
                    "bytes_read": bytes_read,
                    "truncated": truncated,
                },
            )
        except PermissionError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_PERMISSION_DENIED,
                meta={"path": str(path)},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=getattr(e, "error_code", None),
                meta={"path": str(path)},
            )

    def read_file(self, file_path: Union[str, Path]) -> Optional[str]:
        """兼容旧接口：返回带行号前缀的多行文本（换行拼接），失败为 None。"""
        r = self.run(file_path=file_path)
        if not r.success or r.data is None:
            return None
        if isinstance(r.data, list):
            return "\n".join(r.data)
        return str(r.data)


class ReadLinesTool(BaseTool):
    """按行范围读取文件内容。"""

    _parameters_schema = [
        {
            "name": "file_path",
            "type": "string",
            "description": "文件路径：绝对路径",
            "required": True,
        },
        {"name": "start_line", "type": "integer", "description": "起始行号（从 1 开始，闭区间）", "required": True},
        {"name": "end_line", "type": "integer", "description": "结束行号（闭区间）", "required": True},
    ]

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "read_lines"

    @property
    def description(self) -> str:
        return (
            "读取文件中指定行范围的内容，行号从 1 开始、闭区间 [start_line, end_line]；"
            "返回的每一行前会带对应源码行号（形如「  42| 行内容」）。"
        )

    @property
    def usage(self) -> str:
        return (
            "示例：run(file_path='D:/code/src/main.py', start_line=1, end_line=10)（路径相对项目根）"
        )

    def run(
        self,
        file_path: Union[str, Path, None] = None,
        start_line: int = 1,
        end_line: int = 1,
        **kwargs,
    ) -> ToolResult:
        # 兼容 LLM 传 path/filepath/file 而非 file_path 的情况
        if file_path is None:
            file_path = kwargs.pop("path", None) or kwargs.pop("filepath", None) or kwargs.pop("file", None)
        if file_path is None:
            return ToolResult(
                success=False,
                error="缺少 file_path 参数",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        path, resolve_err = _resolve_under_project(file_path, self._base_path)
        if resolve_err:
            return ToolResult(
                success=False,
                error=resolve_err,
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"path": str(path), "start_line": start_line, "end_line": end_line},
            )
        try:
            if not path.exists():
                return ToolResult(
                    success=False,
                    error=f"文件不存在: {path}",
                    error_code=ERROR_CODE_NOT_FOUND,
                    meta={"path": str(path)},
                )
            if start_line < 1 or end_line < 1:
                return ToolResult(
                    success=False,
                    error="start_line 与 end_line 必须 >= 1",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"path": str(path), "start_line": start_line, "end_line": end_line},
                )
            if start_line > end_line:
                return ToolResult(
                    success=False,
                    error="start_line 不能大于 end_line",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"path": str(path), "start_line": start_line, "end_line": end_line},
                )
            content = path.read_text(encoding="utf-8")
            lines = content.splitlines()
            total_lines = len(lines)
            if start_line > total_lines:
                return ToolResult(
                    success=False,
                    error=f"行号越界：文件共 {total_lines} 行，start_line={start_line} 超出范围",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={
                        "path": str(path),
                        "start_line": start_line,
                        "end_line": end_line,
                        "total_lines": total_lines,
                    },
                )
            actual_end = min(end_line, total_lines)
            end_clamped = end_line > total_lines
            raw_slice = lines[start_line - 1 : actual_end]
            selected = _lines_with_line_prefix(
                raw_slice,
                start_line=start_line,
                width_for_line_numbers=max(end_line, actual_end),
            )
            if end_clamped:
                notice = (
                    f"[提示] end_line={end_line} 大于文件总行数 {total_lines}，"
                    f"已改为返回第 {start_line}～{total_lines} 行。"
                )
                selected = [notice] + selected
            meta = {"path": str(path), "start_line": start_line, "end_line": end_line}
            if end_clamped:
                meta = {
                    **meta,
                    "total_lines": total_lines,
                    "effective_end_line": actual_end,
                    "end_line_clamped": True,
                }
            return ToolResult(success=True, data=selected, meta=meta)
        except PermissionError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_PERMISSION_DENIED,
                meta={"path": str(path)},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                meta={"path": str(path)},
            )


class ListFilesTool(BaseTool):
    """按模式列出目录下的文件。"""

    _parameters_schema = [
        {
            "name": "root",
            "type": "string",
            "description": "目录路径：绝对路径，不传则默认项目根",
            "required": False,
        },
        {"name": "pattern", "type": "string", "description": "glob 模式，如 '**/*.py'，默认 '**/*'", "required": False},
    ]

    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "list_files"

    @property
    def description(self) -> str:
        return "列出目录下匹配模式的文件路径，支持 glob 如 '**/*.py'。"

    @property
    def usage(self) -> str:
        return (
            "list_files(root: str | Path, pattern: str = '**/*') -> ToolResult。"
            "示例：run(root='src', pattern='**/*.py')"
        )

    def run(
        self,
        root: Optional[Union[str, Path]] = None,
        pattern: str = "**/*",
        **kwargs,
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
        try:
            if not path.exists():
                return ToolResult(
                    success=False,
                    error=f"路径不存在: {path}",
                    error_code=ERROR_CODE_NOT_FOUND,
                    meta={"root": str(path)},
                )
            if not path.is_dir():
                return ToolResult(
                    success=False,
                    error=f"路径不是目录: {path}",
                    error_code=ERROR_CODE_INVALID_ARGUMENT,
                    meta={"root": str(path)},
                )
            files = list(path.glob(pattern))
            return ToolResult(
                success=True,
                data=[str(p) for p in files],
                meta={"root": str(path), "pattern": pattern, "count": len(files)},
            )
        except PermissionError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_PERMISSION_DENIED,
                meta={"root": str(path)},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                meta={"root": str(path)},
            )

    def list_files(
        self, root: Union[str, Path], pattern: str = "**/*"
    ) -> List[Path]:
        """兼容旧接口：直接返回 Path 列表。"""
        r = self.run(root=root, pattern=pattern)
        if not r.success:
            return []
        return [Path(p) for p in r.data]

