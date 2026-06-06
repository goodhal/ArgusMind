"""代码搜索工具：支持类、方法、字段的高级搜索"""
from pathlib import Path
from typing import List, Optional

from src.tools.base import (
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_NOT_FOUND,
    BaseTool,
    ToolResult,
)
from src.tools.filesystem import _resolve_under_project, _coerce_base
from src.tools.ripgrep import _run_rg


class CodeSearchTool(BaseTool):
    """基于正则的代码搜索工具，用于在代码仓库中搜索符合特定模式的代码片段。"""

    _parameters_schema = [
        {
            "name": "className",
            "type": "string",
            "description": "要搜索的类名，可以是全类名（如 com.example.MyClass）或简单类名（如 MyClass）。"
                          "对于内部类，用 $ 表示，如 com.example.MyClass$InnerClass。",
            "required": True,
        },
        {
            "name": "methodName",
            "type": "string",
            "description": "要搜索的方法名，可为空。支持带参数类型的格式，如 myMethod(String, int)。",
            "required": False,
        },
        {
            "name": "fieldName",
            "type": "string",
            "description": "要搜索的字段名，可为空。",
            "required": False,
        },
        {
            "name": "root",
            "type": "string",
            "description": "搜索根目录，默认项目根目录",
            "required": False,
        },
    ]

    def __init__(self, base_path: Optional[str] = None):
        self._base_path = _coerce_base(base_path)

    @property
    def name(self) -> str:
        return "code_search"

    @property
    def description(self) -> str:
        return (
            "基于正则的代码搜索工具，用于在代码仓库中搜索符合特定模式的代码片段。\n"
            "使用方式：\n"
            "- 只搜索类：传入 className，methodName 和 fieldName 置空\n"
            "- 搜索类的方法：传入 className 和 methodName，fieldName 置空\n"
            "- 搜索类的字段：传入 className 和 fieldName，methodName 置空\n"
            "返回匹配的代码片段列表。"
        )

    def _build_pattern(self, class_name: str, method_name: str, field_name: str) -> str:
        """构建搜索正则模式"""
        patterns = []

        # 类名模式
        if class_name:
            # 支持全类名和简单类名
            class_pattern = class_name.replace(".", r"\.").replace("$", r"\$")
            # 匹配类定义：class Xxx / interface Xxx / enum Xxx
            patterns.append(rf"(class|interface|enum)\s+{class_pattern}\b")

        # 方法名模式
        if method_name and class_name:
            method_pattern = method_name.replace("(", r"\(").replace(")", r"\)").replace(",", r",\s*")
            patterns.append(rf"\b{method_pattern}\s*\(")

        # 字段名模式
        if field_name and class_name:
            # 匹配字段定义（排除方法）
            patterns.append(rf"\b{field_name}\s*[^(]")

        if not patterns:
            return ""

        return "|".join(patterns)

    def run(
        self,
        className: str = "",
        methodName: str = "",
        fieldName: str = "",
        root: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        if not className and not methodName and not fieldName:
            return ToolResult(
                success=False,
                error="至少需要提供 className、methodName 或 fieldName 中的一个",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        if root is None:
            root = str(self._base_path) if self._base_path else "."

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

        pattern = self._build_pattern(className, methodName, fieldName)
        if not pattern:
            return ToolResult(
                success=False,
                error="无法构建搜索模式",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        try:
            # 使用 ripgrep 搜索
            argv = ["--json", "--hidden", "--glob=!.git/*", "--context=3", "--max-count=100"]
            argv.append("--")
            argv.append(pattern)
            argv.append(str(path.resolve()))

            proc = _run_rg(argv, cwd=str(path.resolve()))

            if proc.returncode == 2:
                err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
                return ToolResult(
                    success=False,
                    error=f"搜索失败: {err}",
                    error_code="SEARCH_FAILED",
                    meta={"root": str(path)},
                )

            import json

            matches = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("type") == "match":
                        data = obj.get("data", {})
                        path_o = data.get("path", {})
                        lines_o = data.get("lines", {})
                        matches.append({
                            "path": path_o.get("text", ""),
                            "line_number": data.get("line_number"),
                            "line": lines_o.get("text", ""),
                            "context_before": data.get("context", {}).get("before", []),
                            "context_after": data.get("context", {}).get("after", []),
                        })
                except json.JSONDecodeError:
                    continue

            return ToolResult(
                success=True,
                data=matches,
                meta={
                    "root": str(path),
                    "className": className,
                    "methodName": methodName,
                    "fieldName": fieldName,
                    "match_count": len(matches),
                },
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code="SEARCH_FAILED",
                meta={"root": str(path)},
            )