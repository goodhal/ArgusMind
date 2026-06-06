"""类层次查询工具：查找类的父类和子类"""
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


class ClassHierarchyTool(BaseTool):
    """查找指定类的所有父类或所有子类。"""

    _parameters_schema = [
        {
            "name": "className",
            "type": "string",
            "description": "要查找的类名，可以是全类名（如 com.example.Foo）或简单类名（如 Foo）。",
            "required": True,
        },
        {
            "name": "type",
            "type": "string",
            "description": "查找类型：super 表示查找所有父类，sub 表示查找所有子类。",
            "required": True,
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
        return "class_hierarchy"

    @property
    def description(self) -> str:
        return (
            "查找指定类的所有父类或所有子类。\n"
            "注意：依赖包中的类的子类无法找到，但可以在项目类中找到依赖包中的父类。\n"
            "使用方式：传入 className 和 type 参数（super 或 sub）。"
        )

    def _find_super_classes(self, class_name: str, path: Path) -> List[dict]:
        """查找父类"""
        results = []
        simple_name = class_name.split(".")[-1]

        # 搜索 extends 和 implements 语句
        patterns = [
            rf"class\s+\w+\s+extends\s+{simple_name}\b",
            rf"class\s+\w+\s+implements\s+[^{{}}]*{simple_name}[^{{}}]*\b",
            rf"interface\s+\w+\s+extends\s+{simple_name}\b",
        ]

        for pattern in patterns:
            try:
                argv = ["--json", "--hidden", "--glob=!.git/*", "--max-count=50"]
                argv.append("--")
                argv.append(pattern)
                argv.append(str(path.resolve()))

                proc = _run_rg(argv, cwd=str(path.resolve()))
                if proc.returncode not in (0, 1):
                    continue

                import json

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
                            results.append({
                                "class": data.get("line_number"),
                                "line": lines_o.get("text", ""),
                                "file": path_o.get("text", ""),
                                "type": "super",
                            })
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue

        return results

    def _find_sub_classes(self, class_name: str, path: Path) -> List[dict]:
        """查找子类"""
        results = []
        simple_name = class_name.split(".")[-1]

        # 搜索继承该类的语句
        patterns = [
            rf"extends\s+{simple_name}\b",
            rf"implements\s+[^{{}}]*{simple_name}[^{{}}]*\b",
        ]

        for pattern in patterns:
            try:
                argv = ["--json", "--hidden", "--glob=!.git/*", "--max-count=50"]
                argv.append("--")
                argv.append(pattern)
                argv.append(str(path.resolve()))

                proc = _run_rg(argv, cwd=str(path.resolve()))
                if proc.returncode not in (0, 1):
                    continue

                import json

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
                            results.append({
                                "class": data.get("line_number"),
                                "line": lines_o.get("text", ""),
                                "file": path_o.get("text", ""),
                                "type": "sub",
                            })
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue

        return results

    def run(
        self,
        className: str = "",
        type: str = "",
        root: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        if not className:
            return ToolResult(
                success=False,
                error="className 参数是必需的",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        if not type:
            return ToolResult(
                success=False,
                error="type 参数是必需的，只能为 super 或 sub",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        if type not in ("super", "sub"):
            return ToolResult(
                success=False,
                error="type 参数只能为 super 或 sub",
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

        if type == "super":
            results = self._find_super_classes(className, path)
            result_type = "父类"
        else:
            results = self._find_sub_classes(className, path)
            result_type = "子类"

        return ToolResult(
            success=True,
            data={
                "className": className,
                "searchType": type,
                "resultType": result_type,
                "results": results,
            },
            meta={
                "root": str(path),
                "className": className,
                "type": type,
                "count": len(results),
            },
        )