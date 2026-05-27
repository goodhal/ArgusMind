"""数据平面：工具封装。所有工具继承 BaseTool，统一 name/description/usage、ToolResult 与 AI 可调用的 schema。"""

from src.tools.base import (
    BaseTool,
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_PERMISSION_DENIED,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_UNAVAILABLE,
    ERROR_CODE_UNKNOWN,
    ToolResult,
)
from src.tools.filesystem import (
    ListFilesTool,
    ReadFileTool,
    ReadLinesTool,
)
from src.tools.ripgrep import RipgrepFilesTool, RipgrepSearchTool
from src.tools.registry import ToolRegistry, get_default_registry
from src.tools.tokei import TokeiTool

try:
    from src.tools.opencode import OpenCodeTool
except Exception:  # opencode_ai 未安装或导入失败
    OpenCodeTool = None  # type: ignore[misc, assignment]


def __getattr__(name: str):
    if name == "register_neo4j_tools":
        from src.tools.neo4j_tools import register_neo4j_tools

        return register_neo4j_tools
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolRegistry",
    "get_default_registry",
    "register_neo4j_tools",
    "ERROR_CODE_INVALID_ARGUMENT",
    "ERROR_CODE_NOT_FOUND",
    "ERROR_CODE_PERMISSION_DENIED",
    "ERROR_CODE_TIMEOUT",
    "ERROR_CODE_EXTERNAL",
    "ERROR_CODE_UNKNOWN",
    "ERROR_CODE_UNAVAILABLE",
    "ReadFileTool",
    "ReadLinesTool",
    "ListFilesTool",
    "RipgrepFilesTool",
    "RipgrepSearchTool",
    "TokeiTool",
    "OpenCodeTool",
]
