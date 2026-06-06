# -*- coding:utf-8 -*-
# @name: registry
# @auth: rainy-autumn@outlook.com
"""工具注册表与统一调用入口，供 AI 按名称调用并始终得到结构化结果。"""
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.tools.base import BaseTool, ToolResult, ERROR_CODE_UNAVAILABLE


class ToolRegistry:
    """
    工具注册表。负责：
    - 注册/获取工具
    - 按名称安全调用，统一返回 dict（ToolResult.to_dict()）
    - 导出所有工具的 OpenAI tool schema，供 LLM 选择调用
    """

    def __init__(self, project_path: str):
        self._tools: Dict[str, BaseTool] = {}
        self.project_path = project_path

    def register(self, tool: BaseTool) -> None:
        """注册一个工具，以 tool.name 为键。"""
        self._tools[tool.name] = tool

    def register_many(self, tools: List[BaseTool]) -> None:
        for t in tools:
            self.register(t)

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_names(self) -> List[str]:
        return list(self._tools.keys())

    def get_all_tools_schema(self) -> str:
        """返回所有已注册工具的说明文本（等价于 OpenAI function schema 的原始文本版，含名称、描述、参数类型与说明），用于拼接到提示词。"""
        return "GitNexus系列工具，参数 `repo`=`{self.project_path}`\n\n" + self.get_tools_schema(tool_names=None)

    def get_tools_schema(self, tool_names: Optional[Sequence[str]] = None) -> str:
        """
        导出工具说明文本，格式与 get_all_tools_schema 一致。
        - tool_names 为 None：包含当前注册表中的全部工具（顺序不保证稳定）。
        - tool_names 为序列：按给定顺序仅包含已注册的工具名；未注册的名称会跳过。
        """
        if tool_names is None:
            blocks = [t.to_prompt_description() for t in self._tools.values()]
        else:
            blocks = []
            for name in tool_names:
                t = self.get(name)
                if t is not None:
                    blocks.append(t.to_prompt_description())
        return f"\n\n".join(blocks)

    def get_tools_schema_excluding(self, excluded: Optional[Sequence[str]] = None) -> str:
        """
        导出工具说明文本，格式与 get_tools_schema 一致。
        包含当前注册表中除 excluded 所列名称外的全部工具；顺序与注册表中的键序一致。
        excluded 为 None 或空序列时，等价于 get_tools_schema(None)。
        """
        if not excluded:
            return self.get_tools_schema(None)
        skip = frozenset(excluded)
        names = [n for n in self._tools.keys() if n not in skip]
        return self.get_tools_schema(names)

    def invoke(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """
        按名称调用工具，始终返回 dict（ToolResult.to_dict()）。
        - 工具不存在：返回 success=False, error="Tool not found: xxx", error_code="NOT_FOUND"
        - 工具不可用（status=False）：返回 success=False, error="Tool unavailable", error_code="UNAVAILABLE"
        - 执行过程用 run_safe，异常会被捕获并转为 ToolResult
        这样 AI 总能拿到统一结构，根据 success/error/error_code 决定重试或换参数。
        """
        tool = self.get(tool_name)
        if tool is None:
            return ToolResult(
                success=False,
                error=f"Tool not found: {tool_name}；请检查调用协议是否准确",
                error_code="NOT_FOUND",
                meta={"requested_tool": tool_name},
            ).to_dict()
        if not getattr(tool, "status", True) or not tool.status:
            return ToolResult(
                success=False,
                error="Tool unavailable",
                error_code=ERROR_CODE_UNAVAILABLE,
                meta={"tool": tool_name},
            ).to_dict()
        result = tool.run_safe(**kwargs)
        return result.to_dict()


def get_default_registry(project_path) -> ToolRegistry:
    """返回已注册所有内置工具的默认注册表（ReadFile, ReadLines, ListFiles, Ripgrep, Neo4j, Tokei, OpenCode 需在调用方传入实例）。"""
    from src.tools.filesystem import ListFilesTool, ReadFileTool, ReadLinesTool
    from src.tools.neo4j_tools import register_neo4j_tools
    from src.tools.ripgrep import RipgrepFilesTool, RipgrepSearchTool
    from src.tools.remote_repo import RemoteRepoTool
    from src.tools.code_search import CodeSearchTool
    from src.tools.class_hierarchy import ClassHierarchyTool

    reg = ToolRegistry(project_path)
    base = Path(str(project_path)).expanduser().resolve(strict=False)
    reg.register(ReadFileTool(base_path=base))
    reg.register(ReadLinesTool(base_path=base))
    reg.register(ListFilesTool(base_path=base))
    reg.register(RipgrepFilesTool(base_path=base))
    reg.register(RipgrepSearchTool(base_path=base))
    reg.register(RemoteRepoTool())
    reg.register(CodeSearchTool(base_path=base))
    reg.register(ClassHierarchyTool(base_path=base))
    # OpenCodeTool 需要 project_path 等构造参数，由上层创建后 register
    return reg
