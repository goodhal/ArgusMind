# -*- coding:utf-8 -*-　　
# @name: base
# @auth: rainy-autumn@outlook.com
# @version:
"""工具基类：统一接口、数据格式与 AI 可调用的 Schema。"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 常用错误码，供 AI 根据错误类型做分支（重试、换参数等）
ERROR_CODE_INVALID_ARGUMENT = "INVALID_ARGUMENT"
ERROR_CODE_NOT_FOUND = "NOT_FOUND"
ERROR_CODE_PERMISSION_DENIED = "PERMISSION_DENIED"
ERROR_CODE_TIMEOUT = "TIMEOUT"
ERROR_CODE_EXTERNAL = "EXTERNAL"
ERROR_CODE_UNKNOWN = "UNKNOWN"
ERROR_CODE_UNAVAILABLE = "UNAVAILABLE"
ERROR_CODE_CANCELLED = "CANCELLED"

_TYPE_MAP = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "object": "object",
    "array": "array",
}


@dataclass
class ToolResult:
    """
    工具执行结果。失败时 error/error_code 供 AI 判断并决定是否重试或换参数。
    """

    success: bool
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "meta": self.meta,
        }
        if self.error_code is not None:
            out["error_code"] = self.error_code
        return out

    def to_ai_message(self) -> str:
        """给 AI 看的简短说明。"""
        if self.success:
            return f"工具执行成功。结果: {self.data}"
        msg = f"工具执行失败: {self.error}"
        if self.error_code:
            msg += f" (error_code={self.error_code})"
        if self.meta:
            msg += f" | meta={self.meta}"
        return msg


class BaseTool(ABC):
    """
    工具基类。供 AI 自主调用时：
    - 通过 get_parameters_schema / to_openai_tool_schema 暴露参数说明；
    - 通过 run_safe 或 ToolRegistry.invoke 统一执行并捕获异常，返回 ToolResult。
    失败时应返回 ToolResult(success=False, error=..., error_code=...)，便于 AI 根据错误重试或换参数。
    """

    def __init__(self):
        self.event_id = None

    @property
    @abstractmethod
    def name(self) -> str:
        """工具名称，用于注册与路由。"""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """简要功能描述，供 Agent 或 UI 展示。"""
        ...

    @property
    def usage(self) -> str:
        """使用方法说明（参数、示例等），默认返回空字符串。"""
        return ""

    @property
    def status(self) -> bool:
        """工具是否可用（如依赖服务是否就绪）。"""
        return True

    def get_parameters_schema(self) -> List[Dict[str, Any]]:
        """
        返回参数列表 [{ "name", "type", "description", "required" }]，用于生成 LLM function/tool schema。
        子类可重写或通过 _parameters_schema 赋值。
        """
        return getattr(self, "_parameters_schema", [])

    def to_openai_tool_schema(self) -> Dict[str, Any]:
        """OpenAI function calling 格式的 tool 描述。"""
        params = self.get_parameters_schema()
        properties = {}
        required = []
        for p in params:
            name = p["name"]
            properties[name] = {
                "type": _TYPE_MAP.get(p.get("type", "str"), p.get("type", "string")),
                "description": p.get("description", ""),
            }
            if p.get("required", False):
                required.append(name)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }

    def to_prompt_description(self) -> str:
        """将工具说明转为提示词用原始文本，内容等价于 to_openai_tool_schema（含完整参数说明），仅格式改为可读文本。"""
        lines = [
            f"**工具名**: {self.name}",
            f"**描述**: {self.description}",
        ]
        params = self.get_parameters_schema()
        if params:
            lines.append("**参数**（调用时需按以下名称与类型传参）：")
            for p in params:
                name = p.get("name", "")
                # 与 to_openai_tool_schema 一致的类型表述
                ptype = _TYPE_MAP.get(p.get("type", "str"), p.get("type", "string"))
                desc = p.get("description", "") or "无说明"
                req = "必填" if p.get("required", False) else "可选"
                lines.append(f"  - {name} (类型: {ptype}, {req}): {desc}")
        return "\n".join(lines)

    def run(self, **kwargs) -> ToolResult:
        """
        执行工具。子类必须返回 ToolResult；失败时返回 success=False 并填写 error/error_code，不要抛异常。
        """
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")

    def run_safe(self, **kwargs) -> ToolResult:
        """
        安全执行 run()：捕获未处理异常并转为 ToolResult。推荐通过 ToolRegistry.invoke 统一调用。
        """
        try:
            return self.run(**kwargs)
        except Exception as e:
            code = ERROR_CODE_UNKNOWN
            if isinstance(e, (FileNotFoundError, NotADirectoryError)):
                code = ERROR_CODE_NOT_FOUND
            elif isinstance(e, PermissionError):
                code = ERROR_CODE_PERMISSION_DENIED
            elif isinstance(e, TimeoutError):
                code = ERROR_CODE_TIMEOUT
            elif isinstance(e, (ValueError, TypeError, KeyError)):
                code = ERROR_CODE_INVALID_ARGUMENT
            return ToolResult(
                success=False,
                error=str(e),
                error_code=code,
                meta=getattr(e, "meta", {}) or {"exception_type": type(e).__name__},
            )

    def create_session(self) -> str:
        return ""

    def set_event_id(self, event_id: int):
        self.event_id = event_id

    def fork(self, session_id: str) -> str:
        return ""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
