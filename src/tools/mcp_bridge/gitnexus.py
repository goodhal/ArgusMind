# -*- coding: utf-8 -*-
"""GitNexus MCP 桥接：子进程 stdio 连接 `npx gitnexus mcp`，注册 query / cypher / context / impact 四个远端工具及本地派生 symbol 工具。

本项目的 MCP 适配代码放在包名 `mcp_bridge` 下，避免与 PyPI 官方库 `mcp` 同名导致 `from mcp import …` 解析到本地目录。

使用前请在目标仓库根目录执行 `npx gitnexus analyze` 建立索引；详见
https://github.com/abhigyanpatwari/GitNexus
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.tools.base import (
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_UNKNOWN,
    BaseTool,
    ToolResult,
)
from src.tools.registry import ToolRegistry

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.types import PaginatedRequestParams
except ImportError:
    ClientSession = None  # type: ignore[misc, assignment]
    StdioServerParameters = None  # type: ignore[misc, assignment]
    stdio_client = None  # type: ignore[misc, assignment]
    PaginatedRequestParams = None  # type: ignore[misc, assignment]

# 远端 MCP 工具名 -> 本地注册名（其余 discovered 工具不注册）
_GITNEXUS_REGISTER_MAP: Dict[str, str] = {
    "query": "gitnexus_query",
    "cypher": "gitnexus_cypher",
    "context": "gitnexus_context",
    "impact": "gitnexus_impact",
}

_JSON_TYPE_TO_INTERNAL = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "object": "object",
    "array": "array",
}
logger = logging.getLogger(__name__)


def _normalize_json_type(t: Any) -> str:
    if t is None:
        return "string"
    if isinstance(t, list):
        for x in t:
            if x != "null":
                return str(x)
        return "string"
    return str(t)


def json_schema_to_parameters_schema(schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """将 MCP inputSchema（JSON Schema object）转为 BaseTool 的 _parameters_schema 列表。"""
    if not schema or not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    required = set(schema.get("required") or [])
    out: List[Dict[str, Any]] = []
    for pname, spec in props.items():
        if not isinstance(spec, dict):
            continue
        jt = _normalize_json_type(spec.get("type"))
        internal = _JSON_TYPE_TO_INTERNAL.get(jt, "str")
        desc = (spec.get("description") or spec.get("title") or "").strip()
        if jt in ("object", "array") and desc:
            desc = f"{desc}（可为 JSON 对象/数组，按模型输出解析）"
        elif jt in ("object", "array"):
            desc = "JSON 对象或数组（按模型输出解析）"
        out.append(
            {
                "name": pname,
                "type": internal,
                "description": desc or f"参数 {pname}",
                "required": pname in required,
            }
        )
    return out


def _tool_input_schema(tool: Any) -> Optional[Dict[str, Any]]:
    if hasattr(tool, "inputSchema") and tool.inputSchema is not None:
        s = tool.inputSchema
        return s if isinstance(s, dict) else None
    if hasattr(tool, "input_schema") and tool.input_schema is not None:
        s = tool.input_schema
        return s if isinstance(s, dict) else None
    return None


def _extract_text_from_content(content: Any) -> str:
    if not content:
        return ""
    parts: List[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(str(text))
            continue
        if isinstance(block, dict):
            if block.get("type") == "text" and "text" in block:
                parts.append(str(block["text"]))
    return "\n".join(parts)


_GITNEXUS_NEXT_COACHING_MARKER = "\n\n---\n**Next:**"


def _strip_gitnexus_coaching_suffix(s: str) -> str:
    """去掉 GitNexus 在文本里附加的 **Next:** 建议段（从分隔线起至文末）。"""
    if not s or _GITNEXUS_NEXT_COACHING_MARKER not in s:
        return s
    return s.split(_GITNEXUS_NEXT_COACHING_MARKER, 1)[0].rstrip()


_CONTEXT_STRIP_KEYS = ("incoming", "outgoing", "processes")


def _tool_result_structured_payload(tr: ToolResult) -> Any:
    """从 ToolResult 取出 GitNexus context 的结构化 JSON（dict / list）。"""
    data = tr.data
    if isinstance(data, dict) and "structured" in data:
        return data["structured"]
    if isinstance(data, dict) and "status" in data:
        return data
    if isinstance(data, str) and data.strip():
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data
    return data


def filter_context_to_symbol_payload(payload: Any) -> Any:
    """去掉 context 结果中的 incoming / outgoing / processes，保留 status、symbol、candidates 等。"""
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    for key in _CONTEXT_STRIP_KEYS:
        out.pop(key, None)
    return out


def call_tool_result_to_tool_result(result: Any) -> ToolResult:
    """将 MCP CallToolResult 转为项目统一的 ToolResult。"""
    is_error = bool(getattr(result, "is_error", False))
    content = getattr(result, "content", None)
    text = _extract_text_from_content(content)
    structured = getattr(result, "structured_content", None)

    if is_error:
        msg = text or "GitNexus MCP 工具返回错误"
        return ToolResult(success=False, error=msg, error_code=ERROR_CODE_EXTERNAL, meta={})

    text = _strip_gitnexus_coaching_suffix(text)
    if structured is not None:
        data: Any = {"text": text, "structured": structured} if text else structured
    else:
        data = text
    return ToolResult(success=True, data=data, meta={})


def _parse_mcp_args_from_env() -> List[str]:
    return ["-y", "gitnexus", "mcp"]


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def resolve_gitnexus_repo_name(project_path: Union[str, Path]) -> Optional[str]:
    """
    根据本地项目路径，在 ~/.gitnexus/registry.json 中查找 GitNexus 登记的 repo 名称（`name` 字段）。
    找不到时返回 None（调用方可再用目录名等作为回退）。
    """
    reg = Path.home() / ".gitnexus" / "registry.json"
    if not reg.is_file():
        return None
    try:
        raw = reg.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return None
    target = str(Path(project_path).resolve())
    entries: List[Any]
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = (
                data.get("repos")
                or data.get("repositories")
                or data.get("entries")
                or []
        )
        if not isinstance(entries, list):
            entries = []
    else:
        return None
    for e in entries:
        if not isinstance(e, dict):
            continue
        p = e.get("path")
        if not p:
            continue
        try:
            if str(Path(p).resolve()) == target:
                name = e.get("name")
                if name:
                    return str(name)
        except OSError:
            continue
    return None


def run_gitnexus_analyze(
        project_path: Union[str, Path],
        *,
        timeout: Optional[float] = None,
) -> Tuple[bool, str]:
    """
    在仓库根目录执行 `npx -y gitnexus@latest analyze`（与官方 CLI 一致）。
    extra_args 可传如 ["--skip-embeddings"]；未传时使用环境变量 GITNEXUS_ANALYZE_EXTRA（空格分隔或 JSON 数组）。
    timeout 默认取自环境 GITNEXUS_ANALYZE_TIMEOUT 或 3600 秒。
    """
    gitnexus_cmd = shutil.which("gitnexus")
    if not gitnexus_cmd:
        return False, "未找到 gitnexus，无法执行 gitnexus analyze"
    root = Path(project_path).resolve()
    if not root.is_dir():
        return False, f"项目路径不是目录: {root}"
    if timeout is None:
        try:
            timeout = float(os.getenv("GITNEXUS_ANALYZE_TIMEOUT", "3600"))
        except ValueError:
            timeout = 3600.0
    cmd: List[str] = [gitnexus_cmd, "analyze", project_path]
    env = os.environ.copy()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
    except OSError as e:
        return False, f"执行 analyze 失败: {e}"

    out_lines: List[str] = []
    err_lines: List[str] = []

    def _pump(pipe: Any, sink: List[str], to_stderr: bool = False) -> None:
        for line in iter(pipe.readline, ""):
            if not line:
                break
            text = line.rstrip("\r\n")
            if to_stderr:
                logger.error("[gitnexus analyze] %s", text)
            else:
                logger.info("[gitnexus analyze] %s", text)
            sink.append(line)
        pipe.close()

    try:
        assert proc.stdout is not None
        assert proc.stderr is not None
        t_out = threading.Thread(target=_pump, args=(proc.stdout, out_lines), daemon=True)
        t_err = threading.Thread(target=_pump, args=(proc.stderr, err_lines, True), daemon=True)
        t_out.start()
        t_err.start()
        proc.wait(timeout=timeout)
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, f"gitnexus analyze 超时（{timeout}s）"

    out = "".join(out_lines).strip()
    err = "".join(err_lines).strip()
    tail = (out or err)[-800:] if (out or err) else ""
    if proc.returncode != 0:
        return False, f"gitnexus analyze 退出码 {proc.returncode}: {tail}"
    return True, tail or "gitnexus analyze 完成"


class GitNexusMcpBridge:
    """
    在后台线程中维持一条 MCP stdio 会话，供多个 GitNexusMcpTool 共享。
    """

    def __init__(
            self,
            command: str,
            args: List[str],
            extra_env: Optional[Dict[str, str]] = None,
            default_repo: Optional[str] = None,
    ):
        if ClientSession is None or stdio_client is None:
            raise ImportError(
                "接入 GitNexus MCP 需要安装 mcp：pip install \"argusmind[gitnexus]\" 或 pip install mcp"
            )
        self._command = command
        self._args = args
        self._extra_env = extra_env or {}
        self._default_repo = (default_repo or "").strip() or None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._session: Any = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self._start_error: Optional[BaseException] = None
        self._discovered_tools: List[Any] = []

    @classmethod
    def from_env(cls, default_repo: Optional[str] = None) -> GitNexusMcpBridge:
        cmd = "npx"
        args = _parse_mcp_args_from_env()
        extra: Dict[str, str] = {}
        return cls(
            command=cmd,
            args=args,
            extra_env=extra if extra else None,
            default_repo=default_repo or None,
        )

    @property
    def default_repo(self) -> Optional[str]:
        """传给 GitNexus MCP 工具时自动填充的 `repo`（登记名，非必须等于磁盘路径）。"""
        return self._default_repo

    @staticmethod
    def enabled_from_env() -> bool:
        return _env_truthy("GITNEXUS_MCP_ENABLED") or _env_truthy("GITNEXUS_MCP")

    def start(self, timeout: float = 90.0) -> None:
        if self._thread and self._thread.is_alive():
            return

        def runner() -> None:
            asyncio.run(self._async_main())

        self._start_error = None
        self._started.clear()
        self._stop.clear()
        self._thread = threading.Thread(target=runner, name="gitnexus-mcp", daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):
            self._stop.set()
            raise TimeoutError(f"GitNexus MCP 在 {timeout}s 内未完成握手（检查 Node/npx 与 gitnexus 是否可用）")
        if self._start_error is not None:
            raise RuntimeError(f"GitNexus MCP 启动失败: {self._start_error}") from self._start_error

    async def _list_all_tools(self, session: Any) -> List[Any]:
        tools: List[Any] = []
        cursor: Any = None
        while True:
            params = PaginatedRequestParams(cursor=cursor) if cursor else None  # type: ignore[misc]
            result = await session.list_tools(params=params)
            tools.extend(result.tools)
            cursor = getattr(result, "nextCursor", None) or getattr(result, "next_cursor", None)
            if not cursor:
                break
        return tools

    async def _async_main(self) -> None:
        try:
            env = os.environ.copy()
            env.update(self._extra_env)
            params = StdioServerParameters(command=self._command, args=self._args, env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._loop = asyncio.get_running_loop()
                    self._discovered_tools = await self._list_all_tools(session)
                    self._session = session
                    self._started.set()
                    while not self._stop.is_set():
                        await asyncio.sleep(0.2)
        except BaseException as e:
            self._start_error = e
            self._started.set()

    def stop(self) -> None:
        self._stop.set()

    def call_tool_sync(self, mcp_tool_name: str, arguments: Optional[Dict[str, Any]], timeout: float = 180.0) -> Any:
        if self._loop is None or self._session is None:
            return ToolResult(
                success=False,
                error="GitNexus MCP 未连接",
                error_code=ERROR_CODE_UNKNOWN,
                meta={"mcp_tool": mcp_tool_name},
            )
        coro = self._session.call_tool(mcp_tool_name, arguments)
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            return ToolResult(
                success=False,
                error=f"调用 {mcp_tool_name} 超时（{timeout}s）",
                error_code=ERROR_CODE_TIMEOUT,
                meta={"mcp_tool": mcp_tool_name},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_EXTERNAL,
                meta={"mcp_tool": mcp_tool_name},
            )

    @property
    def discovered_tools(self) -> List[Any]:
        return list(self._discovered_tools)


class GitNexusMcpTool(BaseTool):
    """单个 GitNexus MCP 工具的本地代理（注册名带前缀，避免与内置工具冲突）。"""

    def __init__(
            self,
            bridge: GitNexusMcpBridge,
            mcp_tool: Any,
            registry_name: str,
    ):
        self._bridge = bridge
        self._mcp_name = getattr(mcp_tool, "name", "") or ""
        desc = (getattr(mcp_tool, "description", None) or "").strip()
        self._description = (
            f"{desc}".strip()
        )
        self._registry_name = registry_name
        schema = json_schema_to_parameters_schema(_tool_input_schema(mcp_tool))
        self._parameters_schema = schema
        self._has_repo_param = any(p.get("name") == "repo" for p in schema)

    @property
    def name(self) -> str:
        return self._registry_name

    @property
    def description(self) -> str:
        return self._description

    def get_parameters_schema(self) -> List[Dict[str, Any]]:
        return self._parameters_schema

    def run(self, **kwargs: Any) -> ToolResult:
        args = {k: v for k, v in kwargs.items() if v is not None}
        if args.get("repo") == "":
            del args["repo"]
        if (
                self._bridge.default_repo
                and self._has_repo_param
                and "repo" not in args
        ):
            args["repo"] = self._bridge.default_repo
        args_dict: Optional[Dict[str, Any]] = args if args else None
        raw = self._bridge.call_tool_sync(self._mcp_name, args_dict)
        if isinstance(raw, ToolResult):
            return raw
        return call_tool_result_to_tool_result(raw)


class GitNexusSymbolTool(BaseTool):
    """
    基于远端 ``context`` 的符号定义查询：仅返回定义位置与可选源码，不含调用关系与执行流。
    """

    _PARAMS_SCHEMA: List[Dict[str, Any]] = [
        {
            "name": "name",
            "type": "str",
            "description": "符号名（函数、类、方法等），如 validateUser、AuthService",
            "required": True,
        },
        {
            "name": "file_path",
            "type": "str",
            "description": "文件路径，用于消歧同名符号",
            "required": False,
        },
        {
            "name": "include_content",
            "type": "bool",
            "description": "是否在 symbol 中包含完整源码（默认 false，仅返回位置信息）",
            "required": False,
        },
    ]

    def __init__(self, bridge: GitNexusMcpBridge):
        self._bridge = bridge
        self._parameters_schema = list(self._PARAMS_SCHEMA)

    @property
    def name(self) -> str:
        return "gitnexus_symbol"

    @property
    def description(self) -> str:
        return (
            "根据符号名查找函数/类等定义位置与源码。"
            "基于代码知识图谱，不含调用方、被调方与执行流（精简版 gitnexus_context）。"
            "同名多义时返回 candidates 供选择；可用 file_path 消歧。"
        )

    def get_parameters_schema(self) -> List[Dict[str, Any]]:
        return self._parameters_schema

    def run(self, **kwargs: Any) -> ToolResult:
        name = kwargs.get("name")
        if not name or not str(name).strip():
            return ToolResult(
                success=False,
                error="缺少必填参数 name",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"tool": self.name},
            )

        args: Dict[str, Any] = {"name": str(name).strip()}
        file_path = kwargs.get("file_path")
        if file_path:
            args["file_path"] = str(file_path)
        if kwargs.get("include_content") is True:
            args["include_content"] = True
        elif kwargs.get("include_content") is False:
            args["include_content"] = False

        if self._bridge.default_repo:
            args["repo"] = self._bridge.default_repo

        raw = self._bridge.call_tool_sync("context", args)
        if isinstance(raw, ToolResult):
            tr = raw
        else:
            tr = call_tool_result_to_tool_result(raw)
        if not tr.success:
            return tr

        payload = _tool_result_structured_payload(tr)
        if isinstance(payload, dict):
            return ToolResult(
                success=True,
                data=filter_context_to_symbol_payload(payload),
                meta={"mcp_tool": "context", "derived_tool": self.name},
            )
        return ToolResult(success=True, data=payload, meta={"mcp_tool": "context", "derived_tool": self.name})


def register_gitnexus_tools(
        registry: ToolRegistry,
        bridge: GitNexusMcpBridge,
        name_prefix: Optional[str] = None,
) -> int:
    """
    将 bridge 已发现的 MCP 工具中，仅 _GITNEXUS_REGISTER_MAP 列出的远端名注册到 ToolRegistry。
    name_prefix 参数已忽略（保留签名以兼容旧调用）。
    返回注册的工具数量。
    """
    _ = name_prefix  # 固定使用 _GITNEXUS_REGISTER_MAP 中的本地名
    by_mcp: Dict[str, Any] = {}
    for t in bridge.discovered_tools:
        mcp_name = getattr(t, "name", None)
        if mcp_name:
            by_mcp[str(mcp_name)] = t
    n = 0
    for mcp_name, reg_name in _GITNEXUS_REGISTER_MAP.items():
        t = by_mcp.get(mcp_name)
        if t is None:
            continue
        registry.register(GitNexusMcpTool(bridge, t, reg_name))
        n += 1
    if by_mcp.get("context") is not None:
        registry.register(GitNexusSymbolTool(bridge))
        n += 1
    return n
