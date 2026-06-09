# -*- coding:utf-8 -*-
# @name: brain
# @auth: rainy-autumn@outlook.com
# @version:
"""Brain：一个任务的共享 LLM + 工具门面。

OpenCode 配置：
- 构造 Brain 时若 `opencode_runtime` 未显式传入，会通过 `config_service.get_opencode_runtime_config()`
  从 DB 读取。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.agents.context import BrainContext
from src.core.event_bus import get_event_bus
from src.core.event_span import event_span
from src.core.events import LogEvent, TaskStatusEvent, TokenEvent
from src.llm import LLMClient
from src.tools import BaseTool, get_default_registry
from src.tools.mcp_bridge.gitnexus import (
    GitNexusMcpBridge,
    register_gitnexus_tools,
    resolve_gitnexus_repo_name,
    run_gitnexus_analyze,
)
from src.utils.git_repo import ensure_git_repo_initialized
from src.utils import parse_json
from src.tmp_dir import task_tmp_dir

logger = logging.getLogger(__name__)


def _short(text: Any, limit: int = 4000) -> str:
    s = text if isinstance(text, str) else repr(text)
    if len(s) <= limit:
        return s
    return s[:limit] + f"...(truncated {len(s) - limit} chars)"


class Brain:
    """LLM 大脑 —— 存储任务信息 + 项目基础信息 + 工具注册表。"""

    DEFAULT_MODULE = "Brain"

    def __init__(self, context: BrainContext, **kwargs):
        self.tools: Dict[str, BaseTool] = {}
        self.project_id = context.project_id
        self.project_name = context.project_name
        self.project_path = context.project_path
        self.task_id = context.task_id
        self.offline_mode = context.offline_mode

        # 脱机模式：不初始化 LLMClient（避免 litellm 依赖）
        if context.offline_mode:
            self.llm = None
        else:
            self.llm = LLMClient(context.llm_config)
        self.tool_registry = get_default_registry(self.project_path)

        self._bus = get_event_bus()
        self.module_name = kwargs.get("module_name", self.DEFAULT_MODULE)

        self.tmp_dir = task_tmp_dir(self.task_id)
        if not self.tmp_dir.exists():
            self.tmp_dir.mkdir(parents=True, exist_ok=True)

        if not self.offline_mode:
            self._init_code_agent(kwargs.get("opencode_runtime"))
        else:
            self._log("INFO", "[Brain] 脱机模式，跳过 OpenCode 初始化")

        self.project_info_session_id = ""

        self.project_info = "项目根目录：" + context.project_path + "\n"
        self.project_info_compact = "项目根目录：" + context.project_path + "\n"
        self.plan = ""
        self.risk_files: list = []  # SmartFileFilter 识别的高风险文件
        self.quick_scan_findings: list = []  # QuickScanService 快速扫描结果
        self.gapfill_tasks: list = []  # CoverageTracker 防漏报兜底任务
        self.llm_input_token = 0
        self.llm_output_token = 0
        self.code_count_str = ""
        self.code_count_json = {}

        self._gitnexus_bridge: Optional[GitNexusMcpBridge] = None
        if not self.offline_mode:
            try:
                proj_root = str(Path(self.project_path).resolve())
                ok_git, git_msg = ensure_git_repo_initialized(proj_root)
                if not ok_git:
                    self._log("WARNING", f"[GitNexus] Git 仓库检查: {git_msg}")
                # 创建【GitNexus初始化】事件
                self._log("INFO", f"[GitNexus] 开始 analyze | root={proj_root}")
                logger.info("[GitNexus] 开始 analyze | task_id=%s root=%s", self.task_id, proj_root)
                ok_az, az_msg = run_gitnexus_analyze(proj_root)
                if ok_az:
                    self._log("INFO", f"[GitNexus] analyze 成功: {_short(az_msg, 500)}")
                    logger.info(
                        "[GitNexus] analyze 成功 | task_id=%s %s",
                        self.task_id,
                        _short(az_msg, 500),
                    )
                else:
                    self._log(
                        "WARNING",
                        f"[GitNexus] analyze 未成功（仍将尝试连接 MCP，若索引已存在可忽略）: {az_msg}",
                    )
                default_repo = resolve_gitnexus_repo_name(proj_root) or Path(proj_root).name
                bridge = GitNexusMcpBridge.from_env(default_repo=default_repo)
                bridge.start()
                register_gitnexus_tools(self.tool_registry, bridge)
                self._gitnexus_bridge = bridge
            except Exception as e:
                self._log("ERROR", f"[GitNexus] 初始化失败: {e}")
        else:
            self._log("INFO", "[Brain] 脱机模式，跳过 GitNexus 初始化")

    # ---------------- 初始化辅助 ----------------
    def _init_code_agent(self, runtime_override: Any) -> None:
        try:
            runtime = runtime_override
            if runtime is None:
                from src.services.config_service import get_opencode_runtime_config

                runtime = get_opencode_runtime_config()

            if runtime is None:
                self._emit_log_only(
                    "WARNING", "未检测到 code_agent_config（OpenCode），跳过注册 code_agent 工具"
                )
                return

            model_id = getattr(runtime, "model_id", None) or "deepseek-chat"
            provider_id = getattr(runtime, "provider_id", None) or "deepseek"
            from src.tools.opencode import OpenCodeTool
            tool = OpenCodeTool(
                project_path=self.project_path,
                model_id=model_id,
                provider_id=provider_id,
            )
            if not tool.status:
                self._bus.publish(
                    TaskStatusEvent(
                        task_id=self.task_id,
                        status="failed",
                        message="opencode 初始化探测失败",
                    )
                )
                raise RuntimeError("opencode 初始化探测失败")
            self._emit_log_only("INFO", f"初始化 code_agent URL: {tool.get_url()}")
            tool.name = "code_agent"
            self.tools["code_agent"] = tool
            self.tool_registry.register(tool)
        except Exception as ex:  # pragma: no cover
            self._emit_log_only("ERROR", f"初始化 code_agent 失败: {ex}")
            raise

    # ---------------- 日志辅助 ----------------
    def _log(self, level: str, message: str) -> None:
        try:
            get_event_bus().publish_async(
                LogEvent(level=level, module=self.module_name, message=message, task_id=self.task_id)
            )
        except Exception:
            pass

    def _emit_log_only(self, level: str, message: str) -> None:
        try:
            get_event_bus().publish_async(
                LogEvent(level=level, module=self.DEFAULT_MODULE, message=message, task_id=self.task_id)
            )
        except Exception:
            logger.log(getattr(logging, level.upper(), logging.INFO), "[%s] %s", self.DEFAULT_MODULE, message)

    # ---------------- LLM / 工具调用 ----------------
    def ask(
        self,
        messages: List[Dict[str, str]],
    ):
        # 简单截断：对话过长时仅保留 system 消息 + 最近 8 条
        if len(messages) > 20:
            system_msgs = [m for m in messages if m.get("role") == "system"]
            non_system = [m for m in messages if m.get("role") != "system"]
            messages = system_msgs + non_system[-8:]

        if self.llm is None:
            raise RuntimeError("[Brain] 脱机模式下不支持 LLM 调用")

        resp = self.llm.call(messages)
        parsed = parse_json(resp.content)
        if not isinstance(parsed, dict):
            logger.warning(
                "[Brain] LLM 返回非 dict 类型（type=%s）| "
                "raw_content_len=%d raw_content_preview=%r",
                type(parsed).__name__,
                len(resp.content),
                resp.content[:300],
            )
        return parsed, resp.prompt_tokens, resp.completion_tokens, resp.cached_tokens

    def run_tool(
        self,
        tool_name: str,
        **arguments,
    ) -> Dict[str, Any]:
        return self.tool_registry.invoke(tool_name, **arguments)

    def set_project_info_session_id(self, session_id: str) -> None:
        self.project_info_session_id = session_id

    def get_project_info_session_id(self) -> str:
        return self.project_info_session_id

    def run(self):
        pass

    def wait_for_human_approval(
        self,
        message: str,
        *,
        timeout_seconds: int = 60,
        auto_approve_on_timeout: bool = True,
        interaction_id: str,
        interaction_type: str,
    ) -> Dict[str, Any]:
        """手动触发人工确认，直到用户确认或超时。"""
        from src.services.human_interaction_service import request_approval

        return request_approval(
            task_id=self.task_id,
            message=message,
            timeout_seconds=timeout_seconds,
            auto_approve_on_timeout=auto_approve_on_timeout,
            interaction_id=interaction_id,
            interaction_type=interaction_type
        )

    def get_tool(self, name: str) -> BaseTool:
        if not self.tools:
            raise RuntimeError("Tool registry is empty")
        tool = self.tools.get(name)
        if tool is None:
            raise RuntimeError(f"Tool not found: {name}")
        return tool
