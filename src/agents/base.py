# -*- coding: utf-8 -*-
"""
BaseAgent —— 所有 Agent 的公共基类。

提取 ChainAnalyzer / ChainConfirmer 中重复的 LLM 交互与工具执行逻辑：
  - _llm_step：单轮 LLM 调用，带重试、JSON 解析校验、对话自动回填
  - _execute_tool_call：统一的工具分发与错误处理
"""
import json
import logging
import traceback
from typing import Any, Dict, List, Optional

from src.core.event_span import EventSpan
from src.agents.brain import Brain
from src.agents.tool_output_limit import limit_tool_result
from src.core.event_bus import get_event_bus
from src.core.events import LogEvent
from src.core.task_control import ensure_task_running
from src.llm import LLMError
from src.tools.base import ERROR_CODE_CANCELLED

logger = logging.getLogger(__name__)


class BaseAgent:
    """所有需要 LLM 多轮对话 + 工具调用的 Agent 的公共基类。"""

    def __init__(self, brain: Optional[Brain] = None, max_retries: int = 3):
        self._brain = brain
        self.max_retries = max_retries

    @property
    def _agent_tag(self) -> str:
        """日志前缀，子类可覆写。"""
        return self.__class__.__name__

    def _publish_log(self, level: str, message: str) -> None:
        """经事件总线发布 LogEvent，由 handler 写入 logs 表；失败时仅回退到标准 logging。"""
        module = getattr(self, "MODULE_NAME", None) or self._agent_tag
        task_id = getattr(self._brain, "task_id", None) if self._brain else None
        try:
            get_event_bus().publish(
                LogEvent(level=level, module=module, message=message, task_id=task_id)
            )
        except Exception as ex:
            logger.debug("LogEvent publish failed: %s", ex)
            logger.log(
                getattr(logging, level.upper(), logging.INFO),
                "[%s] %s",
                module,
                message,
            )

    def _llm_step(self, conversation: List[Dict[str, str]]) -> tuple[None, int | Any, int | Any] | tuple[
        dict, Any, Any]:
        """
        执行一轮 LLM 调用。

        - 自动处理 JSON 解析失败的重试（回填纠正消息）
        - 成功返回解析后的 dict，失败返回 None
        - 每次成功/失败的响应都会追加到 conversation 中
        """
        task_id = getattr(self._brain, "task_id", None) if self._brain else None
        ensure_task_running(task_id or "")

        input_token, output_token = 0, 0
        for attempt in range(self.max_retries):
            ensure_task_running(task_id or "")
            try:
                result, input_token, output_token = self._brain.ask(conversation)
            except LLMError:
                # LLM 服务级致命错误（额度不足/鉴权失败/网络异常等）：
                # 绝不能吞成"空响应"后继续重试并标记完成，必须向上抛出，
                # 由编排层将任务标记为 failed。
                self._publish_log(
                    "ERROR",
                    f"[{self._agent_tag}] LLM 调用发生致命错误，终止当前流程（任务将标记为失败）",
                )
                raise
            except ValueError as e:
                conversation.append({"role": "assistant", "content": "(模型返回内容无法解析为JSON)"})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "INVALID_JSON",
                        "detail": str(e),
                        "requirement": "请严格按输出协议只返回一个JSON对象",
                    }, ensure_ascii=False),
                })
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] LLM 返回无法解析为 JSON (attempt {attempt + 1}/{self.max_retries}): {e!r}",
                )
                continue
            except Exception as e:
                logger.exception("[%s] LLM 调用异常: %s", self._agent_tag, e)
                tb = traceback.format_exc()
                tail = tb[-4000:] if len(tb) > 4000 else tb
                self._publish_log(
                    "ERROR",
                    f"[{self._agent_tag}] LLM 调用异常: {e!r}\n{tail}",
                )
                return None, input_token, output_token
            if result is None:
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] LLM 返回为空 (attempt {attempt + 1}/{self.max_retries})",
                )
                continue
            if isinstance(result, dict):
                content = json.dumps(result, ensure_ascii=False)
                conversation.append({"role": "assistant", "content": content})
                return result, input_token, output_token
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] LLM 返回非 JSON 对象 (attempt {attempt + 1}/{self.max_retries}) {str(result)[:200]}",
            )
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "EXPECTED_JSON_OBJECT",
                    "requirement": "请返回一个JSON对象，包含 action 字段，禁止发送补全代码等非系统要求信息。",
                }, ensure_ascii=False),
            })
        self._publish_log(
            "WARNING",
            f"[{self._agent_tag}] LLM 已达最大重试 {self.max_retries} 次仍无有效响应",
        )
        return None, input_token, output_token

    def _bump_consecutive_invalid_action(
        self,
        conversation: List[Dict[str, str]],
        consecutive_invalid_action: int,
        *,
        threshold: int = 3,
    ) -> int:
        """
        连续 INVALID_ACTION 计数 +1；达到 threshold 时将 conversation[0] 的 system 消息再附加一次。
        返回更新后的连续计数（重新附加 system 后归零）。
        """
        count = consecutive_invalid_action + 1
        if count >= threshold and conversation and conversation[0].get("role") == "system":
            conversation.append(dict(conversation[0]))
            self._publish_log(
                "INFO",
                f"[{self._agent_tag}] 连续 {threshold} 次 INVALID_ACTION，已重新附加 system 提示",
            )
            return 0
        return count

    def _execute_tool_call(
            self,
            step: Dict[str, Any],
            conversation: List[Dict[str, str]],
            event_span: EventSpan,
    ) -> Optional[Dict[str, Any]]:
        """
        统一的工具调用分发。

        从 step 中提取 tool_name + arguments，调用 Brain 的工具注册表执行。
        tool_name 为空时向 conversation 追加错误提示并返回 None。
        code_agent 走独立的 session fork 逻辑。
        """
        tool_name = step.get("tool_name", "")
        arguments = step.get("arguments", {}) or {}
        if not tool_name:
            self._publish_log("WARNING", f"[{self._agent_tag}] tool_call 缺少 tool_name")
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "MISSING_TOOL_NAME",
                    "requirement": "tool_call 时 tool_name 不能为空",
                }, ensure_ascii=False),
            })
            return None
        if tool_name == "code_agent":
            return self._run_code_agent(tool_name, arguments, event_span)
        try:
            result = self._brain.run_tool(tool_name, **arguments)
            if isinstance(result, dict):
                if not result.get("success", True):
                    self._publish_log(
                        "WARNING",
                        f"[{self._agent_tag}] 工具 {tool_name!r} 返回 success=False | "
                        f"error={result.get('error')!r}",
                    )
                if self._brain is not None:
                    return limit_tool_result(
                        result,
                        self._brain.tmp_dir,
                        tool_name=tool_name,
                    )
            return result
        except Exception as e:
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] 工具 {tool_name!r} 执行异常: {e!r}",
            )
            return {"success": False, "error": str(e), "error_code": "TOOL_EXECUTION_FAILED"}

    def _run_code_agent(
            self,
            tool_name: str,
            arguments: Dict[str, Any],
            event_span: EventSpan,
    ) -> Optional[Dict[str, Any]]:
        """运行 code_agent（OpenCodeTool）。

        - 传入 event_id：让 opencode 在 SSE 流中把每条事件实时落库到 opencode_events，
          并把 step-finish 累计 token 实时回写到 events.code_agent_*_delta。
        - 结束后把累计 token 写到 EventSpan；add_* 与 finish 会按当前总量发 TokenEvent，
          经 ``report_token_usage`` 对绑定 event 的账本行覆盖写；任务 token 由对 ledger 聚合得到。
        """
        try:
            arguments["event_id"] = event_span.event_id
            arguments['task_id'] = self._brain.task_id
            result = self._brain.run_tool(tool_name, **arguments)
            if (result or {}).get("error_code") == ERROR_CODE_CANCELLED:
                ensure_task_running(self._brain.task_id)
            # Brain.run_tool 走 ToolRegistry.invoke，统一返回 dict（ToolResult.to_dict()）
            data = dict((result or {}).get("data") or {})
            token_input = data.pop("token_input", 0) or 0
            token_output = data.pop("token_output", 0) or 0
            event_span.add_code_agent_tokens(token_input, token_output)
            event_span.set_output(json.dumps(result))
            if isinstance(result, dict) and not result.get("success", True):
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] code_agent 返回 success=False | error={result.get('error')!r}",
                )
            return result
        except Exception as e:
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] code_agent 执行异常: {e!r}",
            )
            return {"success": False, "error": str(e), "error_code": "TOOL_EXECUTION_FAILED"}
