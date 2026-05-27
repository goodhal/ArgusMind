"""LLM 事件 span：把"开始-结束"配对的 LLM/工具调用事件封装为上下文管理器。

使用示例::

    from src.core.event_span import event_span

    with event_span(task_id=tid, module="ChainAnalyzer", action_type="llm_call",
                        reason="根据 sink 点推导链路") as span:
        resp = llm.call(messages)
        span.set_output(resp.content)
        span.add_llm_tokens(resp.prompt_tokens, resp.completion_tokens)
        # 内存累加后按当前总量上报 token_ledger（绑定 event_id 覆盖写）；events 行由 finish_event 写入
        # 若过程中抛异常，span 退出时会自动标记 failed
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.core.event_bus import get_event_bus
from src.core.events import EventEnd, EventStart, TokenEvent


class EventSpan:
    def __init__(
        self,
        *,
        task_id: Optional[str],
        module: str,
        action_type: str,
        tool_name: str = "",
        reason: str = "",
        tool_arguments: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.task_id = task_id
        self.module = module
        self.action_type = action_type
        self.tool_name = tool_name
        self.reason = reason
        self.tool_arguments = tool_arguments

        self.event_id: Optional[int] = None
        self._output: Optional[str] = None
        self._cot: Optional[List[Dict[str, Any]]] = None
        self._final_status: str = ""
        self._status: str = "completed"
        self._llm_input = 0
        self._llm_output = 0
        self._code_agent_input = 0
        self._code_agent_output = 0
        self._bus = get_event_bus()
        self._started = False
        self._finished = False

    # ---------- 外部接口 ----------
    def set_output(self, text: Optional[str]) -> None:
        self._output = text

    def set_chain_of_thought(self, cot: Optional[List[Dict[str, Any]]]) -> None:
        self._cot = cot

    def set_final_status(self, status: str) -> None:
        self._final_status = status or ""

    def mark_failed(self, message: str = "") -> None:
        self._status = "failed"
        if message and not self._final_status:
            self._final_status = message
        self.finish()

    def add_llm_tokens(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        di = int(input_tokens or 0)
        do = int(output_tokens or 0)
        self._llm_input += di
        self._llm_output += do
        self._publish_token_usage_if_running()

    def add_code_agent_tokens(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        di = int(input_tokens or 0)
        do = int(output_tokens or 0)
        self._code_agent_input += di
        self._code_agent_output += do
        self._publish_token_usage_if_running()

    def _publish_token_usage_if_running(self) -> None:
        """将 span 内当前四列总量写入 token_ledger（绑定本 event_id，覆盖同一行）。"""
        if not self.task_id or not self._started or not self.event_id:
            return
        if (
            not self._llm_input
            and not self._llm_output
            and not self._code_agent_input
            and not self._code_agent_output
        ):
            return
        self._bus.publish(
            TokenEvent(
                task_id=self.task_id,
                source_event_id=self.event_id,
                llm_input=self._llm_input,
                llm_output=self._llm_output,
                code_agent_input=self._code_agent_input,
                code_agent_output=self._code_agent_output,
                note=self.action_type,
            )
        )

    def start(self) -> "EventSpan":
        """发送 EventStart 并返回自身，便于函数式调用。"""
        if self._started:
            return self
        start = EventStart(
            task_id=self.task_id,
            module=self.module,
            action_type=self.action_type,
            tool_name=self.tool_name,
            reason=self.reason,
            tool_arguments=self.tool_arguments,
            status="running"
        )
        self.event_id = self._bus.publish(start)
        self._started = True
        return self

    def finish(self, exc_type=None, exc_val=None) -> None:
        """发送 EventEnd（并按需发送 TokenEvent）。可选传入异常信息。"""
        if self._finished:
            return
        if not self._started:
            self.start()
        if exc_type is not None:
            self._status = "failed"
            if not self._final_status:
                self._final_status = f"{exc_type.__name__}: {exc_val}"

        end = EventEnd(
            event_id=self.event_id or 0,
            status=self._status,
            final_status=self._final_status,
            tool_output=self._output,
            chain_of_thought=self._cot,
            llm_input_delta=self._llm_input,
            llm_output_delta=self._llm_output,
            code_agent_input_delta=self._code_agent_input,
            code_agent_output_delta=self._code_agent_output,
        )
        self._bus.publish(end)
        # 与 add_* 内上报总量一致；再发一次为覆盖写幂等（且兜底最后一次 add 未触发上报的路径）
        if self.task_id and self.event_id and (
            self._llm_input or self._llm_output or self._code_agent_input or self._code_agent_output
        ):
            self._bus.publish(
                TokenEvent(
                    task_id=self.task_id,
                    source_event_id=self.event_id,
                    llm_input=self._llm_input,
                    llm_output=self._llm_output,
                    code_agent_input=self._code_agent_input,
                    code_agent_output=self._code_agent_output,
                    note=self.action_type,
                )
            )
        self._finished = True

    # ---------- 上下文管理器 ----------
    def __enter__(self) -> "EventSpan":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.finish(exc_type=exc_type, exc_val=exc_val)
        return False  # 不吞掉异常


def event_span(
    *,
    task_id: Optional[str],
    module: str,
    action_type: str,
    tool_name: str = "",
    reason: str = "",
    tool_arguments: Optional[Dict[str, Any]] = None,
) -> EventSpan:
    return EventSpan(
        task_id=task_id,
        module=module,
        action_type=action_type,
        tool_name=tool_name,
        reason=reason,
        tool_arguments=tool_arguments,
    )


def start_event_span(
    *,
    task_id: Optional[str],
    module: str,
    action_type: str,
    tool_name: str = "",
    reason: str = "",
    tool_arguments: Optional[Dict[str, Any]] = None,
) -> EventSpan:
    """更简洁的函数式入口：创建后立即发送开始事件。"""
    return event_span(
        task_id=task_id,
        module=module,
        action_type=action_type,
        tool_name=tool_name,
        reason=reason,
        tool_arguments=tool_arguments,
    ).start()


# backward compatibility
LLMEventSpan = EventSpan
llm_event_span = event_span
start_llm_event_span = start_event_span
