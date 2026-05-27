"""默认事件处理器：把事件持久化到 PostgreSQL 的对应表"""
from __future__ import annotations

from datetime import datetime

from src.core.event_bus import get_event_bus
from src.core.events import (
    EventEnd,
    EventStart,
    FindingEvent,
    LogEvent,
    TaskStatusEvent,
    TokenEvent,
)


# ---------------- LLM 事件 ----------------

def handle_event_start(ev: EventStart) -> None:
    from src.services import event_service

    event = event_service.create_event(
        task_id=ev.task_id,
        module=ev.module,
        action_type=ev.action_type,
        tool_name=ev.tool_name,

        reason=ev.reason,
        tool_arguments=ev.tool_arguments,
        status=ev.status,
    )
    ev.set_result(event.id)


def handle_event_end(ev: EventEnd) -> None:
    from src.services import event_service

    if not ev.event_id:
        return
    event_service.finish_event(
        ev.event_id,
        status=ev.status,
        final_status=ev.final_status,
        tool_output=ev.tool_output,
        chain_of_thought=ev.chain_of_thought,
        llm_input_delta=ev.llm_input_delta,
        llm_output_delta=ev.llm_output_delta,
        code_agent_input_delta=ev.code_agent_input_delta,
        code_agent_output_delta=ev.code_agent_output_delta,
    )


# ---------------- Token 事件 ----------------

def handle_token_event(ev: TokenEvent) -> None:
    from src.services.token_service import report_token_usage

    ok = report_token_usage(
        task_id=ev.task_id,
        llm_input=ev.llm_input,
        llm_output=ev.llm_output,
        code_agent_input=ev.code_agent_input,
        code_agent_output=ev.code_agent_output,
        source_event_id=ev.source_event_id,
        note=ev.note,
    )
    ev.set_result(ok)


# ---------------- 日志 ----------------

def handle_log_event(ev: LogEvent) -> None:
    from src.services.log_service import write_log

    entry = write_log(level=ev.level, module=ev.module, message=ev.message, task_id=ev.task_id)
    ev.set_result(entry.id)




# ---------------- 任务状态 ----------------

def handle_task_status_event(ev: TaskStatusEvent) -> None:
    from src.infrastructure.db import session_scope
    from src.infrastructure.db.models import Task

    if not ev.task_id or not ev.status:
        return
    with session_scope() as session:
        task = session.get(Task, ev.task_id)
        if task is None:
            return
        task.status = ev.status
        if ev.message:
            task.error = ev.message if ev.status == "failed" else task.error
        if ev.status in {"completed", "failed", "cancelled"} and task.finished_at is None:
            task.finished_at = datetime.utcnow()
        if ev.status == "paused" and task.finished_at is not None:
            task.finished_at = None


# ---------------- 注册入口 ----------------

_registered = False


def register_default_handlers() -> None:
    """幂等地把默认处理器注册到全局事件总线"""
    global _registered
    if _registered:
        return
    bus = get_event_bus()
    bus.subscribe(EventStart, handle_event_start)
    bus.subscribe(EventEnd, handle_event_end)
    bus.subscribe(TokenEvent, handle_token_event)
    bus.subscribe(LogEvent, handle_log_event)
    bus.subscribe(TaskStatusEvent, handle_task_status_event)
    _registered = True
