"""事件服务：创建/更新事件 + 列表查询"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventDetail, EventRecord
from src.repositories.event_repository import EventRepository

STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

def create_event(
    *,
    task_id: Optional[str],
    module: str,
    action_type: str,
    tool_name: str = "",
    reason: str = "",
    tool_arguments: Optional[Dict[str, Any]] = None,
    status: str = ""
) -> EventRecord:
    """创建一条运行中的 event 行，返回其持久化后的快照（含 id）。"""
    if status == "":
        status = STATUS_RUNNING
    with session_scope() as session:
        event = EventRecord(
            task_id=task_id,
            module=module,
            action_type=action_type,
            tool_name=tool_name,
            status=status,
            reason=reason,
            started_at=datetime.utcnow(),
        )
        session.add(event)
        session.flush()
        detail = EventDetail(event_id=event.id, tool_arguments=tool_arguments)
        session.add(detail)
        session.flush()
        session.expunge(event)
        session.expunge(detail)
        return event


def _tool_output_for_text_column(value: Any) -> str:
    """event_details.tool_output 为 Text；非 str 时序列化为 JSON。"""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def finish_event(
    event_id: int,
    *,
    status: str = STATUS_COMPLETED,
    final_status: str = "",
    tool_output: Optional[Any] = None,
    chain_of_thought: Optional[List[Dict[str, Any]]] = None,
    llm_input_delta: int = 0,
    llm_output_delta: int = 0,
    code_agent_input_delta: int = 0,
    code_agent_output_delta: int = 0,
) -> Optional[EventRecord]:
    """更新事件的结束态；可选同步写入 token 增量字段到 events 行。"""
    with session_scope() as session:
        event = EventRepository(session).get(event_id)
        if event is None:
            return None
        event.status = status
        event.final_status = final_status or ""
        event.finished_at = datetime.utcnow()
        event.llm_input_delta = int(llm_input_delta or 0)
        event.llm_output_delta = int(llm_output_delta or 0)
        event.code_agent_input_delta = int(code_agent_input_delta or 0)
        event.code_agent_output_delta = int(code_agent_output_delta or 0)
        detail = event.detail
        if detail is None:
            detail = EventDetail(event_id=event.id)
            session.add(detail)
        if tool_output is not None:
            detail.tool_output = _tool_output_for_text_column(tool_output)
        if chain_of_thought is not None:
            detail.code_agent_chain_of_thought = chain_of_thought
        session.flush()
        session.expunge(event)
        return event


def list_events(
    *,
    task_id: Optional[str] = None,
    after_id: Optional[int] = None,
) -> Tuple[List[EventRecord], int]:
    with session_scope() as session:
        rows, total = EventRepository(session).list(
            task_id=task_id,
            after_id=after_id,
        )
        for r in rows:
            _ = r.detail
            session.expunge(r)
        return rows, total


def fail_running_non_information_events_for_task(task_id: str) -> int:
    """将任务下所有非 information 且仍为 running 的事件标为 failed（重跑前清理遗留）。"""
    with session_scope() as session:
        return EventRepository(session).fail_running_non_information_by_task(task_id)


def mark_event_completed(event_id: int) -> Optional[EventRecord]:
    """将 event 状态更新为 completed。"""
    with session_scope() as session:
        event = EventRepository(session).get(event_id)
        if event is None:
            return None
        event.status = STATUS_COMPLETED
        session.flush()
        session.expunge(event)
        return event
