"""OpenCode SSE 事件服务

职责：
- 把 OpenCode SSE 推送的事件实时落库到 opencode_events（payload 存整条事件的完整 JSON）
- 把每次 step-finish 累积出来的 code_agent token 实时回写到对应 events 行的
  code_agent_input_delta / code_agent_output_delta，便于前端实时查看进度

注意事项：
- 这里仅"覆盖写"events.code_agent_*_delta 为当前累计总额；
  EventSpan.finish() 在结束时仍会再写一次（最终值与累计值一致），不会重复累加 task 总量
- task 维度的 token 由 `token_ledger` 汇总；EventSpan 经 TokenEvent 调用 ``report_token_usage`` 入账本，
  本服务不参与 ledger 写入，避免双重计费
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.event_bus import get_event_bus
from src.core.events import TokenEvent
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventRecord, OpencodeEvent
from src.repositories.opencode_event_repository import OpencodeEventRepository

logger = logging.getLogger(__name__)


def record_opencode_event(
    *,
    event_id: int,
    session_id: str,
    event_type: str,
    part_type: Optional[str] = None,
    part_id: Optional[str] = None,
    message_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_status: Optional[str] = None,
    title: Optional[str] = None,
    content: Optional[str] = None,
    token_input: Optional[int] = None,
    token_output: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Optional[int]:
    """把一条 SSE 事件持久化到 opencode_events，返回新行 id。"""
    if not event_id:
        return None
    try:
        with session_scope() as session:
            row = OpencodeEvent(
                event_id=event_id,
                session_id=session_id or "",
                event_type=event_type or "",
                part_type=part_type,
                part_id=part_id,
                message_id=message_id,
                tool_name=tool_name,
                tool_status=tool_status,
                title=title,
                content=content,
                token_input=token_input,
                token_output=token_output,
                payload=payload,
            )
            session.add(row)
            session.flush()
            return int(row.id)
    except Exception as ex:  # 持久化失败不应阻断 SSE 主流程
        logger.warning("[opencode_event_service] 写入 SSE 事件失败: %s", ex)
        return None


def update_event_code_agent_tokens(
    *,
    event_id: int,
    task_id: str,
    total_input: int,
    total_output: int,
) -> bool:
    """实时把累计 token 写到 events.code_agent_*_delta（覆盖写当前总额）。"""
    if not event_id:
        return False
    try:
        bus = get_event_bus()
        bus.publish(
            TokenEvent(
                task_id=task_id,
                source_event_id=event_id,
                llm_input=0,
                llm_output=0,
                code_agent_input=total_input,
                code_agent_output=total_output,
            )
        )
        with session_scope() as session:
            event = session.get(EventRecord, event_id)
            if event is None:
                return False
            event.code_agent_input_delta = int(total_input or 0)
            event.code_agent_output_delta = int(total_output or 0)
            return True
    except Exception as ex:
        logger.warning("[opencode_event_service] 实时回写 code_agent token 失败: %s", ex)
        return False


def list_opencode_events(
    *,
    event_id: int,
    after_id: Optional[int] = None,
    page_size: Optional[int] = None,
) -> Tuple[List[OpencodeEvent], int]:
    """按 event_id 拉取 SSE 事件，供前端展示。"""
    with session_scope() as session:
        rows, total = OpencodeEventRepository(session).list(
            event_id=event_id,
            after_id=after_id,
            page_size=page_size,
        )
        for r in rows:
            session.expunge(r)
        return rows, total
