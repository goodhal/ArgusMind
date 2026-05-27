"""事件路由"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from src.api.exceptions import NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse, PageResult
from src.schemas.event import (
    EventRead,
    HumanApprovalRead,
    HumanApprovalDecisionRead,
    HumanApprovalDecisionRequest,
    OpencodeEventRead,
)
from src.services import event_service, opencode_event_service
from src.services.human_interaction_service import get_approval, resolve_approval

router = APIRouter(dependencies=[CurrentUserDep])


@router.get("", response_model=PageResult[EventRead])
def list_events(
    task_id: Optional[str] = Query(None),
    after_id: Optional[int] = Query(None, ge=1),
) -> PageResult[EventRead]:
    rows, total = event_service.list_events(
        task_id=task_id,
        after_id=after_id,
    )
    return PageResult[EventRead](data=[EventRead.model_validate(r) for r in rows], total=total)


@router.get("/{event_id}", response_model=OkResponse[EventRead])
def get_event(event_id: int) -> OkResponse[EventRead]:
    from src.infrastructure.db import session_scope
    from src.repositories.event_repository import EventRepository

    with session_scope() as session:
        event = EventRepository(session).get(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
        _ = event.detail
        session.expunge(event)
    return OkResponse[EventRead](data=EventRead.model_validate(event))


@router.get("/{event_id}/opencode", response_model=PageResult[OpencodeEventRead])
def list_event_opencode_events(
    event_id: int,
    after_id: Optional[int] = Query(None, ge=0, description="滚动加载游标，仅返回 id 大于此值的事件"),
    page_size: Optional[int] = Query(None, ge=1, le=2000, description="可选分页大小，留空返回全部"),
) -> PageResult[OpencodeEventRead]:
    """按 event_id 加载 OpenCode SSE 事件（前端 code_agent 详情页用）。

    返回顺序按事件产生顺序升序，便于前端追加渲染。
    """
    rows, total = opencode_event_service.list_opencode_events(
        event_id=event_id,
        after_id=after_id,
        page_size=page_size,
    )
    return PageResult[OpencodeEventRead](
        data=[OpencodeEventRead.model_validate(r) for r in rows],
        total=total,
    )


@router.post("/human-approvals/{interaction_id}", response_model=OkResponse[HumanApprovalDecisionRead])
def resolve_human_approval(
    interaction_id: str,
    body: HumanApprovalDecisionRequest,
    event_id: Optional[int] = Query(None, ge=1),
) -> OkResponse[HumanApprovalDecisionRead]:
    result = resolve_approval(
        interaction_id=interaction_id,
        approved=body.approved,
        operator=body.operator,
        message=body.message,
    )
    if result is None:
        raise NotFoundError("交互不存在或已结束")
    if event_id is not None:
        event = event_service.mark_event_completed(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
    return OkResponse[HumanApprovalDecisionRead](data=HumanApprovalDecisionRead.model_validate(result))


@router.get("/human-approvals/{interaction_id}", response_model=OkResponse[HumanApprovalRead])
def get_human_approval(interaction_id: str) -> OkResponse[HumanApprovalRead]:
    result = get_approval(interaction_id=interaction_id)
    if result is None:
        raise NotFoundError("交互不存在")
    return OkResponse[HumanApprovalRead](data=HumanApprovalRead.model_validate(result))
