"""事件路由"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from src.api.exceptions import BadRequestError, NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse, PageResult
from src.schemas.event import (
    EventPageResult,
    EventRead,
    HumanApprovalRead,
    HumanApprovalDecisionRead,
    HumanApprovalDecisionRequest,
    OpencodeEventRead,
)
from src.services import event_service, opencode_event_service
from src.services.human_interaction_service import get_approval, resolve_approval

router = APIRouter(dependencies=[CurrentUserDep])


@router.get("", response_model=EventPageResult)
def list_events(
    task_id: str = Query(..., description="任务 ID（必填）"),
    limit: int = Query(200, ge=1, le=500, description="首次加载或向上翻页时每页条数"),
    before_id: Optional[int] = Query(None, ge=1, description="向上加载更早事件：返回 id < before_id"),
    after_id: Optional[int] = Query(None, ge=1, description="轮询新事件：返回 id > after_id"),
) -> EventPageResult:
    if before_id is not None and after_id is not None:
        raise BadRequestError("before_id 与 after_id 不能同时使用")

    result = event_service.list_events(
        task_id=task_id,
        limit=limit,
        before_id=before_id,
        after_id=after_id,
    )
    return EventPageResult(
        data=[EventRead.model_validate(r) for r in result.rows],
        total=result.total,
        has_more_older=result.has_more_older,
        page_oldest_id=result.page_oldest_id,
        page_newest_id=result.page_newest_id,
    )


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
