"""日志路由"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from src.api.deps import Pagination, pagination
from src.api.security import CurrentUserDep
from src.schemas.common import PageResult
from src.schemas.log import LogRead
from src.services import log_service

router = APIRouter(dependencies=[CurrentUserDep])


@router.get("", response_model=PageResult[LogRead])
def list_logs(
    level: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    page: Pagination = Depends(pagination),
) -> PageResult[LogRead]:
    rows, total = log_service.list_logs(
        level=level,
        task_id=task_id,
        keyword=keyword,
        current=page.current,
        page_size=page.page_size,
    )
    return PageResult[LogRead](data=[LogRead.model_validate(r) for r in rows], total=total)
