"""OpenCode SSE 事件仓储"""
from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.infrastructure.db.models import OpencodeEvent


class OpencodeEventRepository:
    def __init__(self, session: Session):
        self.session = session

    def add(self, row: OpencodeEvent) -> OpencodeEvent:
        self.session.add(row)
        self.session.flush()
        return row

    def list(
        self,
        *,
        event_id: int,
        after_id: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> Tuple[List[OpencodeEvent], int]:
        """按 event_id 加载 SSE 事件流。

        - after_id：滚动加载游标，返回 id > after_id 的事件
        - page_size：可选分页大小；为空时返回全部
        - 排序：按 id 升序（与产生顺序一致）
        """
        base = select(OpencodeEvent).where(OpencodeEvent.event_id == event_id)
        if after_id is not None:
            base = base.where(OpencodeEvent.id > after_id)

        total = self.session.execute(
            select(func.count()).select_from(base.subquery())
        ).scalar_one()

        stmt = base.order_by(OpencodeEvent.id.asc())
        if page_size is not None:
            stmt = stmt.limit(page_size)

        rows = self.session.execute(stmt).scalars().all()
        return list(rows), int(total)
