"""事件仓储"""
from __future__ import annotations

from typing import List, Optional, Tuple

from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from src.core.enums import ActionType
from src.infrastructure.db.models import EventRecord


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, event_id: int) -> Optional[EventRecord]:
        stmt = select(EventRecord).options(selectinload(EventRecord.detail)).where(EventRecord.id == event_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def list(
        self,
        *,
        task_id: Optional[str] = None,
        after_id: Optional[int] = None,
    ) -> Tuple[List[EventRecord], int]:
        base = select(EventRecord).options(selectinload(EventRecord.detail))
        if task_id:
            base = base.where(EventRecord.task_id == task_id)
        if after_id is not None:
            # 滚动加载：继续拉取比当前游标更早的记录（按倒序列表）
            base = base.where(EventRecord.id > after_id)
        total = self.session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        rows = (
            self.session.execute(
                base.order_by(EventRecord.id.desc())
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    def add(self, event: EventRecord) -> EventRecord:
        self.session.add(event)
        self.session.flush()
        return event

    def update(self, event: EventRecord) -> EventRecord:
        self.session.flush()
        return event

    def fail_running_non_information_by_task(self, task_id: str) -> int:
        """将 task 下 action_type≠information 且 status=running 的事件标为 failed。"""
        stmt = (
            update(EventRecord)
            .where(
                EventRecord.task_id == task_id,
                EventRecord.status == "running",
                EventRecord.action_type != ActionType.INFORMATION.value,
            )
            .values(status="failed", finished_at=datetime.utcnow())
        )
        result = self.session.execute(stmt)
        return int(result.rowcount or 0)
