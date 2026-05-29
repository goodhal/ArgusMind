"""事件仓储"""
from __future__ import annotations

from typing import List, Optional

from datetime import datetime

from sqlalchemy import exists, func, select, update
from sqlalchemy.orm import Session, selectinload

from src.core.enums import ActionType
from src.infrastructure.db.models import EventRecord


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, event_id: int) -> Optional[EventRecord]:
        stmt = select(EventRecord).options(selectinload(EventRecord.detail)).where(EventRecord.id == event_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def count_for_task(self, task_id: str) -> int:
        stmt = select(func.count()).select_from(EventRecord).where(EventRecord.task_id == task_id)
        return int(self.session.execute(stmt).scalar_one())

    def has_older_than(self, task_id: str, event_id: int) -> bool:
        stmt = select(
            exists().where(
                EventRecord.task_id == task_id,
                EventRecord.id < event_id,
            )
        )
        return bool(self.session.execute(stmt).scalar_one())

    def _base_stmt(self, task_id: str):
        return (
            select(EventRecord)
            .options(selectinload(EventRecord.detail))
            .where(EventRecord.task_id == task_id)
        )

    @staticmethod
    def _to_asc(rows: List[EventRecord]) -> List[EventRecord]:
        return list(reversed(rows))

    def list_latest(self, task_id: str, *, limit: int) -> List[EventRecord]:
        """该任务 id 最大的 limit 条，按 id 升序返回。"""
        stmt = self._base_stmt(task_id).order_by(EventRecord.id.desc()).limit(limit)
        rows = self.session.execute(stmt).scalars().all()
        return self._to_asc(list(rows))

    def list_before(self, task_id: str, *, before_id: int, limit: int) -> List[EventRecord]:
        """id < before_id 的更早 limit 条，按 id 升序返回。"""
        stmt = (
            self._base_stmt(task_id)
            .where(EventRecord.id < before_id)
            .order_by(EventRecord.id.desc())
            .limit(limit)
        )
        rows = self.session.execute(stmt).scalars().all()
        return self._to_asc(list(rows))

    def list_after(self, task_id: str, *, after_id: int) -> List[EventRecord]:
        """id > after_id 的新事件，按 id 升序返回（轮询）。"""
        stmt = (
            self._base_stmt(task_id)
            .where(EventRecord.id > after_id)
            .order_by(EventRecord.id.asc())
        )
        return list(self.session.execute(stmt).scalars().all())

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
