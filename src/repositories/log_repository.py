"""日志仓储"""
from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.infrastructure.db.models import LogEntry


class LogRepository:
    def __init__(self, session: Session):
        self.session = session

    def list(
        self,
        *,
        level: Optional[str] = None,
        task_id: Optional[str] = None,
        keyword: Optional[str] = None,
        current: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[LogEntry], int]:
        base = select(LogEntry)
        if level:
            base = base.where(LogEntry.level == level)
        if task_id:
            base = base.where(LogEntry.task_id == task_id)
        if keyword:
            base = base.where(LogEntry.message.ilike(f"%{keyword}%"))
        total = self.session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        rows = (
            self.session.execute(
                base.order_by(LogEntry.created_at.desc())
                .offset(max(0, (current - 1) * page_size))
                .limit(page_size)
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    def add(self, log: LogEntry) -> LogEntry:
        self.session.add(log)
        self.session.flush()
        return log
