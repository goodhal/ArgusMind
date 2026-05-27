"""日志服务：落库 + 查询"""
from __future__ import annotations

from typing import List, Optional, Tuple

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import LogEntry
from src.repositories.log_repository import LogRepository


def write_log(
    *, level: str, module: str, message: str, task_id: Optional[str] = None
) -> LogEntry:
    with session_scope() as session:
        entry = LogEntry(level=level.upper(), module=module, message=message, task_id=task_id)
        LogRepository(session).add(entry)
        session.expunge(entry)
        return entry


def list_logs(
    *,
    level: Optional[str] = None,
    task_id: Optional[str] = None,
    keyword: Optional[str] = None,
    current: int = 1,
    page_size: int = 50,
) -> Tuple[List[LogEntry], int]:
    with session_scope() as session:
        rows, total = LogRepository(session).list(
            level=level,
            task_id=task_id,
            keyword=keyword,
            current=current,
            page_size=page_size,
        )
        for r in rows:
            session.expunge(r)
        return rows, total
