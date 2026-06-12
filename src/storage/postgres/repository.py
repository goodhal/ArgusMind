"""PostgreSQL 数据仓库（兼容层）。

实际 Repository 实现已迁移至 ``src.repositories`` 包，
此处仅保留兼容导入以避免 storage.manager 等旧引用报错。
"""
from typing import Any, List, Optional
from uuid import UUID

from src.storage.postgres.client import PostgresClient


class TaskRepository:
    """任务仓库（兼容旧 storage.manager 引用）"""

    def __init__(self, client: PostgresClient):
        self.client = client

    def create_task(self, task: Any) -> UUID:
        from src.repositories.task_repository import TaskRepository as RealRepo
        from src.infrastructure.db import session_scope
        with session_scope() as session:
            repo = RealRepo(session)
            repo.add(task)
            return task.id

    def get_task(self, task_id: UUID) -> Optional[Any]:
        from src.repositories.task_repository import TaskRepository as RealRepo
        from src.infrastructure.db import session_scope
        with session_scope() as session:
            return RealRepo(session).get(str(task_id))

    def claim_task(self, worker_id: str) -> Optional[Any]:
        # TODO: 实现任务领取逻辑（使用 lease）
        return None

    def update_task_status(self, task_id: UUID, status):
        from src.repositories.task_repository import TaskRepository as RealRepo
        from src.infrastructure.db import session_scope
        with session_scope() as session:
            repo = RealRepo(session)
            task = repo.get(str(task_id))
            if task:
                task.status = status.value if hasattr(status, "value") else str(status)
                repo.update(task)

    def list_tasks(
        self,
        project_id: Optional[UUID] = None,
        status=None,
        limit: int = 100,
    ) -> List[Any]:
        from src.repositories.task_repository import TaskRepository as RealRepo
        from src.infrastructure.db import session_scope
        with session_scope() as session:
            repo = RealRepo(session)
            status_str = status.value if hasattr(status, "value") else status
            rows, _ = repo.list(
                project_id=str(project_id) if project_id else None,
                status=status_str,
                current=1,
                page_size=limit,
            )
            for r in rows:
                session.expunge(r)
            return rows
