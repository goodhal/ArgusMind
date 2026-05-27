"""进程内任务控制状态（暂停/恢复协作式中断）。

暂停标志保存在内存中，执行循环通过 ``is_paused`` O(1) 检查，避免每轮查库。
PostgreSQL ``tasks.status`` 为持久化来源；进程启动时由 ``reload_paused_from_db`` 回填内存。
"""
from __future__ import annotations

import logging
import threading
from typing import Set

logger = logging.getLogger(__name__)


class TaskPausedError(Exception):
    """任务已被暂停，执行循环应协作式退出。"""

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__(f"任务 {task_id} 已暂停")


class TaskControlRegistry:
    """线程安全的任务暂停/停止注册表（单进程）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._paused: Set[str] = set()
        self._stopped: Set[str] = set()

    def set_paused(self, task_id: str) -> None:
        with self._lock:
            self._paused.add(task_id)

    def clear_paused(self, task_id: str) -> None:
        with self._lock:
            self._paused.discard(task_id)

    def set_stopped(self, task_id: str) -> None:
        with self._lock:
            self._stopped.add(task_id)

    def clear_stopped(self, task_id: str) -> None:
        with self._lock:
            self._stopped.discard(task_id)

    def is_paused(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._paused

    def is_stopped(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._stopped

    def reload_paused(self, task_ids: Set[str]) -> None:
        with self._lock:
            self._paused = set(task_ids)
        if task_ids:
            logger.info("[task_control] 已从数据库恢复 %d 个暂停任务到内存", len(task_ids))


_registry: TaskControlRegistry | None = None


def get_task_control() -> TaskControlRegistry:
    global _registry
    if _registry is None:
        _registry = TaskControlRegistry()
    return _registry


def ensure_task_running(task_id: str) -> None:
    """若任务已暂停或已取消则抛出 ``TaskPausedError``。"""
    if not task_id:
        return
    ctrl = get_task_control()
    if ctrl.is_paused(task_id) or ctrl.is_stopped(task_id):
        raise TaskPausedError(task_id)


def reload_paused_from_db() -> None:
    """启动时从数据库加载 status=paused 的任务到内存。"""
    from src.infrastructure.db import session_scope
    from src.repositories.task_repository import TaskRepository

    with session_scope() as session:
        rows, _ = TaskRepository(session).list(status="paused", current=1, page_size=10000)
        task_ids = {r.id for r in rows}
    get_task_control().reload_paused(task_ids)
