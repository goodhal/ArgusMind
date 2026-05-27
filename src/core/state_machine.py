"""任务状态机"""
from __future__ import annotations

from typing import Dict, Set

from src.core.enums import TaskStatus

_ALLOWED: Dict[TaskStatus, Set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.RUNNING, TaskStatus.CANCELLED, TaskStatus.FAILED},
    TaskStatus.RUNNING: {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.PAUSED,
    },
    TaskStatus.PAUSED: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: {TaskStatus.PENDING},  # 允许重试
    TaskStatus.CANCELLED: {TaskStatus.PENDING},
}


class InvalidTransition(Exception):
    pass


def can_transition(src: TaskStatus, dst: TaskStatus) -> bool:
    return dst in _ALLOWED.get(src, set())


def ensure_transition(src: TaskStatus, dst: TaskStatus) -> None:
    if not can_transition(src, dst):
        raise InvalidTransition(f"任务状态非法转换：{src} -> {dst}")
