"""队列后端抽象"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional


class QueueBackend(ABC):
    @abstractmethod
    def enqueue(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        ...

    @abstractmethod
    def dequeue(self, timeout: Optional[float] = None) -> Optional[tuple]:
        ...
