"""本地内存队列（线程安全，适合单机开发）"""
from __future__ import annotations

import queue
import threading
import uuid
from typing import Any, Callable, Optional, Tuple

from src.infrastructure.queue.base import QueueBackend


class LocalQueue(QueueBackend):
    def __init__(self) -> None:
        self._q: "queue.Queue[Tuple[str, Callable[..., Any], tuple, dict]]" = queue.Queue()
        self._lock = threading.Lock()

    def enqueue(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        job_id = uuid.uuid4().hex
        with self._lock:
            self._q.put((job_id, fn, args, kwargs))
        return job_id

    def dequeue(self, timeout: Optional[float] = None) -> Optional[tuple]:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None
