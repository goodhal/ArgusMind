"""任务队列抽象"""
from src.infrastructure.queue.base import QueueBackend
from src.infrastructure.queue.local_queue import LocalQueue

__all__ = ["QueueBackend", "LocalQueue"]
