"""事件总线：按类型订阅 + 发布

- 同步调用（publish 直接执行所有已注册 handler）
- 按事件 dataclass 的类型订阅；子类默认不继承，需显式订阅
- 发布时 handler 可通过 `event.set_result(value)` 写回结果，供调用方拿到（例如 start → event_id）
- 捕获 handler 异常，避免单个 handler 崩溃影响整条流水
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Type

from src.core.events import _EventBase

EventHandler = Callable[[Any], Any]
logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[Type, List[EventHandler]] = defaultdict(list)
        self._lock = threading.RLock()

    def subscribe(self, event_type: Type, handler: EventHandler) -> None:
        with self._lock:
            self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: Type, handler: EventHandler) -> None:
        with self._lock:
            lst = self._handlers.get(event_type)
            if lst and handler in lst:
                lst.remove(handler)

    def clear(self) -> None:
        with self._lock:
            self._handlers.clear()

    def publish(self, event: _EventBase) -> Any:
        """同步发布事件；若有多个 handler，它们依次执行，返回最后一个 `set_result` 的值。"""
        with self._lock:
            handlers = list(self._handlers.get(type(event), []))
        for h in handlers:
            try:
                h(event)
            except Exception as ex:
                # 不抛出 - 避免审计流水受 handler 失败影响
                logger.exception(
                    "[event_bus] handler 异常 %s / %s: %s",
                    type(event).__name__,
                    getattr(h, "__name__", repr(h)),
                    ex,
                )
        return event.result


# 全局单例
_default_bus: Optional[EventBus] = None
_default_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    global _default_bus
    if _default_bus is None:
        with _default_bus_lock:
            if _default_bus is None:
                _default_bus = EventBus()
    return _default_bus


def reset_event_bus() -> None:
    """测试用：重置全局总线"""
    global _default_bus
    with _default_bus_lock:
        _default_bus = EventBus()
