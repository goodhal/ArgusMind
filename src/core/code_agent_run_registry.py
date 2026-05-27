"""进程内登记正在执行的 code_agent（OpenCode）调用，供暂停/取消时 abort 会话。"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class _ActiveCodeAgentRun:
    task_id: str
    session_id: str
    client: Any
    cancelled: threading.Event = field(default_factory=threading.Event)


class CodeAgentRunRegistry:
    """每个 task_id 至多登记一条进行中的 OpenCode chat。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._runs: Dict[str, _ActiveCodeAgentRun] = {}

    def register(self, task_id: str, session_id: str, client: Any) -> Optional[_ActiveCodeAgentRun]:
        if not (task_id and str(task_id).strip()):
            return None
        run = _ActiveCodeAgentRun(task_id=str(task_id), session_id=session_id, client=client)
        with self._lock:
            self._runs[str(task_id)] = run
        return run

    def unregister(self, task_id: str) -> None:
        if not task_id:
            return
        with self._lock:
            self._runs.pop(str(task_id), None)

    def get(self, task_id: str) -> Optional[_ActiveCodeAgentRun]:
        with self._lock:
            return self._runs.get(str(task_id))

    def is_cancelled(self, task_id: str) -> bool:
        run = self.get(task_id)
        return bool(run and run.cancelled.is_set())

    def abort(self, task_id: str, *, reason: str = "") -> bool:
        """请求中止该任务当前进行中的 OpenCode 会话。"""
        from src.tools.opencode_abort import abort_opencode_session

        with self._lock:
            run = self._runs.get(str(task_id))
        if run is None:
            return False
        run.cancelled.set()
        try:
            abort_opencode_session(run.client, run.session_id)
            logger.info(
                "[code_agent] 已请求 abort task_id=%s session_id=%s reason=%s",
                task_id,
                run.session_id,
                reason or "-",
            )
        except Exception as ex:
            logger.warning(
                "[code_agent] abort 失败 task_id=%s session_id=%s: %s",
                task_id,
                run.session_id,
                ex,
            )
        return True


_registry: CodeAgentRunRegistry | None = None


def get_code_agent_run_registry() -> CodeAgentRunRegistry:
    global _registry
    if _registry is None:
        _registry = CodeAgentRunRegistry()
    return _registry


def abort_code_agent_for_task(task_id: str, *, reason: str = "") -> bool:
    return get_code_agent_run_registry().abort(task_id, reason=reason)
