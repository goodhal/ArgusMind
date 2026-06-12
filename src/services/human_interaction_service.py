"""人工交互服务：发起确认、等待用户操作、超时自动决策。"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import HumanInteraction

DEFAULT_TIMEOUT_SECONDS = 60
POLL_INTERVAL_SECONDS = 2


def _normalize_timeout(timeout_seconds: Optional[int]) -> int:
    if timeout_seconds is None:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    return max(1, timeout)


def request_approval(
    *,
    task_id: Optional[str],
    message: str,
    timeout_seconds: Optional[int] = None,
    auto_approve_on_timeout: bool = True,
    interaction_id: str = None,
    interaction_type: str = None,
) -> Dict[str, object]:
    """发起一次人工确认并阻塞等待结果（或超时自动决策）。"""
    timeout = _normalize_timeout(timeout_seconds)
    with session_scope() as session:
        session.add(
            HumanInteraction(
                interaction_id=interaction_id,
                event_id=None,
                task_id=task_id,
                message=message,
                is_confirmed=None,
                timeout_seconds=timeout,
                decided_by="",
                interaction_type=interaction_type,
            )
        )

    started = time.monotonic()
    timed_out = False
    approved = bool(auto_approve_on_timeout)
    decided_by = "timeout"
    while True:
        with session_scope() as session:
            row = session.get(HumanInteraction, interaction_id)
            if row is not None and row.is_confirmed is not None:
                approved = bool(row.is_confirmed)
                decided_by = row.decided_by or "user"
                message = row.message
                break

        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            timed_out = True
            with session_scope() as session:
                row = session.get(HumanInteraction, interaction_id)
                if row is not None:
                    if row.is_confirmed is None:
                        row.is_confirmed = bool(auto_approve_on_timeout)
                        row.decided_by = "timeout"
                        row.confirmed_at = datetime.now(timezone.utc)
                        row.updated_at = datetime.now(timezone.utc)
                        approved = bool(auto_approve_on_timeout)
                        decided_by = "timeout"
                    else:
                        approved = bool(row.is_confirmed)
                        decided_by = row.decided_by or "user"
                        timed_out = decided_by == "timeout"
            break

        remaining = timeout - elapsed
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0.1, remaining)))

    elapsed_ms = int((time.monotonic() - started) * 1000)

    result = {
        "interaction_id": interaction_id,
        "approved": approved,
        "timed_out": timed_out,
        "decided_by": decided_by,
        "message": message,
        "timeout_seconds": timeout,
        "elapsed_ms": elapsed_ms,
    }
    return result


def resolve_approval(
    *,
    interaction_id: str,
    approved: bool = True,
    operator: str = "user",
    message: Optional[str] = None,
) -> Optional[Dict[str, object]]:
    """由前端回调确认结果。返回 None 表示交互不存在或已结束。"""
    with session_scope() as session:
        row = session.get(HumanInteraction, interaction_id)
        if row is None:
            return None
        # if row.is_confirmed is not None:
        #     return None
        row.message = message
        row.is_confirmed = bool(approved)
        row.decided_by = operator or "user"
        row.confirmed_at = datetime.now(timezone.utc)
        row.updated_at = datetime.now(timezone.utc)
        return {
            "interaction_id": interaction_id,
            "approved": bool(row.is_confirmed),
            "timed_out": False,
            "decided_by": row.decided_by,
            "message": row.message,
            "timeout_seconds": row.timeout_seconds,
        }


def get_approval(*, interaction_id: str) -> Optional[Dict[str, object]]:
    """按 interaction_id 查询人工确认数据。"""
    with session_scope() as session:
        row = session.get(HumanInteraction, interaction_id)
        if row is None:
            return None
        return {
            "interaction_id": row.interaction_id,
            "approved": row.is_confirmed,
            "decided_by": row.decided_by or "",
            "message": row.message or "",
            "timeout_seconds": row.timeout_seconds,
            "interaction_type": row.interaction_type or "",
        }
