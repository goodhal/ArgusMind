"""OpenCode 会话 abort 辅助（兼容不同 SDK 版本）。"""
from __future__ import annotations

import logging
from typing import Any

from openai._base_client import make_request_options
from opencode_ai import Omit

logger = logging.getLogger(__name__)


def abort_opencode_session(client: Any, session_id: str) -> None:
    """尽力中止进行中的 OpenCode session；失败不抛出。"""
    if not session_id or client is None:
        return

    session_api = getattr(client, "session", None)
    if session_api is not None:
        for method_name in ("abort", "cancel", "stop"):
            method = getattr(session_api, method_name, None)
            if not callable(method):
                continue
            for kwargs in (
                {"id": session_id},
                {"session_id": session_id},
                {"sessionID": session_id},
            ):
                try:
                    method(**kwargs)
                    return
                except TypeError:
                    continue
                except Exception as ex:
                    logger.debug("[opencode abort] session.%s failed: %s", method_name, ex)
            try:
                method(session_id)
                return
            except TypeError:
                pass
            except Exception as ex:
                logger.debug("[opencode abort] session.%s(positional) failed: %s", method_name, ex)

    post = getattr(client, "post", None)
    if callable(post):
        for path in (
            f"/session/{session_id}/abort",
            f"/sessions/{session_id}/abort",
        ):
            try:
                post(
                    path,
                    options=make_request_options(
                        timeout=None,
                        extra_headers={"Content-Type": Omit()},
                    ),
                )
                return
            except Exception as ex:
                logger.debug("[opencode abort] POST %s failed: %s", path, ex)
