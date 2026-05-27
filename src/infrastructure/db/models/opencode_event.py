"""OpenCode SSE 事件表

设计要点：
- 每次 code_agent（OpenCodeTool）调用对应一条 events 行，event_id 即为该调用的 ID
- OpenCodeTool 在 SSE 流中会持续推送 message.part.updated / session.* / todo.* 等事件
- 每条与本次会话相关、且去重后唯一的 SSE 事件被持久化为一行 opencode_events
- 前端按 event_id 拉取后即可还原 OpenCode 的实时执行步骤

字段说明：
- payload：整条 OpenCode SSE 事件序列化为 JSONB（含 type、properties 及 SDK 顶层字段），
  与 event_type 等列并存，便于完整回放与后续解析
- token_input/token_output：仅 step-finish 事件填充，便于前端聚合
- 排序按 id 升序（自增 BIGINT，单 event_id 内单调递增）
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.db.base import Base


class OpencodeEvent(Base):
    """单条 OpenCode SSE 事件记录"""

    __tablename__ = "opencode_events"
    __table_args__ = (
        Index("idx_opencode_events_event_seq", "event_id", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    session_id: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)

    part_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    part_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    tool_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tool_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    token_input: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    token_output: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
