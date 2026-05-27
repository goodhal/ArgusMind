"""事件表 + 事件详情表

设计要点：
- events 记录一次 LLM / 工具调用的"摘要信息"
  - 发起时（start）：创建行，`status='running'`，写 started_at、module、action_type、tool_name、reason
  - 结束时（end）：更新同一行，写 finished_at、最终状态，以及本次调用的 token 增量
- event_details 记录 1:1 的可扩展详情（工具参数、工具输出、code_agent 思维链）
- token 增量同时冗余到 `events` 行上，供前端直接展示；去重由 `token_ledger` 表保证
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.infrastructure.db.base import Base


class EventRecord(Base):
    """记录每次 LLM/工具 action 的摘要"""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_id: Mapped[Optional[str]] = mapped_column(
        PGUUID(as_uuid=False), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=True, index=True
    )
    module: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="running", nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    final_status: Mapped[str] = mapped_column(Text, default="", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # 本次调用对应的 token 增量（冗余字段，便于前端直接展示）
    llm_input_delta: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    llm_output_delta: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    code_agent_input_delta: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    code_agent_output_delta: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    detail: Mapped[Optional["EventDetail"]] = relationship(
        "EventDetail", back_populates="event", uselist=False, cascade="all, delete-orphan"
    )


class EventDetail(Base):
    """事件的可扩展详情"""

    __tablename__ = "event_details"

    event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )
    tool_arguments: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    tool_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    code_agent_chain_of_thought: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONB, nullable=True)

    event: Mapped[EventRecord] = relationship("EventRecord", back_populates="detail")


# backward compatibility
LLMEvent = EventRecord
