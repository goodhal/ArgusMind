"""Token 账本表

设计：
- 有 ``source_event_id`` 时：与 ``events.id`` 绑定，**一行代表该 event 的用量总量快照**，再次上报覆盖四列。
- 无 ``source_event_id`` 时：每次插入新行；任务总用量仍由按 ``task_id`` 求和得到。
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.db.base import Base


class TokenLedger(Base):
    __tablename__ = "token_ledger"
    __table_args__ = (UniqueConstraint("source_event_id", name="uq_token_ledger_source_event_id"),)

    id: Mapped[str] = mapped_column(PGUUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    task_id: Mapped[str] = mapped_column(
        PGUUID(as_uuid=False), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_event_id: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        ForeignKey("events.id", ondelete="SET NULL"),
        nullable=True,
    )
    # 有 source_event_id 时为该 event 的用量总量快照；无键时每行一项独立片段，按 task 求和
    llm_input: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    llm_output: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    code_agent_input: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    code_agent_output: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    note: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
