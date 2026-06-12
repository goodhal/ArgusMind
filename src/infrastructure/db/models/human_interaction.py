"""人工交互表"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.db.base import Base


class HumanInteraction(Base):
    __tablename__ = "human_interactions"

    interaction_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(
        PGUUID(as_uuid=False), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=True, index=True
    )
    message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    interaction_type: Mapped[str] = mapped_column(String(32), default="", nullable=False, index=True)
    is_confirmed: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    decided_by: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
