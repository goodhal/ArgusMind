"""日志表"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.db.base import Base


class LogEntry(Base):
    __tablename__ = "logs"

    id: Mapped[str] = mapped_column(PGUUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(16), default="INFO", nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    task_id: Mapped[Optional[str]] = mapped_column(String(64), default="", nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, default="", nullable=False)
