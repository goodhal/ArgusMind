"""日志 schema"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class LogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    level: str
    module: str
    task_id: Optional[str] = None
    message: str


class LogFilter(BaseModel):
    level: Optional[str] = None
    task_id: Optional[str] = None
    keyword: Optional[str] = None
