"""PostgreSQL 数据模型"""
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Enum as SQLEnum, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Task(Base):
    """任务模型"""
    __tablename__ = "tasks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id = Column(PGUUID(as_uuid=True), nullable=False, index=True)
    type = Column(String(100), nullable=False)
    status = Column(SQLEnum(TaskStatus), nullable=False, default=TaskStatus.PENDING, index=True)
    payload = Column(Text)  # JSON 字符串
    result = Column(Text)  # JSON 字符串
    error = Column(Text)
    worker_id = Column(String(100))
    lease_until = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

