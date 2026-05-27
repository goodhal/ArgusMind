"""通用 schema：分页、结果封装"""
from __future__ import annotations

from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PageQuery(BaseModel):
    current: int = Field(1, ge=1, description="当前页码")
    pageSize: int = Field(20, ge=1, le=200, description="每页条数")


class PageResult(BaseModel, Generic[T]):
    data: List[T]
    total: int
    success: bool = True


class IdNameItem(BaseModel):
    id: str
    name: str


class OkResponse(BaseModel, Generic[T]):
    success: bool = True
    data: Optional[T] = None


class ErrorResponse(BaseModel):
    success: bool = False
    code: str = "internal_error"
    message: str = ""
