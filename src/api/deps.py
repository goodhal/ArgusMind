"""通用依赖：分页参数等"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Query


@dataclass
class Pagination:
    current: int
    page_size: int


def pagination(
    current: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=200),
) -> Pagination:
    return Pagination(current=current, page_size=pageSize)
