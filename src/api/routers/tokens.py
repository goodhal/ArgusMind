"""Token 用量统计路由"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Query

from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse
from src.schemas.stats import DailyTokenStat, TokenStats
from src.services import stats_service

router = APIRouter(dependencies=[CurrentUserDep])


@router.get(
    "/stats",
    response_model=OkResponse[TokenStats],
    summary="Token 用量汇总",
    description="全平台 token_ledger 四列合计及总和。",
)
def token_stats() -> OkResponse[TokenStats]:
    return OkResponse[TokenStats](data=stats_service.get_token_stats())


@router.get(
    "/trend",
    response_model=OkResponse[List[DailyTokenStat]],
    summary="Token 按日趋势",
    description="按 UTC 日期聚合四列 token 用量；默认最近 30 天。",
)
def token_trend(
    days: int = Query(30, ge=1, le=365, description="统计最近 N 天（UTC）"),
) -> OkResponse[List[DailyTokenStat]]:
    return OkResponse[List[DailyTokenStat]](data=stats_service.list_token_daily_stats(days=days))
