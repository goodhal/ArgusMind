"""仪表盘统计服务"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from src.infrastructure.db import session_scope
from src.repositories.stats_repository import SEVERITY_KEYS, StatsRepository
from src.schemas.stats import (
    DailySeverityStat,
    DailyTokenStat,
    FindingStats,
    FindingTypeStat,
    LanguageStatItem,
    ProjectOverviewStats,
    ProjectTopByVuln,
    TaskStats,
    TokenStats,
)


# 简单 TTL 缓存（仪表盘数据秒级不敏感）
_cache: dict = {"ts": 0.0, "data": {}}
_CACHE_TTL = 30  # 秒


def _cached(key: str, ttl: int = _CACHE_TTL) -> Optional[object]:
    """获取缓存值，过期返回 None。"""
    now = time.monotonic()
    if now - _cache["ts"] < ttl:
        return _cache["data"].get(key)
    return None


def _set_cache(key: str, value: object) -> None:
    """设置缓存值。"""
    now = time.monotonic()
    if now - _cache["ts"] >= _CACHE_TTL:
        _cache["data"].clear()
        _cache["ts"] = now
    _cache["data"][key] = value


def _since_from_days(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=max(1, days))


def _empty_severity_row(date: str) -> DailySeverityStat:
    return DailySeverityStat(date=date)


def _pivot_daily_severity(
    rows: List[tuple],
) -> List[DailySeverityStat]:
    by_date: Dict[str, DailySeverityStat] = {}
    for day, level, cnt in rows:
        if day not in by_date:
            by_date[day] = _empty_severity_row(day)
        item = by_date[day]
        key = level if level in SEVERITY_KEYS else "unknown"
        setattr(item, key, getattr(item, key) + cnt)
    return [by_date[k] for k in sorted(by_date.keys())]


def get_task_stats() -> TaskStats:
    cached = _cached("get_task_stats")
    if cached:
        return cached  # type: ignore[return-value]
    with session_scope() as session:
        total, by_status = StatsRepository(session).task_counts_by_status()
        result = TaskStats(total=total, by_status=by_status)
        _set_cache("get_task_stats", result)
        return result


def get_project_overview() -> ProjectOverviewStats:
    cached = _cached("get_project_overview")
    if cached:
        return cached  # type: ignore[return-value]
    with session_scope() as session:
        repo = StatsRepository(session)
        overview = repo.project_overview_scalars()
        top = repo.top_projects_by_vulnerabilities(limit=5)
        merged = repo.aggregate_language_stats_python()
        languages = [
            LanguageStatItem(
                language=lang,
                code=v["code"],
                files=v["files"],
                lines=v["lines"],
            )
            for lang, v in sorted(merged.items(), key=lambda x: (-x[1]["code"], x[0]))
        ]
        result = ProjectOverviewStats(
            total_projects=overview.total_projects,
            total_files=overview.total_files,
            total_lines=overview.total_lines,
            languages=languages,
            top_by_vulnerabilities=[
                ProjectTopByVuln(
                    project_id=r.project_id,
                    project_name=r.project_name,
                    vulnerability_count=r.vulnerability_count,
                )
                for r in top
            ],
        )
        _set_cache("get_project_overview", result)
        return result


def get_finding_stats() -> FindingStats:
    cached = _cached("get_finding_stats")
    if cached:
        return cached  # type: ignore[return-value]
    with session_scope() as session:
        total, by_severity = StatsRepository(session).finding_counts_by_severity()
        result = FindingStats(total=total, by_severity=by_severity)
        _set_cache("get_finding_stats", result)
        return result


def list_finding_type_stats(*, limit: int = 50) -> List[FindingTypeStat]:
    with session_scope() as session:
        rows = StatsRepository(session).finding_counts_by_category(limit=limit)
        return [FindingTypeStat(category_name=name, count=cnt) for name, cnt in rows]


def list_finding_daily_stats(*, days: int = 30) -> List[DailySeverityStat]:
    since = _since_from_days(days)
    with session_scope() as session:
        rows = StatsRepository(session).finding_daily_by_severity(since=since)
        return _pivot_daily_severity(rows)


def get_token_stats() -> TokenStats:
    cached = _cached("get_token_stats")
    if cached:
        return cached  # type: ignore[return-value]
    with session_scope() as session:
        li, lo, ci, co = StatsRepository(session).token_totals()
        result = TokenStats(
            llm_input=li,
            llm_output=lo,
            code_agent_input=ci,
            code_agent_output=co,
            total=li + lo + ci + co,
        )
        _set_cache("get_token_stats", result)
        return result


def list_token_daily_stats(*, days: int = 30) -> List[DailyTokenStat]:
    since = _since_from_days(days)
    with session_scope() as session:
        rows = StatsRepository(session).token_daily(since=since)
        return [
            DailyTokenStat(
                date=day,
                llm_input=li,
                llm_output=lo,
                code_agent_input=ci,
                code_agent_output=co,
                total=li + lo + ci + co,
            )
            for day, li, lo, ci, co in rows
        ]
