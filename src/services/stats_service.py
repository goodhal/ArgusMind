"""仪表盘统计服务"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List

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


def _since_from_days(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=max(1, days))


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
    with session_scope() as session:
        total, by_status = StatsRepository(session).task_counts_by_status()
        return TaskStats(total=total, by_status=by_status)


def get_project_overview() -> ProjectOverviewStats:
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
        return ProjectOverviewStats(
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


def get_finding_stats() -> FindingStats:
    with session_scope() as session:
        total, by_severity = StatsRepository(session).finding_counts_by_severity()
        return FindingStats(total=total, by_severity=by_severity)


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
    with session_scope() as session:
        li, lo, ci, co = StatsRepository(session).token_totals()
        return TokenStats(
            llm_input=li,
            llm_output=lo,
            code_agent_input=ci,
            code_agent_output=co,
            total=li + lo + ci + co,
        )


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
