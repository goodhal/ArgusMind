"""项目仓储"""
from __future__ import annotations

from datetime import datetime
from typing import List, NamedTuple, Optional, Tuple

from sqlalchemy import case, func, literal, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from src.infrastructure.db.models import Project, Task, Vulnerability

HIGH_RISK_LEVELS = ("critical", "high")
VULNERABILITY_RISK_THRESHOLD = 1


class ProjectListRow(NamedTuple):
    project: Project
    vulnerability_count: int
    high_risk_count: int
    last_scanned_at: Optional[datetime]
    health_status: str


class ProjectStatsRow(NamedTuple):
    total: int
    normal: int
    risk: int
    pending_scan: int


class ProjectIdNameRow(NamedTuple):
    id: str
    name: str


class ProjectRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, project_id: str) -> Optional[Project]:
        return self.session.get(Project, project_id)

    def get_by_name(self, name: str) -> Optional[Project]:
        stmt = select(Project).where(Project.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def _build_list_select(
        self,
        *,
        keyword: Optional[str] = None,
        source_type: Optional[str] = None,
        health_status: Optional[str] = None,
    ) -> Tuple[Select, object]:
        vuln_subq = (
            select(
                Vulnerability.project_id.label("project_id"),
                func.count(Vulnerability.id).label("vulnerability_count"),
            )
            .group_by(Vulnerability.project_id)
            .subquery()
        )
        high_risk_subq = (
            select(
                Vulnerability.project_id.label("project_id"),
                func.count(Vulnerability.id).label("high_risk_count"),
            )
            .where(func.lower(Vulnerability.level).in_(HIGH_RISK_LEVELS))
            .group_by(Vulnerability.project_id)
            .subquery()
        )
        last_scan_subq = (
            select(
                Task.project_id.label("project_id"),
                func.max(Task.finished_at).label("last_scanned_at"),
            )
            .where(Task.status == "completed")
            .group_by(Task.project_id)
            .subquery()
        )

        vulnerability_count = func.coalesce(vuln_subq.c.vulnerability_count, 0)
        high_risk_count = func.coalesce(high_risk_subq.c.high_risk_count, 0)
        last_scanned_at = last_scan_subq.c.last_scanned_at

        health_status_expr = case(
            (last_scanned_at.is_(None), literal("pending_scan")),
            (
                or_(
                    high_risk_count > 0,
                    vulnerability_count >= VULNERABILITY_RISK_THRESHOLD,
                ),
                literal("risk"),
            ),
            else_=literal("normal"),
        ).label("health_status")

        stmt = (
            select(
                Project,
                vulnerability_count.label("vulnerability_count"),
                high_risk_count.label("high_risk_count"),
                last_scanned_at.label("last_scanned_at"),
                health_status_expr,
            )
            .outerjoin(vuln_subq, Project.id == vuln_subq.c.project_id)
            .outerjoin(high_risk_subq, Project.id == high_risk_subq.c.project_id)
            .outerjoin(last_scan_subq, Project.id == last_scan_subq.c.project_id)
        )

        if keyword:
            pattern = f"%{keyword}%"
            stmt = stmt.where(Project.name.ilike(pattern))
        if source_type:
            if source_type == "upload":
                stmt = stmt.where(Project.source_type.in_(["upload", "archive"]))
            else:
                stmt = stmt.where(Project.source_type == source_type)
        if health_status:
            stmt = stmt.where(health_status_expr == health_status)

        return stmt, health_status_expr

    def list(
        self,
        *,
        keyword: Optional[str] = None,
        source_type: Optional[str] = None,
        health_status: Optional[str] = None,
        current: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[ProjectListRow], int]:
        base, _ = self._build_list_select(
            keyword=keyword, source_type=source_type, health_status=health_status
        )
        total = self.session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        rows = self.session.execute(
            base.order_by(Project.updated_at.desc())
            .offset(max(0, (current - 1) * page_size))
            .limit(page_size)
        ).all()
        return [
            ProjectListRow(
                project=row[0],
                vulnerability_count=int(row[1]),
                high_risk_count=int(row[2]),
                last_scanned_at=row[3],
                health_status=str(row[4]),
            )
            for row in rows
        ], int(total)

    def list_id_names(self) -> List[ProjectIdNameRow]:
        rows = self.session.execute(
            select(Project.id, Project.name).order_by(Project.created_at.desc())
        ).all()
        return [ProjectIdNameRow(id=row[0], name=row[1]) for row in rows]

    def stats(
        self,
        *,
        keyword: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> ProjectStatsRow:
        base, _ = self._build_list_select(keyword=keyword, source_type=source_type, health_status=None)
        inner = base.subquery()
        row = self.session.execute(
            select(
                func.count().label("total"),
                func.coalesce(
                    func.sum(case((inner.c.health_status == literal("normal"), 1), else_=0)), 0
                ).label("normal"),
                func.coalesce(
                    func.sum(case((inner.c.health_status == literal("risk"), 1), else_=0)), 0
                ).label("risk"),
                func.coalesce(
                    func.sum(case((inner.c.health_status == literal("pending_scan"), 1), else_=0)), 0
                ).label("pending_scan"),
            ).select_from(inner)
        ).one()
        return ProjectStatsRow(
            total=int(row.total),
            normal=int(row.normal),
            risk=int(row.risk),
            pending_scan=int(row.pending_scan),
        )

    def add(self, project: Project) -> Project:
        self.session.add(project)
        self.session.flush()
        return project

    def update(self, project: Project) -> Project:
        self.session.flush()
        return project

    def delete(self, project: Project) -> None:
        self.session.delete(project)
        self.session.flush()
