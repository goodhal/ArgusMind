"""任务仓储"""
from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.infrastructure.db.models import Task, TokenLedger, Vulnerability
from src.services.token_service import sum_task_tokens_map_from_ledger


class TaskIdNameRow(NamedTuple):
    id: str
    name: str


class TaskRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, task_id: str) -> Optional[Task]:
        return self.session.get(Task, task_id)

    def attach_token_aggregates(self, tasks: List[Task]) -> None:
        """从 token_ledger 聚合填充任务对象上的 token 字段（供 TaskRead 序列化，不写 tasks 表）。"""
        if not tasks:
            return
        totals = sum_task_tokens_map_from_ledger(self.session, [t.id for t in tasks])
        for task in tasks:
            a, b, c, d = totals.get(task.id, (0, 0, 0, 0))
            task.llm_input_token = a
            task.llm_output_token = b
            task.code_agent_input_token = c
            task.code_agent_output_token = d

    def list_id_names(self) -> List[TaskIdNameRow]:
        rows = self.session.execute(
            select(Task.id, Task.name).order_by(Task.created_at.desc())
        ).all()
        return [TaskIdNameRow(id=row[0], name=row[1]) for row in rows]

    def list(
        self,
        *,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        current: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[Task], int]:
        base = select(Task)
        if project_id:
            base = base.where(Task.project_id == project_id)
        if status:
            base = base.where(Task.status == status)
        total = self.session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        rows = (
            self.session.execute(
                base.order_by(Task.created_at.desc())
                .offset(max(0, (current - 1) * page_size))
                .limit(page_size)
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    def list_with_aggregates(
        self,
        *,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        current: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[Task], int]:
        """分页列表，单次查询附带漏洞数与 token 账本聚合（避免额外 round-trip）。"""
        filters = []
        if project_id:
            filters.append(Task.project_id == project_id)
        if status:
            filters.append(Task.status == status)

        count_stmt = select(func.count()).select_from(Task)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int(self.session.execute(count_stmt).scalar_one())

        vuln_agg = (
            select(
                Vulnerability.task_id.label("task_id"),
                func.count().label("vuln_count"),
            )
            .where(Vulnerability.task_id.isnot(None))
            .group_by(Vulnerability.task_id)
        ).subquery()

        token_agg = (
            select(
                TokenLedger.task_id.label("task_id"),
                func.coalesce(func.sum(TokenLedger.llm_input), 0).label("agg_llm_in"),
                func.coalesce(func.sum(TokenLedger.llm_output), 0).label("agg_llm_out"),
                func.coalesce(func.sum(TokenLedger.code_agent_input), 0).label("agg_ca_in"),
                func.coalesce(func.sum(TokenLedger.code_agent_output), 0).label("agg_ca_out"),
            )
            .group_by(TokenLedger.task_id)
        ).subquery()

        stmt = (
            select(
                Task,
                func.coalesce(vuln_agg.c.vuln_count, 0).label("vuln_count"),
                func.coalesce(token_agg.c.agg_llm_in, 0).label("llm_in"),
                func.coalesce(token_agg.c.agg_llm_out, 0).label("llm_out"),
                func.coalesce(token_agg.c.agg_ca_in, 0).label("ca_in"),
                func.coalesce(token_agg.c.agg_ca_out, 0).label("ca_out"),
            )
            .outerjoin(vuln_agg, Task.id == vuln_agg.c.task_id)
            .outerjoin(token_agg, Task.id == token_agg.c.task_id)
        )
        if filters:
            stmt = stmt.where(*filters)
        rows = self.session.execute(
            stmt.order_by(Task.created_at.desc())
            .offset(max(0, (current - 1) * page_size))
            .limit(page_size)
        ).all()

        tasks: List[Task] = []
        for row in rows:
            task = row[0]
            setattr(task, "vuln_count", int(row[1]))
            task.llm_input_token = int(row[2])
            task.llm_output_token = int(row[3])
            task.code_agent_input_token = int(row[4])
            task.code_agent_output_token = int(row[5])
            tasks.append(task)
        return tasks, total

    def add(self, task: Task) -> Task:
        self.session.add(task)
        self.session.flush()
        return task

    def update(self, _task: Task) -> Task:
        self.session.flush()
        return _task

    def delete(self, task: Task) -> None:
        self.session.delete(task)
        self.session.flush()
