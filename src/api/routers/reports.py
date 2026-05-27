"""任务审计报告：聚合 findings + token + LLM event 数量形成概览。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sqlalchemy import func, select

from src.api.security import CurrentUserDep
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventRecord, LogEntry, Task, Vulnerability
from src.schemas.common import OkResponse
from src.services.token_service import sum_task_tokens_from_ledger

router = APIRouter(dependencies=[CurrentUserDep])


@router.get("/{task_id}", response_model=OkResponse[dict])
def get_report(task_id: str) -> OkResponse[dict]:
    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        findings_rows = (
            session.execute(
                select(Vulnerability).where(Vulnerability.task_id == task_id).order_by(Vulnerability.created_at.desc())
            )
            .scalars()
            .all()
        )

        # 结论聚合
        verdict_counts = dict(
            session.execute(
                select(Vulnerability.verdict, func.count())
                .where(Vulnerability.task_id == task_id)
                .group_by(Vulnerability.verdict)
            ).all()
        )

        # LLM 事件数量
        action_counts = dict(
            session.execute(
                select(EventRecord.action_type, func.count())
                .where(EventRecord.task_id == task_id)
                .group_by(EventRecord.action_type)
            ).all()
        )

        # 日志 ERROR/WARNING 数量
        log_counts = dict(
            session.execute(
                select(LogEntry.level, func.count())
                .where(LogEntry.task_id == task_id)
                .group_by(LogEntry.level)
            ).all()
        )

        findings_payload = [
            {
                "id": f.id,
                "vul_name": f.vul_name,
                "verdict": f.verdict,
                "confidence": f.confidence or "LOW",
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "neo4j_element_id": f.neo4j_element_id,
            }
            for f in findings_rows
        ]

        li, lo, ci, co = sum_task_tokens_from_ledger(session, task_id)
        report = {
            "task": {
                "id": task.id,
                "project_id": task.project_id,
                "status": task.status,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "error": task.error or "",
            },
            "tokens": {
                "llm_input": li,
                "llm_output": lo,
                "code_agent_input": ci,
                "code_agent_output": co,
            },
            "summary": {
                "total_findings": len(findings_payload),
                "verdict": verdict_counts,
                "events_by_action": action_counts,
                "log_levels": log_counts,
            },
            "findings": findings_payload,
        }
        return OkResponse[dict](data=report)
