"""任务应用服务"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import Task
from src.repositories.project_repository import ProjectRepository
from src.repositories.task_repository import TaskRepository
from src.core.enums import TaskStatus
from src.core.state_machine import InvalidTransition, ensure_transition
from src.core.code_agent_run_registry import abort_code_agent_for_task
from src.core.task_control import get_task_control
from src.schemas.common import IdNameItem
from src.schemas.task import AuditTaskCreate, TaskUpdate, TokenUsagePatch
from src.services.graph_service import delete_task_neo4j_data
from src.services.token_service import report_token_usage


class TaskNotFound(Exception):
    pass


class ProjectNotFound(Exception):
    pass


class InvalidTaskState(Exception):
    """任务当前状态不允许该操作。"""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def create_task(data: AuditTaskCreate) -> Task:
    with session_scope() as session:
        project = ProjectRepository(session).get(data.project_id)
        if project is None:
            raise ProjectNotFound(data.project_id)
        task = Task(
            project_id=data.project_id,
            name=data.name,
            status="pending",
        )
        TaskRepository(session).add(task)
        session.expunge(task)
        return task


def get_task(task_id: str) -> Optional[Task]:
    with session_scope() as session:
        repo = TaskRepository(session)
        task = repo.get(task_id)
        if task:
            repo.attach_token_aggregates([task])
            session.expunge(task)
        return task


def list_task_id_names() -> List[IdNameItem]:
    with session_scope() as session:
        rows = TaskRepository(session).list_id_names()
        return [IdNameItem(id=row.id, name=row.name) for row in rows]


def list_tasks(
    *,
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    current: int = 1,
    page_size: int = 20,
) -> Tuple[List[Task], int]:
    with session_scope() as session:
        rows, total = TaskRepository(session).list_with_aggregates(
            project_id=project_id, status=status, current=current, page_size=page_size
        )
        for r in rows:
            session.expunge(r)
        return rows, total


def update_task(task_id: str, data: TaskUpdate) -> Optional[Task]:
    with session_scope() as session:
        repo = TaskRepository(session)
        task = repo.get(task_id)
        if task is None:
            return None
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(task, field, value)
        if data.status in {"completed", "failed", "cancelled"} and task.finished_at is None:
            task.finished_at = datetime.utcnow()
        if data.status in {"cancelled", "completed", "failed", "running"}:
            ctrl = get_task_control()
            ctrl.clear_paused(task_id)
            if data.status == "running":
                ctrl.clear_stopped(task_id)
            if data.status == "cancelled":
                ctrl.set_stopped(task_id)
        repo.update(task)
        session.expunge(task)
        return task


def delete_task(task_id: str) -> bool:
    """删除 PostgreSQL 任务记录、Neo4j 子图，并清理任务控制标志。"""
    get_task_control().clear_paused(task_id)
    get_task_control().set_stopped(task_id)
    abort_code_agent_for_task(task_id, reason="delete")
    with session_scope() as session:
        if TaskRepository(session).get(task_id) is None:
            return False
    delete_task_neo4j_data(task_id)
    with session_scope() as session:
        repo = TaskRepository(session)
        task = repo.get(task_id)
        if task is None:
            return False
        repo.delete(task)
        return True


def batch_delete_tasks(task_ids: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """先 batch_pause_tasks，再逐条删除；返回 (已删除 task_id 列表, [(task_id, 错误信息), ...])。"""
    ids: List[str] = []
    seen: set[str] = set()
    for task_id in task_ids:
        if task_id in seen:
            continue
        seen.add(task_id)
        ids.append(task_id)

    batch_pause_tasks(ids)

    deleted: List[str] = []
    errors: List[Tuple[str, str]] = []
    for task_id in ids:
        if delete_task(task_id):
            deleted.append(task_id)
        else:
            errors.append((task_id, "任务不存在"))
    return deleted, errors


def cancel_task(task_id: str) -> Optional[Task]:
    get_task_control().set_stopped(task_id)
    abort_code_agent_for_task(task_id, reason="cancelled")
    get_task_control().clear_paused(task_id)
    return update_task(task_id, TaskUpdate(status="cancelled"))


def pause_task(task_id: str) -> Task:
    """将运行中的任务标记为暂停（内存 + 数据库）。"""
    with session_scope() as session:
        repo = TaskRepository(session)
        task = repo.get(task_id)
        if task is None:
            raise TaskNotFound(task_id)
        current = TaskStatus(task.status)
        ensure_transition(current, TaskStatus.PAUSED)
        get_task_control().set_paused(task_id)
        abort_code_agent_for_task(task_id, reason="paused")
        task.status = TaskStatus.PAUSED.value
        repo.update(task)
        session.expunge(task)
        return task


def batch_pause_tasks(task_ids: List[str]) -> Tuple[List[Task], List[Tuple[str, str]]]:
    """批量暂停；返回 (成功任务, [(task_id, 错误信息), ...])。"""
    succeeded: List[Task] = []
    errors: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for task_id in task_ids:
        if task_id in seen:
            continue
        seen.add(task_id)
        try:
            succeeded.append(pause_task(task_id))
        except TaskNotFound:
            errors.append((task_id, "任务不存在"))
        except InvalidTaskState as ex:
            errors.append((task_id, ex.message))
        except InvalidTransition as ex:
            errors.append((task_id, f"当前状态不允许暂停: {ex}"))
    return succeeded, errors


def batch_resume_tasks(task_ids: List[str]) -> Tuple[List[Task], List[Tuple[str, str]]]:
    """批量恢复；返回 (成功任务, [(task_id, 错误信息), ...])。"""
    succeeded: List[Task] = []
    errors: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for task_id in task_ids:
        if task_id in seen:
            continue
        seen.add(task_id)
        try:
            succeeded.append(resume_task(task_id))
        except TaskNotFound:
            errors.append((task_id, "任务不存在"))
        except InvalidTaskState as ex:
            errors.append((task_id, ex.message))
    return succeeded, errors


def resume_task(task_id: str) -> Task:
    """恢复暂停的任务（清除内存标志，数据库置为 running）。"""
    with session_scope() as session:
        repo = TaskRepository(session)
        task = repo.get(task_id)
        if task is None:
            raise TaskNotFound(task_id)
        current = TaskStatus(task.status)
        if current != TaskStatus.PAUSED:
            raise InvalidTaskState(f"仅 paused 状态可恢复，当前为 {task.status}")
        ctrl = get_task_control()
        ctrl.clear_paused(task_id)
        ctrl.clear_stopped(task_id)
        task.status = TaskStatus.RUNNING.value
        if task.finished_at is not None:
            task.finished_at = None
        repo.update(task)
        session.expunge(task)
        return task


def add_token_usage(task_id: str, delta: TokenUsagePatch) -> Optional[Task]:
    """经 ``report_token_usage`` 写入账本（无 ``source_event_id`` 时每次插入新行）。

    ``TokenUsagePatch`` 四字段语义由调用方约定；若多次上报「任务级累计总量」且无 event 绑定，求和会重复，应改为带 event 的覆盖上报或只报片段行。
    """
    with session_scope() as session:
        if TaskRepository(session).get(task_id) is None:
            return None
    report_token_usage(
        task_id=task_id,
        llm_input=delta.llm_input,
        llm_output=delta.llm_output,
        code_agent_input=delta.code_agent_input,
        code_agent_output=delta.code_agent_output,
        source_event_id=None,
        note="task_service.add_token_usage",
    )
    return get_task(task_id)
