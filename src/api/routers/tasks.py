"""任务路由"""
from __future__ import annotations

import logging
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query

import src.storage.manager as db_manager
from src.api.deps import Pagination, pagination
from src.api.exceptions import AppException, BadRequestError, NotFoundError
from src.api.security import CurrentUserDep
from typing import List

from src.schemas.common import IdNameItem, OkResponse, PageResult
from src.schemas.stats import TaskStats
from src.schemas.task import (
    AuditTaskCreate,
    TaskAuditCompletionStatus,
    TaskBatchDeleteResult,
    TaskBatchIds,
    TaskBatchItemError,
    TaskBatchResult,
    TaskRead,
    TaskUpdate,
)
from src.services import stats_service, task_service
from src.services.plan_service import fetch_task_language_risk_status
from src.services.audit_service import AuditConfigMissing, run_task

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[CurrentUserDep])


@router.get(
    "/options",
    response_model=OkResponse[List[IdNameItem]],
    summary="全部任务 id 与名称",
    description="返回所有任务的 id、name 列表，用于下拉选择等场景。",
)
def list_task_options() -> OkResponse[List[IdNameItem]]:
    return OkResponse[List[IdNameItem]](data=task_service.list_task_id_names())


@router.get(
    "/stats",
    response_model=OkResponse[TaskStats],
    summary="任务数量统计",
    description="返回任务总数及各 status 数量。",
)
def task_stats() -> OkResponse[TaskStats]:
    return OkResponse[TaskStats](data=stats_service.get_task_stats())


@router.get("", response_model=PageResult[TaskRead])
def list_tasks(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: Pagination = Depends(pagination),
) -> PageResult[TaskRead]:
    rows, total = task_service.list_tasks(
        project_id=project_id, status=status, current=page.current, page_size=page.page_size
    )
    return PageResult[TaskRead](data=[TaskRead.model_validate(r) for r in rows], total=total)


@router.get("/detail", response_model=OkResponse[TaskRead])
def get_task_detail(id: UUID = Query(..., alias="id")) -> OkResponse[TaskRead]:
    task = task_service.get_task(str(id))
    if task is None:
        raise NotFoundError("任务不存在")
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.post("/batch/pause", response_model=OkResponse[TaskBatchResult])
def pause_tasks_batch(body: TaskBatchIds) -> OkResponse[TaskBatchResult]:
    """批量暂停运行中的任务。"""
    tasks, errs = task_service.batch_pause_tasks(body.task_ids)
    return OkResponse[TaskBatchResult](
        data=TaskBatchResult(
            tasks=[TaskRead.model_validate(t) for t in tasks],
            errors=[TaskBatchItemError(task_id=tid, message=msg) for tid, msg in errs],
        )
    )


@router.post(
    "/batch/delete",
    response_model=OkResponse[TaskBatchDeleteResult],
    summary="删除任务（支持单个或多个）",
    description="taskIds 传 1 个即为单条删除。先 batch_pause_tasks，再删 PostgreSQL 与 Neo4j 子图；返回 deletedIds 与 errors。",
)
def delete_tasks_batch(body: TaskBatchIds) -> OkResponse[TaskBatchDeleteResult]:
    deleted_ids, errs = task_service.batch_delete_tasks(body.task_ids)
    return OkResponse[TaskBatchDeleteResult](
        data=TaskBatchDeleteResult(
            deleted_ids=deleted_ids,
            errors=[TaskBatchItemError(task_id=tid, message=msg) for tid, msg in errs],
        )
    )


@router.post("/batch/resume", response_model=OkResponse[TaskBatchResult])
def resume_tasks_batch(body: TaskBatchIds, background: BackgroundTasks) -> OkResponse[TaskBatchResult]:
    """批量恢复已暂停的任务并重新加入后台执行队列。"""
    tasks, errs = task_service.batch_resume_tasks(body.task_ids)

    for task in tasks:
        task_id_str = task.id
        project_id = task.project_id

        def _runner(tid: str = task_id_str, pid: str = project_id) -> None:
            try:
                run_task(tid, project_id=pid)
            except AuditConfigMissing as ex:
                logger.warning("[run_task] 配置缺失: %s", ex)
            except Exception as ex:  # pragma: no cover
                logger.exception("[run_task] 执行异常: %s", ex)

        background.add_task(_runner)

    return OkResponse[TaskBatchResult](
        data=TaskBatchResult(
            tasks=[TaskRead.model_validate(t) for t in tasks],
            errors=[TaskBatchItemError(task_id=tid, message=msg) for tid, msg in errs],
        )
    )


@router.get(
    "/{task_id}/completion-status",
    response_model=OkResponse[TaskAuditCompletionStatus],
    summary="任务审计计划完成进度",
    description="从 Neo4j 读取该任务下 Language、RiskCategory 的 status，用于统计任务完成状态。",
)
def get_task_completion_status(task_id: UUID) -> OkResponse[TaskAuditCompletionStatus]:
    task_id_str = str(task_id)
    if task_service.get_task(task_id_str) is None:
        raise NotFoundError("任务不存在")
    try:
        db_manager.neo4j_repository
    except Exception as ex:
        raise AppException(message=f"Neo4j 未初始化: {ex}", code="NEO4J_UNAVAILABLE", status_code=503)
    try:
        raw = fetch_task_language_risk_status(task_id_str)
    except Exception as ex:
        logger.exception("[tasks/completion-status] task_id=%s", task_id_str)
        raise AppException(message=f"Neo4j 查询失败: {ex}", code="NEO4J_QUERY_FAILED", status_code=500)

    return OkResponse[TaskAuditCompletionStatus](
        data=TaskAuditCompletionStatus.model_validate(raw)
    )


@router.get("/{task_id}", response_model=OkResponse[TaskRead])
def get_task(task_id: UUID) -> OkResponse[TaskRead]:
    task = task_service.get_task(str(task_id))
    if task is None:
        raise NotFoundError("任务不存在")
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.post("", response_model=OkResponse[TaskRead])
def create_task(body: AuditTaskCreate, background: BackgroundTasks) -> OkResponse[TaskRead]:
    try:
        task = task_service.create_task(body)
    except task_service.ProjectNotFound:
        raise NotFoundError("关联项目不存在")

    def _runner():
        try:
            run_task(task.id, project_id=body.project_id)
        except AuditConfigMissing as ex:
            logger.warning("[run_task] 配置缺失: %s", ex)
        except Exception as ex:  # pragma: no cover
            logger.exception("[run_task] 执行异常: %s", ex)

    background.add_task(_runner)
    # 任务成功加入后台执行队列后，立即置为 running。
    task = task_service.update_task(task.id, TaskUpdate(status="running")) or task
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.put("/{task_id}", response_model=OkResponse[TaskRead])
def update_task(task_id: UUID, body: TaskUpdate) -> OkResponse[TaskRead]:
    task = task_service.update_task(str(task_id), body)
    if task is None:
        raise NotFoundError("任务不存在")
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.post("/{task_id}/cancel", response_model=OkResponse[TaskRead])
def cancel_task(task_id: UUID) -> OkResponse[TaskRead]:
    task = task_service.cancel_task(str(task_id))
    if task is None:
        raise NotFoundError("任务不存在")
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.get("/{task_id}/pause", response_model=OkResponse[TaskRead])
def pause_task(task_id: UUID) -> OkResponse[TaskRead]:
    """暂停运行中的任务；执行线程在下一轮 Agent 边界协作式退出。"""
    try:
        task = task_service.pause_task(str(task_id))
    except task_service.TaskNotFound:
        raise NotFoundError("任务不存在")
    except task_service.InvalidTaskState as ex:
        raise BadRequestError(str(ex))
    except Exception as ex:
        from src.core.state_machine import InvalidTransition

        if isinstance(ex, InvalidTransition):
            raise BadRequestError(f"当前状态不允许暂停: {ex}")
        raise
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.get("/{task_id}/resume", response_model=OkResponse[TaskRead])
def resume_task(task_id: UUID, background: BackgroundTasks) -> OkResponse[TaskRead]:
    """恢复已暂停的任务并重新加入后台执行队列。"""
    task_id_str = str(task_id)
    try:
        task = task_service.resume_task(task_id_str)
    except task_service.TaskNotFound:
        raise NotFoundError("任务不存在")
    except task_service.InvalidTaskState as ex:
        raise BadRequestError(str(ex))

    def _runner():
        try:
            run_task(task_id_str, project_id=task.project_id)
        except AuditConfigMissing as ex:
            logger.warning("[run_task] 配置缺失: %s", ex)
        except Exception as ex:  # pragma: no cover
            logger.exception("[run_task] 执行异常: %s", ex)

    background.add_task(_runner)
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))


@router.get("/{task_id}/run", response_model=OkResponse[TaskRead])
def run_task_endpoint(task_id: UUID, background: BackgroundTasks) -> OkResponse[TaskRead]:
    task_id_str = str(task_id)
    task = task_service.get_task(task_id_str)
    if task is None:
        raise NotFoundError("任务不存在")

    def _runner():
        try:
            run_task(task_id_str)
        except AuditConfigMissing as ex:
            logger.warning("[run_task] 配置缺失: %s", ex)
        except Exception as ex:  # pragma: no cover
            logger.exception("[run_task] 执行异常: %s", ex)

    background.add_task(_runner)
    return OkResponse[TaskRead](data=TaskRead.model_validate(task))
