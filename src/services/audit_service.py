"""审计编排总入口：API / Worker 通过此服务触发审计任务。

职责：
  1) 从 DB 加载 LLM / OpenCode 配置
  2) 构造 `ExecutionContext` 并调用 `Orchestrator.run(ctx)`
  3) 通过事件总线上报任务状态与日志；异常时兜底写入任务错误
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from src.core.enums import ActionType
from src.core.event_bus import get_event_bus
from src.core.events import EventStart, LogEvent, TaskStatusEvent
from src.core.context import ExecutionContext
from src.core.task_control import TaskPausedError, ensure_task_running
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import Project, Task
from src.services.config_service import get_llm_runtime_config, get_opencode_runtime_config


class AuditConfigMissing(Exception):
    pass


def run_task(task_id: str, project_id: Optional[str] = None) -> None:
    """同步执行一个审计任务。"""
    bus = get_event_bus()

    try:
        ensure_task_running(task_id)
    except TaskPausedError:
        bus.publish(LogEvent(level="INFO", module="audit", message=f"任务 {task_id} 处于暂停状态，跳过执行", task_id=task_id))
        return

    llm_cfg = get_llm_runtime_config()
    if llm_cfg is None:
        raise AuditConfigMissing("LLM_config 未配置（provider/key/model 必填）")
    opencode_cfg = get_opencode_runtime_config()

    # 快照项目与任务基础信息（短事务）
    project_name: str = ""
    project_path: str = ""
    resolved_project_id: str = ""
    with session_scope() as session:
        if project_id:
            project = session.get(Project, project_id)
            if project is not None:
                resolved_project_id = project.id
                project_name = project.name
                project_path = project.path
        else:
            task: Optional[Task] = session.get(Task, task_id)
            if task is None:
                raise ValueError(f"任务不存在: {task_id}")
            if task.project_id:
                project = session.get(Project, task.project_id)
                if project is not None:
                    resolved_project_id = project.id
                    project_name = project.name
                    project_path = project.path

    if not project_path:
        bus.publish(
            EventStart(
                task_id=task_id,
                module="audit",
                action_type=ActionType.INFORMATION,
                reason="关联项目缺失或 path 为空",
                status="failed",
            )
        )
        bus.publish(
            TaskStatusEvent(task_id=task_id, status="failed", message="关联项目缺失或 path 为空")
        )
        return

    bus.publish(LogEvent(level="INFO", module="audit", message=f"任务 {task_id} 开始执行", task_id=task_id))

    # 延迟导入，避免 API 冷启动就加载 agents 链路
    from src.core.orchestrator import Orchestrator

    ctx = ExecutionContext(
        task_id=task_id,
        project_id=resolved_project_id,
        project_name=project_name,
        project_path=Path(project_path),
        llm_config=llm_cfg,
        opencode_config=opencode_cfg,
    )

    try:
        Orchestrator().run(ctx)
    except TaskPausedError:
        bus.publish(LogEvent(level="INFO", module="audit", message=f"任务 {task_id} 已暂停", task_id=task_id))
        return
    except Exception as ex:  # pragma: no cover - 失败兜底
        bus.publish(
            EventStart(
                task_id=task_id,
                module="audit",
                action_type=ActionType.INFORMATION,
                reason=str(ex),
                status="failed",
            )
        )
        bus.publish(TaskStatusEvent(task_id=task_id, status="failed", message=str(ex)))
        bus.publish(LogEvent(level="ERROR", module="audit", message=f"任务执行失败: {ex}", task_id=task_id))
        raise
    else:
        bus.publish(LogEvent(level="INFO", module="audit", message="任务执行完成", task_id=task_id))
