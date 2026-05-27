"""任务 schema"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AuditTaskCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    project_id: str = Field(..., alias="projectId")
    name: str = Field(..., max_length=255)


class TaskUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None


class TaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    project_id: str
    name: str
    status: str
    todo: Optional[List[Dict[str, Any]]] = None
    llm_input_token: int = 0
    llm_output_token: int = 0
    code_agent_input_token: int = 0
    code_agent_output_token: int = 0
    error: str = ""
    created_at: datetime
    finished_at: Optional[datetime] = None
    updated_at: datetime
    vuln_count: int = Field(0, serialization_alias="vulnCount")


class TaskBatchIds(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    task_ids: List[str] = Field(..., alias="taskIds", min_length=1, max_length=100)


class TaskBatchItemError(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    task_id: str = Field(..., alias="taskId")
    message: str


class TaskBatchResult(BaseModel):
    tasks: List[TaskRead]
    errors: List[TaskBatchItemError]


class TaskBatchDeleteResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    deleted_ids: List[str] = Field(default_factory=list, alias="deletedIds")
    errors: List[TaskBatchItemError] = Field(default_factory=list)


class TaskRiskCategoryStatus(BaseModel):
    node_id: str
    category_name: str
    status: str
    level: int = 100
    sink_finder_completed: bool = False


class TaskLanguageStatus(BaseModel):
    node_id: str
    language: str
    status: str
    level: int = 100
    risk_categories: List[TaskRiskCategoryStatus] = Field(default_factory=list)


class TaskAuditCompletionStatus(BaseModel):
    """任务在 Neo4j 审计计划中的语言 / 风险类别执行进度。"""

    task_id: str
    languages: List[TaskLanguageStatus] = Field(default_factory=list)


class TokenUsagePatch(BaseModel):
    """经 task_service 写入 token_ledger（无 event 键时为插入行，数值语义由调用方约定）。"""

    llm_input: int = 0
    llm_output: int = 0
    code_agent_input: int = 0
    code_agent_output: int = 0
