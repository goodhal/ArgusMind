"""事件 schema"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class EventDetailRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tool_arguments: Optional[Dict[str, Any]] = None
    tool_output: Optional[str] = None
    code_agent_chain_of_thought: Optional[List[Dict[str, Any]]] = None


class OpencodeEventRead(BaseModel):
    """OpenCode SSE 单条事件，供前端按 event_id 渲染 code_agent 实时执行步骤。

    payload 为整条 SSE 事件的完整 JSON（含 type、properties 及 SDK 其它顶层字段）。
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int
    session_id: str = ""
    event_type: str = ""
    part_type: Optional[str] = None
    part_id: Optional[str] = None
    message_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_status: Optional[str] = None
    title: Optional[str] = None
    content: Optional[str] = None
    token_input: Optional[int] = None
    token_output: Optional[int] = None
    payload: Optional[Dict[str, Any]] = None
    created_at: datetime


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: Optional[str] = None
    module: str
    action_type: str
    tool_name: str
    status: str
    reason: str
    final_status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    llm_input_delta: int = 0
    llm_output_delta: int = 0
    code_agent_input_delta: int = 0
    code_agent_output_delta: int = 0
    detail: Optional[EventDetailRead] = None


class EventPageResult(BaseModel):
    """任务事件列表（游标分页 + 元数据）。"""

    success: bool = True
    data: List[EventRead]
    total: int
    has_more_older: bool = False
    page_oldest_id: Optional[int] = None
    page_newest_id: Optional[int] = None


class HumanApprovalDecisionRequest(BaseModel):
    approved: bool = True
    operator: str = Field(default="user", max_length=64)
    message: Optional[str] = Field(default=None, max_length=10000)


class HumanApprovalDecisionRead(BaseModel):
    interaction_id: str
    approved: bool
    timed_out: bool = False
    decided_by: str = ""
    message: str = ""
    timeout_seconds: int = 0


class HumanApprovalRead(BaseModel):
    interaction_id: str
    approved: Optional[bool] = None
    decided_by: str = ""
    message: str = ""
    timeout_seconds: int = 0
    interaction_type: str = ""


# backward compatibility
LLMEventDetailSchema = EventDetailRead
LLMEventRead = EventRead
