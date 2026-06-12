"""内部事件类型定义

设计原则：
- 每种事件是一个独立的 dataclass，语义清晰
- 事件总线通过类型订阅（type-based subscription）
- 一些事件会返回值（如 EventStart 返回新建的 event_id），handler 里通过 `set_result()` 写回

事件总览：
  EventStart       LLM / 工具调用开始 → 创建 events 行，返回 event_id
  EventEnd         LLM / 工具调用结束 → 更新 events 行 + event_details
  TokenEvent       token 用量上报   → 写入 token_ledger（见 report_token_usage）；任务总量由查询时对 ledger 聚合
  LogEvent         持久化日志        → 写入 logs 表
  FindingEvent     发现/更新漏洞     → 写入 findings/finding_details 表
  TaskStatusEvent  任务状态流转      → 更新 tasks.status
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class _EventBase:
    """通用事件基类：提供 result 承载字段"""

    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _result: Any = None

    def set_result(self, value: Any) -> None:
        """handler 用来写回结果（如 EventStart → event_id）"""
        self._result = value

    @property
    def result(self) -> Any:
        return self._result


# ------------------- LLM / 工具调用事件 -------------------

@dataclass
class EventStart(_EventBase):
    """LLM 或工具调用开始。handler 创建 events 行并通过 set_result(event_id) 返回 ID。"""

    task_id: Optional[str] = None
    module: str = ""
    action_type: str = ""  # 如 llm_call / tool_call / code_agent / end 等
    tool_name: str = ""
    reason: str = ""
    status: str = ""
    result: str = ""
    tool_arguments: Optional[Dict[str, Any]] = None


@dataclass
class EventEnd(_EventBase):
    """LLM 或工具调用结束。"""

    event_id: int = 0
    status: str = "completed"  # completed / failed
    final_status: str = ""  # 业务维度的最终状态（例如 end 决策时的结果状态）
    tool_output: Optional[str] = None
    chain_of_thought: Optional[List[Dict[str, Any]]] = None
    # 可选：把 token 增量随 end 一起上报
    llm_input_delta: int = 0
    llm_output_delta: int = 0
    code_agent_input_delta: int = 0
    code_agent_output_delta: int = 0


# ------------------- Token 事件 -------------------

@dataclass
class TokenEvent(_EventBase):
    """token 用量上报 → `report_token_usage` 写入 `token_ledger`。

    四字段为**当前上报的用量总量**（由 span / 调用方在内存中累加后再发）；带 ``source_event_id`` 时对应账本行**覆盖更新**。
    `events` 行上的 token 列由 `finish_event` / OpenCode 等单独写入。
    """

    task_id: str = ""
    source_event_id: Optional[int] = None
    llm_input: int = 0
    llm_output: int = 0
    code_agent_input: int = 0
    code_agent_output: int = 0
    note: str = ""


# ------------------- 日志事件 -------------------

@dataclass
class LogEvent(_EventBase):
    level: str = "INFO"
    module: str = ""
    message: str = ""
    task_id: Optional[str] = None


# ------------------- 漏洞事件 -------------------

@dataclass
class FindingEvent(_EventBase):
    project_id: str = ""
    task_id: Optional[str] = None
    vul_name: str = ""
    verdict: str = ""
    confidence: str = "LOW"
    neo4j_element_id: str = ""
    detail: Optional[Dict[str, Any]] = None


# ------------------- 任务状态事件 -------------------

@dataclass
class TaskStatusEvent(_EventBase):
    task_id: str = ""
    status: str = ""  # pending / running / completed / failed / cancelled
    message: str = ""
    vuln_count: int = 0


# 向后兼容（旧代码里可能引用 InternalEvent 等名称）
InternalEvent = _EventBase

__all__ = [
    "EventStart",
    "EventEnd",
    "TokenEvent",
    "LogEvent",
    "FindingEvent",
    "TaskStatusEvent",
    "InternalEvent",
    # backward compatibility
    "LLMEventStart",
    "LLMEventEnd",
]

# backward compatibility
LLMEventStart = EventStart
LLMEventEnd = EventEnd
