"""任务 / 阶段枚举"""
from __future__ import annotations

from enum import Enum


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditStage(str, Enum):
    INFORMATION_COLLECTION = "information_collection"
    PLANNING = "planning"
    SINK_DISCOVERY = "sink_discovery"
    CHAIN_ANALYSIS = "chain_analysis"
    REVIEW = "review"
    REPORT = "report"


class ActionType(str, Enum):
    INFORMATION = "information"
    PLANNING = "planning"
    SINK_DISCOVERY = "sink_discovery"
    SINK_REFINE = "sink_refine"
    CHAIN_ANALYSIS = "chain_analysis"
    HUMAN_APPROVAL = "human_approval"
    VULNERABILITY = "vulnerability"
    TOOL_CALL = "tool_call"
    THINKING = "thinking"
    FINAL = "final"
    REVIEW = "review"
    REPORT = "report"

class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    IGNORED = "ignored"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
