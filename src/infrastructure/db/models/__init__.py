"""ORM 模型聚合：导入本文件即可完成所有模型的注册"""
from src.infrastructure.db.models.audit_log import LogEntry
from src.infrastructure.db.models.config import ConfigEntry
from src.infrastructure.db.models.vulnerability import Vulnerability, VulnerabilityDetail
from src.infrastructure.db.models.event import EventDetail, EventRecord
from src.infrastructure.db.models.human_interaction import HumanInteraction
from src.infrastructure.db.models.opencode_event import OpencodeEvent
from src.infrastructure.db.models.project import Project
from src.infrastructure.db.models.task import Task
from src.infrastructure.db.models.token_ledger import TokenLedger
from src.infrastructure.db.models.user import User

__all__ = [
    "User",
    "Project",
    "Task",
    "ConfigEntry",
    "EventRecord",
    "EventDetail",
    "HumanInteraction",
    "OpencodeEvent",
    "TokenLedger",
    "Vulnerability",
    "VulnerabilityDetail",
    "LogEntry",
    # backward compatibility
    "LLMEvent",
]

# backward compatibility
LLMEvent = EventRecord
