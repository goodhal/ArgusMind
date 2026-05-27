"""编排策略与规则（占位）"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OrchestratorPolicy:
    max_concurrent_agents: int = 1
    chain_analysis_timeout_sec: int = 3600
    reuse_plan_when_exists: bool = True
    reuse_project_node_when_exists: bool = True
