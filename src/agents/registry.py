"""Agent 注册表：统一管理具体 Agent 类型"""
from __future__ import annotations

from typing import Dict, Type

from src.agents.base import BaseAgent


class AgentRegistry:
    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseAgent]] = {}

    def register(self, name: str, cls: Type[BaseAgent]) -> None:
        self._registry[name] = cls

    def get(self, name: str) -> Type[BaseAgent] | None:
        return self._registry.get(name)

    def all(self) -> Dict[str, Type[BaseAgent]]:
        return dict(self._registry)


default_registry = AgentRegistry()


def register_default_agents() -> AgentRegistry:
    """尝试注册项目内置 Agent；失败则跳过，不抛错。"""
    try:
        from src.agents.chain_analyzer import ChainAnalyzer
        default_registry.register("chain_analyzer", ChainAnalyzer)
    except Exception:
        pass
    try:
        from src.agents.chain_confirmer import ChainConfirmer
        default_registry.register("chain_confirmer", ChainConfirmer)
    except Exception:
        pass
    try:
        from src.agents.plan import Plan
        default_registry.register("planner", Plan)
    except Exception:
        pass
    try:
        from src.agents.project_info import ProjectInfo
        default_registry.register("project_info", ProjectInfo)
    except Exception:
        pass
    try:
        from src.agents.sink_finder import SinkFinder
        default_registry.register("sink_finder", SinkFinder)
    except Exception:
        pass
    return default_registry
