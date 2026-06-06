"""风险评分模块

整合自 code-review-graph 项目的风险评分算法
用于评估代码变更的风险级别
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import RISK_WEIGHTS, SECURITY_KEYWORDS, SEVERITY_LEVELS


@dataclass
class CodeNode:
    """代码节点（函数/类等）的简化表示"""
    name: str
    qualified_name: str
    kind: str = "Function"  # Function, Class, Test
    file_path: str = ""
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    is_test: bool = False
    caller_count: int = 0
    test_coverage: int = 0  # 测试覆盖数量
    flow_participation: List[float] = field(default_factory=list)  # 每个流的关键度
    community_id: Optional[str] = None
    cross_community_callers: int = 0


@dataclass
class RiskScoreResult:
    """风险评分结果"""
    overall_score: float
    severity: str
    risk_factors: Dict[str, float]
    details: Dict[str, Any]


class RiskScorer:
    """风险评分器"""

    def __init__(self) -> None:
        self._security_keywords_lower = {
            kw.lower() for kw in SECURITY_KEYWORDS
        }

    def compute_risk_score(
        self,
        node: CodeNode,
    ) -> RiskScoreResult:
        """
        为单个代码节点计算风险评分（0.0 - 1.0）

        评分因素:
          - 流参与度: 关键度总和，最大权重 RISK_WEIGHTS["flow_participation"]
          - 社区交叉: 跨社区调用者数量 * 0.05，最大权重 RISK_WEIGHTS["cross_community"]
          - 测试覆盖率: 基准权重减去已覆盖的权重
          - 安全敏感度: 如果名称匹配安全关键词，加 RISK_WEIGHTS["security_sensitive"]
          - 调用者数量: 调用者数 / 20，最大权重 RISK_WEIGHTS["caller_count"]
        """
        score = 0.0
        risk_factors: Dict[str, float] = {}

        # 1. 流参与度（关键度加权）
        flow_score = 0.0
        if node.flow_participation:
            flow_score = min(sum(node.flow_participation), RISK_WEIGHTS["flow_participation"])
        else:
            # 备选：如果没有流数据，使用固定权重
            flow_count = len(node.flow_participation)
            flow_score = min(flow_count * 0.05, RISK_WEIGHTS["flow_participation"])
        score += flow_score
        risk_factors["flow_participation"] = flow_score

        # 2. 社区交叉
        cross_score = min(
            node.cross_community_callers * 0.05,
            RISK_WEIGHTS["cross_community"]
        )
        score += cross_score
        risk_factors["cross_community"] = cross_score

        # 3. 测试覆盖率（未测试的代码风险更高）
        test_score = RISK_WEIGHTS["test_coverage_base"] - (
            min(node.test_coverage / 5.0, 1.0) * 0.25
        )
        score += test_score
        risk_factors["test_coverage_gap"] = test_score

        # 4. 安全敏感度
        security_score = 0.0
        name_lower = node.name.lower()
        qn_lower = node.qualified_name.lower()
        if any(
            kw in name_lower or kw in qn_lower
            for kw in self._security_keywords_lower
        ):
            security_score = RISK_WEIGHTS["security_sensitive"]
        score += security_score
        risk_factors["security_sensitive"] = security_score

        # 5. 调用者数量
        caller_score = min(
            node.caller_count / 20.0,
            RISK_WEIGHTS["caller_count"]
        )
        score += caller_score
        risk_factors["caller_count"] = caller_score

        # 最终评分限制在 [0, 1]
        overall_score = round(min(max(score, 0.0), 1.0), 4)

        # 确定严重性级别
        severity = self._score_to_severity(overall_score)

        return RiskScoreResult(
            overall_score=overall_score,
            severity=severity,
            risk_factors=risk_factors,
            details={
                "node_name": node.name,
                "node_kind": node.kind,
                "is_test": node.is_test,
            },
        )

    def compute_aggregate_risk(
        self,
        nodes: List[CodeNode],
    ) -> RiskScoreResult:
        """计算多个代码节点的聚合风险"""
        if not nodes:
            return RiskScoreResult(
                overall_score=0.0,
                severity="info",
                risk_factors={},
                details={"node_count": 0},
            )

        # 计算每个节点的风险
        individual_scores = [
            self.compute_risk_score(node)
            for node in nodes
        ]

        # 聚合：取最大风险
        max_score = max(r.overall_score for r in individual_scores)
        avg_score = sum(r.overall_score for r in individual_scores) / len(individual_scores)

        # 聚合风险因素
        aggregate_factors: Dict[str, float] = {}
        for score in individual_scores:
            for factor, value in score.risk_factors.items():
                if factor not in aggregate_factors or value > aggregate_factors[factor]:
                    aggregate_factors[factor] = value

        severity = self._score_to_severity(max_score)

        return RiskScoreResult(
            overall_score=max_score,
            severity=severity,
            risk_factors=aggregate_factors,
            details={
                "node_count": len(nodes),
                "max_score": max_score,
                "avg_score": avg_score,
                "individual_scores": [
                    {"node": n.name, "score": s.overall_score, "severity": s.severity}
                    for n, s in zip(nodes, individual_scores)
                ],
            },
        )

    def _score_to_severity(self, score: float) -> str:
        """将数值评分转换为严重性级别"""
        if score >= SEVERITY_LEVELS["critical"]:
            return "critical"
        elif score >= SEVERITY_LEVELS["high"]:
            return "high"
        elif score >= SEVERITY_LEVELS["medium"]:
            return "medium"
        elif score >= SEVERITY_LEVELS["low"]:
            return "low"
        else:
            return "info"


# 便捷函数
_default_scorer: Optional[RiskScorer] = None


def get_default_scorer() -> RiskScorer:
    """获取默认的风险评分器实例"""
    global _default_scorer
    if _default_scorer is None:
        _default_scorer = RiskScorer()
    return _default_scorer


def score_node(node: CodeNode) -> RiskScoreResult:
    """便捷函数：为单个节点评分"""
    return get_default_scorer().compute_risk_score(node)


def score_nodes(nodes: List[CodeNode]) -> RiskScoreResult:
    """便捷函数：为多个节点聚合评分"""
    return get_default_scorer().compute_aggregate_risk(nodes)
