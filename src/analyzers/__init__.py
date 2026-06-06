# -*- coding: utf-8 -*-
"""分析器模块 —— 整合自 gbt-codeagent。

包含：
- rules_engine: YAML 规则引擎 + LRU 正则缓存
- taint_analyzer: 污点分析器（source→sink 数据流追踪）
- static_analyzer: 综合静态分析器（模式匹配 + 污点分析）
- exploit_chain: 漏洞利用链分析器
- route_mapper: Java Web 路由映射（Spring/Struts2/Servlet/JAX-RS）
- ast_enricher: AST 增强分析器（50+ 危险 sink 数据库 + 上下文感知分析）
- constants: 安全关键词和风险评分常量
- risk_scorer: 多因素风险评分算法
"""

from src.analyzers.rules_engine import RulesEngine, DetectionRule
from src.analyzers.taint_analyzer import TaintAnalyzer, TaintAnalysisResult
from src.analyzers.static_analyzer import StaticAnalyzer, StaticAnalysisResult
from src.analyzers.exploit_chain import ExploitChain, generate_exploit_chain_report
from src.analyzers.route_mapper import RouteInfo, extract_routes_from_file, extract_routes_from_project, format_routes_for_prompt
from src.analyzers.ast_enricher import (
    ASTEnricherService,
    ASTContext,
    DANGEROUS_SINKS,
    get_global_ast_enricher,
)
from src.analyzers.constants import (
    SECURITY_KEYWORDS,
    RISK_WEIGHTS,
    SEVERITY_LEVELS,
)
from src.analyzers.risk_scorer import (
    CodeNode,
    RiskScorer,
    RiskScoreResult,
    score_node,
    score_nodes,
    get_default_scorer,
)

__all__ = [
    # 规则引擎
    "RulesEngine",
    "DetectionRule",
    # 污点分析
    "TaintAnalyzer",
    "TaintAnalysisResult",
    # 静态分析
    "StaticAnalyzer",
    "StaticAnalysisResult",
    # 漏洞利用链
    "ExploitChain",
    "generate_exploit_chain_report",
    # 路由映射
    "RouteInfo",
    "extract_routes_from_file",
    "extract_routes_from_project",
    "format_routes_for_prompt",
    # AST 增强
    "ASTEnricherService",
    "ASTContext",
    "DANGEROUS_SINKS",
    "get_global_ast_enricher",
    # 风险评分
    "SECURITY_KEYWORDS",
    "RISK_WEIGHTS",
    "SEVERITY_LEVELS",
    "CodeNode",
    "RiskScorer",
    "RiskScoreResult",
    "score_node",
    "score_nodes",
    "get_default_scorer",
]
