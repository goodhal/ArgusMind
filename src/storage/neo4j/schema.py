# -*- coding: utf-8 -*-
"""Neo4j 索引 DDL（幂等，Neo4j 5+ 语法）。

每次 ``init_db``（含应用启动 lifespan）调用 ``ensure_neo4j_indexes``；
语句带 ``IF NOT EXISTS``，索引已存在时不会报错。
"""
from __future__ import annotations

import logging
from typing import Iterable, Tuple

from src.storage.neo4j.client import Neo4jClient

logger = logging.getLogger(__name__)

# 与 MERGE / MATCH 业务键对齐；启动时 IF NOT EXISTS 幂等创建
_INDEX_STATEMENTS: Tuple[str, ...] = (
    # --- P0：幂等写入与核心点查 ---
    "CREATE INDEX task_task_id IF NOT EXISTS FOR (t:Task) ON (t.task_id)",
    "CREATE INDEX audit_stage_task_name IF NOT EXISTS FOR (s:AuditStage) ON (s.task_id, s.name)",
    "CREATE INDEX audit_stage_node_id IF NOT EXISTS FOR (s:AuditStage) ON (s.node_id)",
    "CREATE INDEX language_node_id IF NOT EXISTS FOR (l:Language) ON (l.node_id)",
    "CREATE INDEX risk_category_node_id IF NOT EXISTS FOR (r:RiskCategory) ON (r.node_id)",
    "CREATE INDEX risk_category_node_task IF NOT EXISTS FOR (r:RiskCategory) ON (r.node_id, r.task_id)",
    "CREATE INDEX sink_flow_sink_task IF NOT EXISTS FOR (s:SinkFlowNode) ON (s.sink_node_id, s.task_id)",
    "CREATE INDEX sink_flow_sink_id IF NOT EXISTS FOR (s:SinkFlowNode) ON (s.sink_node_id)",
    "CREATE INDEX chain_node_id_task IF NOT EXISTS FOR (c:ChainNode) ON (c.node_id, c.task_id)",
    "CREATE INDEX chain_node_id IF NOT EXISTS FOR (c:ChainNode) ON (c.node_id)",
    "CREATE INDEX knowledge_rc IF NOT EXISTS FOR (k:Knowledge) ON (k.risk_category_node_id)",
    # --- P1：按 task 划分子图 ---
    "CREATE INDEX language_task_id IF NOT EXISTS FOR (l:Language) ON (l.task_id)",
    "CREATE INDEX risk_category_task_id IF NOT EXISTS FOR (r:RiskCategory) ON (r.task_id)",
    "CREATE INDEX sink_flow_task_id IF NOT EXISTS FOR (s:SinkFlowNode) ON (s.task_id)",
    "CREATE INDEX chain_node_task_id IF NOT EXISTS FOR (c:ChainNode) ON (c.task_id)",
    "CREATE INDEX analysis_result_task_id IF NOT EXISTS FOR (a:AnalysisResult) ON (a.task_id)",
    # --- P2：调度 / 状态过滤 ---
    "CREATE INDEX audit_stage_task_name_status IF NOT EXISTS FOR (s:AuditStage) ON (s.task_id, s.name, s.status)",
    "CREATE INDEX sink_flow_task_status IF NOT EXISTS FOR (s:SinkFlowNode) ON (s.task_id, s.status)",
)


def index_statements() -> Iterable[str]:
    """返回全部索引 DDL（供测试或脚本复用）。"""
    return _INDEX_STATEMENTS


def ensure_neo4j_indexes(client: Neo4jClient) -> None:
    """
    确保项目约定的 Neo4j 属性索引存在。

    使用 ``CREATE INDEX ... IF NOT EXISTS``：已存在的索引会被跳过，不会失败。
    其它错误（权限、Neo4j 版本不兼容等）仅记 warning，不抛异常。
    """
    failed = 0
    for stmt in _INDEX_STATEMENTS:
        try:
            client.execute_write(stmt)
        except Exception as ex:
            failed += 1
            logger.warning(
                "Neo4j 索引创建失败（可忽略若已存在或版本不支持）: %s — %s",
                stmt,
                ex,
            )
    if failed:
        logger.info(
            "Neo4j 索引初始化完成：%d/%d 条语句未成功",
            failed,
            len(_INDEX_STATEMENTS),
        )
    else:
        logger.debug("Neo4j 索引初始化完成：%d 条", len(_INDEX_STATEMENTS))
