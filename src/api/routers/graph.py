"""图查询路由：返回可视化所需的 nodes/edges。"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Query

import src.storage.manager as db_manager
from src.api.exceptions import AppException, NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse
from services import graph_service

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[CurrentUserDep])


def _neo4j_repo():
    try:
        return db_manager.neo4j_repository
    except Exception as ex:
        raise AppException(message=f"Neo4j 未初始化: {ex}", code="NEO4J_UNAVAILABLE", status_code=503)


@router.get("", response_model=OkResponse[dict])
def get_graph(
    task_id: str = Query(..., min_length=1, description="任务 ID，对应 Neo4j Task 根节点的 task_id"),
) -> OkResponse[dict]:
    """返回图可视化所需的 nodes / edges。

    从 ``Task`` 节点起，返回与其通过无向关系连通的**全部**节点与（两端均在分量内的）全部边，
    不设深度与条数上限。
    """
    _neo4j_repo()
    try:
        data = graph_service.fetch_task_neighborhood_graph(task_id)
    except Exception as ex:
        raise AppException(message=f"Neo4j 查询失败: {ex}", code="NEO4J_QUERY_FAILED", status_code=500)

    return OkResponse[dict](data=data)


@router.get("/result-to-language", response_model=OkResponse[dict])
def get_result_to_language_path(
    task_id: str = Query(..., min_length=1, description="任务 ID"),
    result_node_id: str = Query(..., min_length=1, description="AnalysisResult 的 Neo4j elementId"),
) -> OkResponse[dict]:
    """返回 AnalysisResult 至 Language 的全部路径子图（含 Knowledge、AuditInfo；paths 为多条链）。"""
    _neo4j_repo()
    try:
        data = graph_service.fetch_result_to_language_path(task_id, result_node_id)
    except Exception as ex:
        logger.exception("[graph/result-to-language] task_id=%s result_node_id=%s", task_id, result_node_id)
        raise AppException(message=f"Neo4j 查询失败: {ex}", code="NEO4J_QUERY_FAILED", status_code=500)

    if not data.get("paths"):
        raise NotFoundError("分析结果不存在或与 Language 无连通路径")

    return OkResponse[dict](data=data)
