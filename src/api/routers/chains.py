"""调用链路由

接口：
  GET /chains?finding_id=...   返回漏洞对应的调用链
  GET /chains/by-task/{task_id} 返回任务下所有调用链概要

实现：直接查 Neo4j，依赖 chain_analyzer 产生的 (AnalysisResult) - [CALLS*]-> (SinkNode) 路径模型。
对于不存在 Neo4j 的降级场景，返回空列表。
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Query

import src.storage.manager as db_manager
from src.api.exceptions import AppException
from src.api.security import CurrentUserDep
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import Vulnerability
from src.schemas.common import OkResponse

router = APIRouter(dependencies=[CurrentUserDep])


def _neo4j_repo():
    try:
        return db_manager.neo4j_repository
    except Exception as ex:
        raise AppException(message=f"Neo4j 未初始化: {ex}", code="NEO4J_UNAVAILABLE", status_code=503)


@router.get("", response_model=OkResponse[list])
def list_chains(finding_id: str = Query(..., description="漏洞 ID")) -> OkResponse[list]:
    """按漏洞 ID 返回所关联的调用链路径。"""
    with session_scope() as session:
        finding = session.get(Vulnerability, finding_id)
        if finding is None:
            raise NotFoundError("漏洞不存在")
        element_id = finding.neo4j_element_id

    if not element_id:
        return OkResponse[list](data=[])

    repo = _neo4j_repo()
    query = """
    MATCH (f) WHERE elementId(f) = $eid
    OPTIONAL MATCH p = (f)-[:BASED_ON|HAS_PATH|CALLS*1..8]-(x)
    WITH p
    WHERE p IS NOT NULL
    RETURN
      [n IN nodes(p) | {
        elementId: elementId(n),
        labels: labels(n),
        props: properties(n)
      }] AS nodes,
      [r IN relationships(p) | {
        elementId: elementId(r),
        type: type(r),
        props: properties(r)
      }] AS rels
    LIMIT 50
    """
    try:
        records = repo.client.execute_read(query, {"eid": element_id})
    except Exception as ex:
        raise AppException(message=f"Neo4j 查询失败: {ex}", code="NEO4J_QUERY_FAILED", status_code=500)

    chains: List[Dict[str, Any]] = []
    for rec in records:
        chains.append({"nodes": rec["nodes"], "relationships": rec["rels"]})
    return OkResponse[list](data=chains)


@router.get("/by-task/{task_id}", response_model=OkResponse[list])
def chains_by_task(task_id: str) -> OkResponse[list]:
    """按任务返回该任务生成的所有链路概要。"""
    repo = _neo4j_repo()
    query = """
    MATCH (ar:AnalysisResult {task_id: $task_id})
    RETURN elementId(ar) AS elementId, properties(ar) AS props
    ORDER BY ar.created_at DESC
    LIMIT 200
    """
    try:
        records = repo.client.execute_read(query, {"task_id": task_id})
    except Exception as ex:
        raise AppException(message=f"Neo4j 查询失败: {ex}", code="NEO4J_QUERY_FAILED", status_code=500)
    return OkResponse[list](data=[{"elementId": r["elementId"], **r["props"]} for r in records])
