"""链路图 API：Neo4j 子图供 React Flow 使用（见 src/doc/frontend_chain_graph_reactflow.md）。"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Query, Request, Response

import src.storage.manager as db_manager
from src.api.exceptions import AppException, NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse
from src.services import chain_graph_service as cgs

router = APIRouter(dependencies=[CurrentUserDep])


def _neo4j_repo():
    try:
        return db_manager.neo4j_repository
    except Exception as ex:
        raise AppException(message=f"Neo4j 未初始化: {ex}", code="NEO4J_UNAVAILABLE", status_code=503)


def _etag_match(request: Request, graph_version: str) -> bool:
    inm = request.headers.get("if-none-match") or request.headers.get("If-None-Match")
    if not inm:
        return False
    inm = inm.strip().strip('"')
    return inm == graph_version


@router.get("/by-vul", response_model=OkResponse[dict])
def chain_graph_by_vul(
    request: Request,
    response: Response,
    vul_node_id: str = Query(..., description="RiskCategory.node_id"),
    task_id: str = Query(..., description="与 Neo4j RiskCategory.task_id 对齐"),
    max_depth: int = Query(80, ge=1, le=150, description="FLOW 可变长上界，不超过 150"),
    include_completed_results: bool = Query(
        True,
        description="为 false 时排除 status=completed 的 AnalysisResult 及其 HAS_RESULT 边",
    ),
) -> Response | OkResponse[dict]:
    _neo4j_repo()
    if not cgs.verify_risk_category_for_task(vul_node_id, task_id):
        raise NotFoundError("漏洞上下文不存在或 task_id 不匹配")

    data: Dict[str, Any] = cgs.fetch_graph_by_vul(
        vul_node_id,
        task_id,
        max_depth=max_depth,
        include_completed_results=include_completed_results,
    )
    gv = str(data.get("graph_version") or "")
    response.headers["ETag"] = f'"{gv}"'
    if _etag_match(request, gv):
        return Response(status_code=304)
    return OkResponse[dict](data=data)


@router.get("/by-ar", response_model=OkResponse[dict])
def chain_graph_by_ar(
    request: Request,
    response: Response,
    ar_node_id: str = Query(..., description="AnalysisResult 的 Neo4j elementId"),
    task_id: str = Query(..., description="与 Neo4j RiskCategory.task_id 对齐，用于鉴权"),
) -> Response | OkResponse[dict]:
    _neo4j_repo()
    if not cgs.verify_analysis_result_for_task(ar_node_id, task_id):
        raise NotFoundError("分析结果不存在或不在该 task 范围内")

    data = cgs.fetch_graph_by_ar(ar_node_id, task_id)
    gv = str(data.get("graph_version") or "")
    response.headers["ETag"] = f'"{gv}"'
    if _etag_match(request, gv):
        return Response(status_code=304)
    return OkResponse[dict](data=data)


@router.get("/node-detail", response_model=OkResponse[dict])
def chain_graph_node_detail(
    task_id: str = Query(..., description="用于子图鉴权"),
    id: Optional[str] = Query(None, description="Neo4j elementId"),
    kind: Optional[str] = Query(None, description="sinkFlow | chain | result（与业务 id 联用）"),
    business_id: Optional[str] = Query(None, description="sink_node_id / ChainNode.node_id / AnalysisResult 的 Neo4j elementId"),
) -> OkResponse[dict]:
    _neo4j_repo()
    if not id and not (kind and business_id):
        raise AppException(
            message="必须提供 id（elementId）或 kind+business_id",
            code="BAD_QUERY",
            status_code=400,
        )

    detail = cgs.fetch_node_detail(
        task_id=task_id,
        element_id=id,
        kind=kind,
        business_id=business_id,
    )
    if detail is None:
        raise NotFoundError("节点不存在或不在该 task 子图范围内")
    return OkResponse[dict](data=detail)
