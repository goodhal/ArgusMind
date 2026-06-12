"""漏洞路由"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from src.api.deps import Pagination, pagination
from src.api.exceptions import NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import OkResponse, PageResult
from src.schemas.stats import DailySeverityStat, FindingStats, FindingTypeStat
from src.schemas.vulnerability import (
    FindingFilter,
    FindingListItem,
    FindingRead,
    FindingStatusUpdate,
    FindingUpdate,
    FindingVerificationUpdate,
)
from src.services import stats_service, vulnerability_service

router = APIRouter(dependencies=[CurrentUserDep])


@router.get(
    "/stats",
    response_model=OkResponse[FindingStats],
    summary="漏洞数量统计",
    description="漏洞总数及各严重等级（level）数量。",
)
def finding_stats() -> OkResponse[FindingStats]:
    return OkResponse[FindingStats](data=stats_service.get_finding_stats())


@router.get(
    "/stats/by-type",
    response_model=OkResponse[List[FindingTypeStat]],
    summary="漏洞类型统计",
    description="按 category_name 分组计数，默认返回前 50 类。",
)
def finding_stats_by_type(
    limit: int = Query(50, ge=1, le=200, description="返回类型条数上限"),
) -> OkResponse[List[FindingTypeStat]]:
    return OkResponse[List[FindingTypeStat]](
        data=stats_service.list_finding_type_stats(limit=limit)
    )


@router.get(
    "/stats/daily",
    response_model=OkResponse[List[DailySeverityStat]],
    summary="漏洞按日 × 严重等级",
    description="按 UTC 日期与 level 聚合；默认最近 30 天。",
)
def finding_stats_daily(
    days: int = Query(30, ge=1, le=365, description="统计最近 N 天（UTC）"),
) -> OkResponse[List[DailySeverityStat]]:
    return OkResponse[List[DailySeverityStat]](
        data=stats_service.list_finding_daily_stats(days=days)
    )


@router.get("", response_model=PageResult[FindingListItem])
def list_findings(
    project_id: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="与主表 level 匹配（大小写不敏感）"),
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None, description="来源过滤"),
    page: Pagination = Depends(pagination),
) -> PageResult[FindingListItem]:
    flt = FindingFilter(
        project_id=project_id,
        task_id=task_id,
        keyword=keyword,
        severity=severity,
        status=status,
        source=source,
    )
    rows, total = vulnerability_service.list_findings(flt, current=page.current, page_size=page.page_size)
    return PageResult[FindingListItem](data=[FindingListItem.model_validate(r) for r in rows], total=total)


@router.get("/export", summary="导出漏洞列表为 Excel")
def export_findings(
    project_id: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
):
    from io import BytesIO
    from openpyxl import Workbook

    from src.repositories.vulnerability_repository import VulnerabilityRepository
    from src.infrastructure.db import session_scope
    from src.infrastructure.db.models import Vulnerability, VulnerabilityDetail

    flt = FindingFilter(
        project_id=project_id,
        task_id=task_id,
        keyword=keyword,
        severity=severity,
        status=status,
        source=source,
    )
    with session_scope() as session:
        rows, _ = VulnerabilityRepository(session).list(
            project_id=flt.project_id,
            task_id=flt.task_id,
            keyword=flt.keyword,
            severity=flt.severity,
            status=flt.status,
            source=flt.source,
            current=1,
            page_size=10000,
        )
        wb = Workbook()
        ws = wb.active
        ws.title = "漏洞列表"
        ws.append(["ID", "漏洞名称", "等级", "判定", "来源", "状态", "二次校验", "置信度", "文件位置", "CWE", "创建时间"])
        for r in rows:
            ep = str(getattr(r.detail, "entry_points", "")) if r.detail else ""
            cwe = str(getattr(r.detail, "cwe", "")) if r.detail else ""
            ws.append([
                r.id, r.vul_name, r.level, r.verdict, r.source, r.status,
                r.verification_status, r.confidence, ep, cwe,
                r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
            ])
        buf = BytesIO()
        wb.save(buf)
        buf.seek(0)

    from fastapi.responses import Response
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.xlsx"},
    )


@router.get(
    "/by-neo4j-element-id",
    response_model=OkResponse[FindingRead],
    summary="按 Neo4j elementId 查询漏洞",
    description="通过 neo4j_element_id 返回漏洞 id 及 detail。",
)
def get_finding_by_neo4j_element_id(
    neo4j_element_id: str = Query(..., description="Neo4j 节点 elementId"),
) -> OkResponse[FindingRead]:
    f = vulnerability_service.get_finding_by_neo4j_element_id(neo4j_element_id)
    if f is None:
        raise NotFoundError("漏洞不存在")
    return OkResponse[FindingRead](data=FindingRead.model_validate(f))


@router.get("/{finding_id}", response_model=OkResponse[FindingRead])
def get_finding(finding_id: str) -> OkResponse[FindingRead]:
    f = vulnerability_service.get_finding(finding_id)
    if f is None:
        raise NotFoundError("漏洞不存在")
    return OkResponse[FindingRead](data=FindingRead.model_validate(f))


@router.put("/{finding_id}", response_model=OkResponse[FindingRead])
def update_finding(finding_id: str, body: FindingUpdate) -> OkResponse[FindingRead]:
    f = vulnerability_service.update_finding(finding_id, body)
    if f is None:
        raise NotFoundError("漏洞不存在")
    return OkResponse[FindingRead](data=FindingRead.model_validate(f))


@router.patch("/{finding_id}/status", response_model=OkResponse[FindingRead])
def update_finding_status(finding_id: str, body: FindingStatusUpdate) -> OkResponse[FindingRead]:
    f = vulnerability_service.update_finding(finding_id, FindingUpdate(status=body.status.value))
    if f is None:
        raise NotFoundError("漏洞不存在")
    return OkResponse[FindingRead](data=FindingRead.model_validate(f))


@router.delete("/{finding_id}", response_model=OkResponse[bool])
def delete_finding(finding_id: str) -> OkResponse[bool]:
    ok = vulnerability_service.delete_finding(finding_id)
    if not ok:
        raise NotFoundError("漏洞不存在")
    return OkResponse[bool](data=True)


@router.patch("/{finding_id}/verification", response_model=OkResponse[FindingRead])
def update_finding_verification(
    finding_id: str, body: FindingVerificationUpdate
) -> OkResponse[FindingRead]:
    """更新漏洞的三态验证状态（confirmed / uncertain / rejected）。"""
    f = vulnerability_service.update_finding_verification(
        finding_id,
        body.verification_status,
        body.verification_reason,
        body.reviewed_severity,
    )
    if f is None:
        raise NotFoundError("漏洞不存在")
    return OkResponse[FindingRead](data=FindingRead.model_validate(f))
