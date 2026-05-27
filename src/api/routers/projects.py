"""项目路由"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Query, UploadFile

from src.api.deps import Pagination, pagination
from src.api.exceptions import NotFoundError
from src.api.security import CurrentUserDep
from src.schemas.common import IdNameItem, OkResponse, PageResult
from src.schemas.project import ProjectListItem, ProjectRead, ProjectStats
from src.schemas.stats import ProjectOverviewStats
from src.services import project_service, stats_service

router = APIRouter(dependencies=[CurrentUserDep])


@router.get(
    "/options",
    response_model=OkResponse[List[IdNameItem]],
    summary="全部项目 id 与名称",
    description="返回所有项目的 id、name 列表，用于下拉选择等场景。",
)
def list_project_options() -> OkResponse[List[IdNameItem]]:
    return OkResponse[List[IdNameItem]](data=project_service.list_project_id_names())


@router.get(
    "/stats",
    response_model=OkResponse[ProjectStats],
    summary="项目 Tab 角标数量",
    description="返回全部/正常/风险/待扫描数量；筛选口径与列表一致，不传 health_status。",
)
def project_stats(
    name: Optional[str] = Query(None, description="按项目名称模糊搜索（与 keyword 二选一，优先 name）"),
    keyword: Optional[str] = Query(None, description="搜索关键词，等同 name"),
    source_type: Optional[str] = Query(None, description="代码来源：git / upload / path"),
) -> OkResponse[ProjectStats]:
    search_keyword = name if name is not None else keyword
    stats = project_service.project_stats(keyword=search_keyword, source_type=source_type)
    return OkResponse[ProjectStats](data=stats)


@router.get(
    "/overview",
    response_model=OkResponse[ProjectOverviewStats],
    summary="项目仪表盘概览",
    description="项目总数、文件/代码行合计、各语言汇总、漏洞 Top5 项目。",
)
def project_overview() -> OkResponse[ProjectOverviewStats]:
    return OkResponse[ProjectOverviewStats](data=stats_service.get_project_overview())


@router.get(
    "",
    response_model=PageResult[ProjectListItem],
    summary="分页查询项目列表",
    description="项目管理列表页数据源；支持名称、来源、health_status Tab 筛选。",
)
def list_projects(
    name: Optional[str] = Query(None, description="按项目名称模糊搜索（与 keyword 二选一，优先 name）"),
    keyword: Optional[str] = Query(None, description="搜索关键词，等同 name"),
    source_type: Optional[str] = Query(None, description="代码来源：git / upload / path"),
    health_status: Optional[str] = Query(
        None, description="Tab 筛选：normal / risk / pending_scan；全部项目不传"
    ),
    page: Pagination = Depends(pagination),
) -> PageResult[ProjectListItem]:
    search_keyword = name if name is not None else keyword
    rows, total = project_service.list_projects(
        keyword=search_keyword,
        source_type=source_type,
        health_status=health_status,
        current=page.current,
        page_size=page.page_size,
    )
    return PageResult[ProjectListItem](data=rows, total=total)


@router.post(
    "",
    response_model=OkResponse[ProjectRead],
    summary="创建项目",
    description=(
        "从 Git 仓库、本机目录或 zip 压缩包导入代码并创建项目记录。"
        "创建成功后后台异步清理 node_modules 等噪音目录。"
    ),
)
async def create_project(
    background_tasks: BackgroundTasks,
    name: str = Form(..., description="项目名称，唯一展示名"),
    source_type: str = Form(..., description="数据源类型：git | upload | path"),
    git_url: Optional[str] = Form(None, description="source_type=git 时必填，http/https 仓库地址"),
    git_branch: Optional[str] = Form(None, description="source_type=git 时必填，分支名"),
    source_path: Optional[str] = Form(None, description="source_type=path 时必填，本机绝对目录路径"),
    archive_file: Optional[UploadFile] = File(None, description="source_type=upload 时必填，zip 压缩包"),
) -> OkResponse[ProjectRead]:
    temp_archive: Optional[Path] = None
    try:
        if archive_file is not None:
            suffix = Path(archive_file.filename or "upload.zip").suffix or ".zip"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(await archive_file.read())
                temp_archive = Path(tmp.name)

        project = project_service.create_project_from_source(
            name=name,
            source_type=source_type,
            git_url=git_url,
            git_branch=git_branch,
            source_path=source_path,
            upload_file_path=temp_archive,
        )
        background_tasks.add_task(project_service.cleanup_project_noise, project.path)
        return OkResponse[ProjectRead](data=ProjectRead.model_validate(project))
    finally:
        if temp_archive is not None and temp_archive.exists():
            temp_archive.unlink(missing_ok=True)

@router.delete(
    "",
    response_model=OkResponse[bool],
    summary="删除项目",
    description="按项目 ID 删除数据库记录及服务器上的项目工作目录。",
)
def delete_project_by_query(id: str = Query(..., description="项目 ID")) -> OkResponse[bool]:
    ok = project_service.delete_project(id)
    if not ok:
        raise NotFoundError("项目不存在")
    return OkResponse[bool](data=True)
