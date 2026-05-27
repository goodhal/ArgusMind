"""项目 schema"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ProjectBase(BaseModel):
    name: str = Field(..., max_length=255)
    path: str
    description: str = ""
    description_compact: str = ""
    project_uuid: str = Field(..., max_length=64)
    source_type: Literal["git", "upload", "path"]
    source_git_url: Optional[str] = None
    source_git_branch: Optional[str] = None
    source_path: Optional[str] = None
    storage_path: str = ""


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    path: Optional[str] = None
    session_id: Optional[str] = Field(None, max_length=64)
    description: Optional[str] = None
    description_compact: Optional[str] = None
    source_git_url: Optional[str] = None
    source_git_branch: Optional[str] = None
    source_path: Optional[str] = None
    storage_path: Optional[str] = None
    language_stats: Optional[Dict[str, Any]] = None
    file_count: Optional[int] = None
    line_count: Optional[int] = None


class ProjectRead(ProjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    file_count: int = 0
    line_count: int = 0
    language_stats: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


HealthStatus = Literal["normal", "risk", "pending_scan"]
ProjectSourceType = Literal["git", "upload", "path"]


class ProjectListItem(BaseModel):
    """项目列表项（项目管理列表页）。"""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="项目 ID")
    name: str = Field(..., description="项目名称")
    path: str = Field(..., description="项目在服务器上的工作目录绝对路径")
    repo_path: Optional[str] = Field(None, description="用户可见的仓库/来源路径")
    branch: Optional[str] = Field(None, description="Git 分支；非 git 数据源时为 null")
    source_type: Optional[ProjectSourceType] = Field(None, description="代码来源：git / upload / path")
    health_status: HealthStatus = Field(..., description="项目状态，用于 Tab 筛选")
    language: Optional[Dict[str, Any]] = Field(
        None,
        description="tokei 原始 JSON（language_stats），未采集为 null",
    )
    vulnerability_count: int = Field(0, description="漏洞总数")
    high_risk_count: int = Field(0, description="高危 + 严重漏洞合计")
    file_count: int = Field(0, description="文件总数")
    line_count: int = Field(0, description="代码行数")
    last_scanned_at: Optional[datetime] = Field(None, description="最近一次成功扫描时间（UTC）")


class ProjectStats(BaseModel):
    """Tab 角标数量汇总"""

    total: int = Field(..., description="符合筛选条件的项目总数")
    normal: int = Field(..., description="health_status=normal 的数量")
    risk: int = Field(..., description="health_status=risk 的数量")
    pending_scan: int = Field(..., description="health_status=pending_scan 的数量")
