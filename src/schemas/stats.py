"""仪表盘 / 统计 schema"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class TaskStats(BaseModel):
    total: int = Field(..., description="任务总数")
    by_status: Dict[str, int] = Field(
        ...,
        description="各状态数量，键为 pending|running|completed|failed|cancelled",
    )


class LanguageStatItem(BaseModel):
    language: str
    code: int = 0
    files: int = 0
    lines: int = 0


class ProjectTopByVuln(BaseModel):
    project_id: str
    project_name: str
    vulnerability_count: int


class ProjectOverviewStats(BaseModel):
    total_projects: int = Field(..., description="项目总数")
    total_files: int = Field(..., description="全平台文件数合计（projects.file_count 求和）")
    total_lines: int = Field(..., description="全平台代码行数合计（projects.line_count 求和）")
    languages: List[LanguageStatItem] = Field(
        default_factory=list,
        description="全平台各语言汇总（合并 projects.language_stats.languages）",
    )
    top_by_vulnerabilities: List[ProjectTopByVuln] = Field(
        ...,
        description="按漏洞数量降序 Top5 项目",
    )


class FindingStats(BaseModel):
    total: int = Field(..., description="漏洞总数")
    by_severity: Dict[str, int] = Field(
        ...,
        description="各严重等级数量（level 小写：info|low|medium|high|critical|unknown）",
    )


class FindingTypeStat(BaseModel):
    category_name: str = Field(..., description="漏洞类型 / 分类名")
    count: int


class DailySeverityStat(BaseModel):
    date: str = Field(..., description="UTC 日期 YYYY-MM-DD")
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    unknown: int = 0


class TokenStats(BaseModel):
    llm_input: int = 0
    llm_output: int = 0
    code_agent_input: int = 0
    code_agent_output: int = 0
    total: int = Field(..., description="四列之和")


class DailyTokenStat(BaseModel):
    date: str = Field(..., description="UTC 日期 YYYY-MM-DD")
    llm_input: int = 0
    llm_output: int = 0
    code_agent_input: int = 0
    code_agent_output: int = 0
    total: int = 0
