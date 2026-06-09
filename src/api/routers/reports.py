"""任务审计报告：聚合 findings + token + LLM event 数量形成概览。

增强：返回快速扫描统计、覆盖率数据、HTML 报告下载路径。
"""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, HTTPException

from sqlalchemy import func, select

from src.api.security import CurrentUserDep
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventRecord, LogEntry, Project, Task, Vulnerability
from src.schemas.common import OkResponse
from src.services.token_service import sum_task_tokens_from_ledger

router = APIRouter(dependencies=[CurrentUserDep])


def _extract_quick_scan_stats(events: list[EventRecord]) -> dict:
    """从事件记录中提取快速扫描统计。

    返回字段：
        completed: 快速扫描是否完成
        findings_count: 总发现数
        rule_findings: 规则层发现数
        llm_findings: LLM 复核发现数
        rule_targets: 规则层扫描目标数
        llm_called_targets: LLM 已调用目标数
        llm_skipped_targets: LLM 跳过目标数
        source_mode: 来源模式
    """
    result = {
        "completed": False,
        "findings_count": 0,
        "rule_findings": 0,
        "llm_findings": 0,
        "rule_targets": 0,
        "llm_called_targets": 0,
        "llm_skipped_targets": 0,
        "reason": "",
        "source_mode": "unknown",
    }

    for ev in events:
        reason = ev.reason or ""
        # 快速扫描
        if "快速扫描" in reason or "quick_scan" in reason.lower():
            result["completed"] = ev.status == "completed"
            # 提取发现数量
            match = re.search(r"(\d+)\s*个潜在问题", reason)
            if match:
                result["findings_count"] = int(match.group(1))
            result["reason"] = reason
        # LLM 已调用目标数
        llm_match = re.search(r"LLM\s*(?:已复核|调用)[^\d]*(\d+)\s*(?:个|条|目标)", reason)
        if llm_match:
            result["llm_called_targets"] = int(llm_match.group(1))
        # LLM 跳过目标数
        skip_match = re.search(r"LLM\s*跳过[^\d]*(\d+)\s*(?:个|条|目标)", reason)
        if skip_match:
            result["llm_skipped_targets"] = int(skip_match.group(1))
        # 来源模式检测
        if "GitHub" in reason:
            result["source_mode"] = "GitHub 候选发现"
        elif "Gitee" in reason:
            result["source_mode"] = "Gitee 候选发现"
        elif "URL" in reason or "url" in reason.lower():
            result["source_mode"] = "URL 导入"
        elif "ZIP" in reason or "zip" in reason.lower():
            result["source_mode"] = "ZIP 代码包上传"
        elif "本地" in reason or "local" in reason.lower():
            result["source_mode"] = "本地代码导入"
        # 规则层目标数
        rule_match = re.search(r"规则层[^\d]*(\d+)\s*(?:个|条|目标)", reason)
        if rule_match:
            result["rule_targets"] = int(rule_match.group(1))

    return result


def _extract_coverage_data(events: list[EventRecord]) -> dict:
    """从事件记录中提取覆盖率数据。

    覆盖率事件格式（orchestrator 发布）：
        reason="审计覆盖率报告: 45.5% (23/50 文件)"
    """
    for ev in events:
        if "覆盖率" in (ev.reason or ""):
            # 从 reason 中提取覆盖率百分比和文件数
            rate_match = re.search(r"(\d+(?:\.\d+)?)\s*%", ev.reason or "")
            if not rate_match:
                rate_match = re.search(r"(\d+(?:\.\d+)?)\s*%", ev.final_status or "")
            rate = float(rate_match.group(1)) if rate_match else 0
            # 从 reason 提取已审查/总文件
            file_match = re.search(r"(\d+)/(\d+)\s*文件", ev.reason or "")
            reviewed = int(file_match.group(1)) if file_match else 0
            total = int(file_match.group(2)) if file_match else 0
            return {
                "coverage_rate": rate,
                "reviewed_files": reviewed,
                "total_files": total,
            }
    return {"coverage_rate": 0, "reviewed_files": 0, "total_files": 0}


def _find_html_report(project_path: str, task_id: str) -> dict:
    """查找已生成的 HTML 报告文件。"""
    report_dir = os.path.join(project_path, ".argusmind", "reports")
    report_file = os.path.join(report_dir, f"audit-report-{task_id}.html")
    if os.path.isfile(report_file):
        return {
            "available": True,
            "download_path": f"/api/reports/{task_id}/html",
            "file_name": f"audit-report-{task_id}.html",
        }
    return {"available": False, "download_path": "", "file_name": ""}


@router.get("/{task_id}", response_model=OkResponse[dict])
def get_report(task_id: str) -> OkResponse[dict]:
    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        findings_rows = (
            session.execute(
                select(Vulnerability)
                .where(Vulnerability.task_id == task_id)
                .where(Vulnerability.status != "false_positive")
                .order_by(Vulnerability.created_at.desc())
            )
            .scalars()
            .all()
        )
        # 使用 collect_enriched_findings 获取完整的 findings 数据（与 regenerate 逻辑一致）
        project = session.get(Project, task.project_id) if task.project_id else None
        project_path = project.storage_path if project else ""
        from src.services.vulnerability_service import collect_enriched_findings
        findings_payload = collect_enriched_findings(task_id, project_path)

        rule_source_set = {"quick_scan", "component_scan", "pattern_analyzer"}
        rule_findings_count = len([f for f in findings_payload if f.get("source") in rule_source_set])
        llm_findings_count = len([f for f in findings_payload if f.get("source") not in rule_source_set])

        # 从 findings 计算 verdict 分布
        verdict_counts = {}
        for f in findings_payload:
            v = str(f.get("verdict", "unknown") or "unknown")
            verdict_counts[v] = verdict_counts.get(v, 0) + 1

        # LLM 事件数量
        action_counts = dict(
            session.execute(
                select(EventRecord.action_type, func.count())
                .where(EventRecord.task_id == task_id)
                .group_by(EventRecord.action_type)
            ).all()
        )

        # 日志 ERROR/WARNING 数量
        log_counts = dict(
            session.execute(
                select(LogEntry.level, func.count())
                .where(LogEntry.task_id == task_id)
                .group_by(LogEntry.level)
            ).all()
        )

        # 查询与快速扫描和覆盖率相关的事件
        info_events = (
            session.execute(
                select(EventRecord)
                .where(EventRecord.task_id == task_id)
                .where(EventRecord.action_type == "information")
                .order_by(EventRecord.started_at.asc())
            )
            .scalars()
            .all()
        )

        li, lo, ci, co = sum_task_tokens_from_ledger(session, task_id)

        # 快速扫描统计：findings_count 用数据库实际入库数量，与 severity 统计一致
        quick_scan = _extract_quick_scan_stats(list(info_events))
        quick_scan["findings_count"] = len(findings_payload)
        # 按 source 分类统计（与参考报告格式对齐）
        quick_scan["rule_findings"] = rule_findings_count
        quick_scan["llm_findings"] = llm_findings_count

        # 覆盖率数据：从项目文件重新计算（不依赖事件历史）
        from src.services.coverage_tracker import CoverageTracker
        _project_file_list = []
        try:
            from src.core.orchestrator import Orchestrator
            _orch = Orchestrator()
            _project_file_list = _orch._collect_project_files(str(project_path))
        except Exception:
            pass
        _ct = CoverageTracker(str(project_path), _project_file_list)
        for _pf in _project_file_list:
            _ct.mark_reviewed(_pf, "quick_scan")
        for _f in findings_payload:
            _file = _f.get("file", "")
            if _file:
                _ct.mark_reviewed(_file, _f.get("vuln_type", ""))
        coverage = _ct.generate_report()

        # HTML 报告路径
        html_report = _find_html_report(project_path, task_id)

        # 严重等级分布（从 enriched findings 中统计）
        severity_counts = {"C": 0, "H": 0, "M": 0, "L": 0}
        for f in findings_payload:
            lvl = str(f.get("severity", "")).upper()
            if lvl in ("CRITICAL", "C"):
                severity_counts["C"] += 1
            elif lvl in ("HIGH", "H"):
                severity_counts["H"] += 1
            elif lvl in ("MEDIUM", "M"):
                severity_counts["M"] += 1
            else:
                severity_counts["L"] += 1

        # audit_score：从 findings 计算
        audit_score_result = None
        try:
            from src.knowledge.audit_scoring import calculate_audit_score
            audit_score_result = calculate_audit_score(findings_payload)
        except Exception:
            pass

        # scan_stats：从 findings 统计
        scan_stats = {
            "code_findings": len([f for f in findings_payload if f.get("source") == "quick_scan"]),
            "component_findings": len([f for f in findings_payload if f.get("source") == "component_scan"]),
            "total_findings": len(findings_payload),
            "rule_findings": rule_findings_count,
            "llm_findings": llm_findings_count,
            "source_mode": "URL 导入",  # 默认值，后续从事件覆盖
        }
        for ev in info_events:
            if "快速扫描" in (ev.reason or ""):
                import re
                m = re.search(r"(\d+)\s*个潜在问题", ev.reason or "")
                if m:
                    scan_stats["total_candidates"] = int(m.group(1))
                # 来源模式
                reason = ev.reason or ""
                if "GitHub" in reason:
                    scan_stats["source_mode"] = "GitHub 候选发现"
                elif "Gitee" in reason:
                    scan_stats["source_mode"] = "Gitee 候选发现"
                elif "ZIP" in reason:
                    scan_stats["source_mode"] = "ZIP 代码包上传"
                elif "URL" in reason:
                    scan_stats["source_mode"] = "URL 导入"

        report = {
            "task": {
                "id": task.id,
                "project_id": task.project_id,
                "status": task.status,
                "started_at": task.created_at.isoformat() if task.created_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "error": task.error or "",
            },
            "tokens": {
                "llm_input": li,
                "llm_output": lo,
                "code_agent_input": ci,
                "code_agent_output": co,
            },
            "summary": {
                "total_findings": len(findings_payload),
                "verdict": verdict_counts,
                "severity": severity_counts,
                "events_by_action": action_counts,
                "log_levels": log_counts,
            },
            "quick_scan": quick_scan,
            "coverage": coverage,
            "html_report": html_report,
            "scan_stats": scan_stats,
            "audit_score": audit_score_result,
            "findings": findings_payload,
        }
        return OkResponse[dict](data=report)


@router.get("/{task_id}/html")
def get_html_report(task_id: str):
    """下载 HTML 审计报告。"""
    from fastapi.responses import FileResponse

    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        project = session.get(Project, task.project_id) if task.project_id else None
        if not project:
            raise HTTPException(status_code=404, detail="project not found")

        report_dir = os.path.join(project.storage_path, ".argusmind", "reports")
        report_file = os.path.join(report_dir, f"audit-report-{task_id}.html")

        if not os.path.isfile(report_file):
            raise HTTPException(status_code=404, detail="HTML report not found")

        return FileResponse(
            report_file,
            media_type="text/html",
            filename=f"audit-report-{task_id}.html",
        )


@router.post("/{task_id}/regenerate")
def regenerate_html_report(task_id: str):
    """重新生成 HTML 审计报告（含评分/覆盖率/利用链等完整数据）。"""
    from src.services.report_generator import write_report_to_file

    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        project = session.get(Project, task.project_id) if task.project_id else None
        if not project:
            raise HTTPException(status_code=404, detail="project not found")

        project_name = project.name or "Unknown"
        project_path = project.storage_path or ""
        if not project_path:
            raise HTTPException(status_code=400, detail="project storage_path is empty")

        # 使用共享的 collect_enriched_findings（与 orchestrator 首次报告逻辑一致）
        from src.services.vulnerability_service import collect_enriched_findings
        findings = collect_enriched_findings(task_id, project_path)

        # 查询扫描统计信息事件
        evs = session.query(EventRecord).filter(
            EventRecord.task_id == task_id,
            EventRecord.action_type == "information"
        ).order_by(EventRecord.started_at.asc()).all()

        quick_scan = [f for f in findings if f.get("source") in ("quick_scan", "component_scan", "pattern_analyzer")]
        llm = [f for f in findings if f.get("source") not in ("quick_scan", "component_scan", "pattern_analyzer")]

        # --- audit_score：从 findings 重新计算 ---
        audit_score_result = None
        try:
            from src.knowledge.audit_scoring import calculate_audit_score
            audit_score_result = calculate_audit_score(findings)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"[regenerate] calculate_audit_score 失败: {e}")

        # --- scan_stats：从事件 + findings 统计重建 ---
        rule_source_set = {"quick_scan", "component_scan", "pattern_analyzer"}
        rule_findings_list = [f for f in findings if f.get("source") in rule_source_set]
        llm_findings_list = [f for f in findings if f.get("source") not in rule_source_set]

        # 获取项目文件数
        total_files_scanned = 0
        try:
            from src.core.orchestrator import Orchestrator
            _orch = Orchestrator()
            total_files_scanned = len(_orch._collect_project_files(str(project_path)))
        except Exception:
            pass

        scan_stats = {
            "code_findings": len([f for f in findings if f.get("source") == "quick_scan"]),
            "component_findings": len([f for f in findings if f.get("source") == "component_scan"]),
            "total_findings": len(findings),
            "rule_findings": len(rule_findings_list),
            "llm_findings": len(llm_findings_list),
            "total_files_scanned": total_files_scanned,
            "source_mode": "URL 导入",  # 默认值，后续从事件覆盖
        }
        # 从 information 事件提取原始扫描统计
        for ev in evs:
            reason = ev.reason or ""
            # 来源模式（所有事件中检测，避免被 "快速扫描" 内的覆盖逻辑重复设置）
            src_set = scan_stats.get("source_mode", "unknown")
            if src_set == "unknown" or src_set == "URL 导入":
                if "GitHub" in reason:
                    scan_stats["source_mode"] = "GitHub 候选发现"
                elif "Gitee" in reason:
                    scan_stats["source_mode"] = "Gitee 候选发现"
                elif "ZIP" in reason or "zip" in reason.lower():
                    scan_stats["source_mode"] = "ZIP 代码包上传"
                elif "URL" in reason or "url" in reason.lower():
                    scan_stats["source_mode"] = "URL 导入"
            # 候选发现数
            if "快速扫描" in reason:
                import re
                m = re.search(r"(\d+)\s*个潜在问题", reason)
                if m:
                    scan_stats["total_candidates"] = int(m.group(1))
                if "代码" in reason:
                    m2 = re.search(r"代码=(\d+)", reason)
                    if m2:
                        scan_stats["code_findings"] = int(m2.group(1))
                if "组件" in reason:
                    m3 = re.search(r"组件=(\d+)", reason)
                    if m3:
                        scan_stats["component_findings"] = int(m3.group(1))

        # --- coverage_report：从项目文件重新计算 ---
        coverage_report = None
        try:
            from src.services.coverage_tracker import CoverageTracker
            from src.core.orchestrator import Orchestrator
            _orch = Orchestrator()
            _project_file_list = _orch._collect_project_files(str(project_path))
            _ct = CoverageTracker(str(project_path), _project_file_list)
            for _pf in _project_file_list:
                _ct.mark_reviewed(_pf, "quick_scan")
            _ct.mark_from_findings(findings)
            coverage_report = _ct.generate_report()
        except Exception:
            pass

        # 收集语言统计信息
        language_stats = None
        try:
            from src.tools import TokeiTool
            tokei = TokeiTool()
            tokei_result = tokei.run(str(project_path))
            if tokei_result.success and tokei_result.data:
                language_stats = tokei_result.data
        except Exception:
            pass

        report_dir = os.path.join(str(project_path), ".argusmind", "reports")
        result = write_report_to_file(
            report_dir=report_dir,
            task_id=task_id,
            project_name=project_name,
            findings=findings,
            audit_score=audit_score_result,
            coverage_report=coverage_report,
            scan_stats=scan_stats,
            quick_scan_findings=quick_scan,
            llm_findings=llm,
            exploit_chain_report=None,
            language_stats=language_stats,
        )

        return OkResponse[dict](data={
            "file_path": result["file_path"],
            "file_name": result["file_name"],
            "total_findings": len(findings),
            "quick_scan_count": len(quick_scan),
            "llm_count": len(llm),
            "audit_score": audit_score_result,
            "scan_stats": scan_stats,
            "coverage": coverage_report,
        })
