# -*- coding utf-8 -*-
"""HTML 审计报告生成器 —— 整合自 gbt-codeagent/services/reportWriter.js。

生成包含以下内容的 HTML 报告：
1. 审计评分卡片（分数环 + 门禁判定）
2. 漏洞统计概览（按严重等级/来源/类型）
3. 漏洞详情列表（代码片段 + 证据 + 修复建议）
4. 覆盖率报告
5. 组件漏洞信息
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def _escape(text: str) -> str:
    """HTML 转义。"""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def _format_beijing_time(iso_string: str) -> str:
    """格式化时间为北京时间。"""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return iso_string


def _score_ring_class(score: int) -> str:
    """根据评分返回 CSS 类名。"""
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    return "low"


def _severity_badge_class(severity: str) -> str:
    """根据严重等级返回 CSS 类名。"""
    s = str(severity).upper()
    if s in ("C", "CRITICAL", "严重"):
        return "critical"
    if s in ("H", "HIGH", "高危"):
        return "high"
    if s in ("M", "MEDIUM", "中危"):
        return "medium"
    return "low"


def _severity_label(severity: str) -> str:
    """获取严重等级中文标签。"""
    s = str(severity).upper()
    if s in ("C", "CRITICAL"):
        return "Critical"
    if s in ("H", "HIGH"):
        return "High"
    if s in ("M", "MEDIUM"):
        return "Medium"
    if s in ("L", "LOW"):
        return "Low"
    return severity


SCAN_SOURCES = frozenset({"quick_scan", "component_scan", "pattern_analyzer"})


# ---------- HTML 报告入口 ----------


def generate_html_report(
    task_id: str,
    project_name: str,
    findings: List[Dict[str, Any]],
    audit_score: Optional[Dict[str, Any]] = None,
    coverage_report: Optional[Dict[str, Any]] = None,
    scan_stats: Optional[Dict[str, Any]] = None,
    quick_scan_findings: Optional[List[Dict[str, Any]]] = None,
    llm_findings: Optional[List[Dict[str, Any]]] = None,
    exploit_chain_report: Optional[Dict[str, Any]] = None,
    language_stats: Optional[Dict[str, Any]] = None,
) -> str:
    """生成完整的 HTML 审计报告。

    Args:
        task_id: 任务 ID
        project_name: 项目名称
        findings: 所有漏洞发现列表
        audit_score: 审计评分结果（来自 calculate_audit_score）
        coverage_report: 覆盖率报告（来自 CoverageTracker.generate_report）
        scan_stats: 扫描统计信息
        quick_scan_findings: 快速扫描发现
        llm_findings: LLM 审计发现

    Returns:
        HTML 字符串
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 分离快速扫描和 LLM 发现
    if quick_scan_findings is None:
        quick_scan_findings = [f for f in findings if f.get("source") in SCAN_SOURCES]
    if llm_findings is None:
        llm_findings = [f for f in findings if f.get("source") not in SCAN_SOURCES]

    # 漏洞统计：分别统计快扫和 LLM，确保与 API 数据一致
    severity_counts = {"C": 0, "H": 0, "M": 0, "L": 0}
    all_reported = (quick_scan_findings or []) + (llm_findings or [])
    for f in all_reported:
        sev = str(f.get("severity", "L")).upper()
        if sev in ("C", "CRITICAL", "严重"):
            severity_counts["C"] += 1
        elif sev in ("H", "HIGH", "高危"):
            severity_counts["H"] += 1
        elif sev in ("M", "MEDIUM", "中危"):
            severity_counts["M"] += 1
        else:
            severity_counts["L"] += 1

    total_findings = len(all_reported)

    # 构建 HTML
    doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>审计报告 - {_escape(project_name)}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    html{{scroll-behavior:smooth;font-size:15px}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6fa;color:#1e293b;line-height:1.6}}
    .app{{display:flex;min-height:100vh;max-width:1400px;margin:0 auto;padding:0 20px}}
    .sidebar{{position:sticky;top:0;width:220px;height:100vh;padding:36px 16px 24px 0;flex-shrink:0;overflow-y:auto}}
    .content{{flex:1;min-width:0;padding:32px 0 64px 32px;max-width:960px}}
    .toc-header{{font-size:13px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #e2e8f0}}
    .toc{{display:flex;flex-direction:column;gap:2px}}
    .toc-link{{display:block;padding:8px 12px;border-radius:8px;font-size:13px;color:#475569;text-decoration:none;transition:all .12s;border-left:3px solid transparent}}
    .toc-link:hover{{background:#eaf3ff;color:#1677ff;border-left-color:#1677ff}}
    .card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px;margin-bottom:20px;box-shadow:0 6px 18px rgba(31,42,68,.04)}}
    .card h2{{font-size:17px;font-weight:600;margin-bottom:16px;color:#0f172a;display:flex;align-items:center;gap:8px}}
    .hero{{background:linear-gradient(135deg,#eaf3ff,#f0f7ff);border:1px solid #b9d4fd}}
    .hero h1{{font-size:22px;font-weight:700;color:#1e293b;margin-bottom:4px}}
    .hero .muted{{font-size:13px;color:#64748b;margin-bottom:20px}}
    .grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:4px}}
    .metric{{padding:14px 16px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0}}
    .metric strong{{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:#64748b;margin-bottom:4px}}
    .metric span{{font-size:20px;font-weight:700;color:#0f172a}}
    .callout{{padding:16px 20px;border-radius:8px;border:1px solid #b9d4fd;background:#f5f9ff;margin-top:16px}}
    .callout strong{{font-size:14px;color:#1e293b;display:block;margin-bottom:6px}}
    .callout p{{font-size:13px;color:#475569;line-height:1.7}}
    .callout .counts{{margin-top:10px;display:flex;gap:16px;flex-wrap:wrap;font-size:13px;font-weight:500}}
    .score-card{{display:flex;align-items:center;gap:20px;padding:16px 20px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;flex-wrap:wrap}}
    .score-ring{{flex-shrink:0;width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;box-shadow:0 4px 12px rgba(31,42,68,.08)}}
    .score-ring.high{{background:#d1fae5;color:#059669;border:3px solid #34d399}}
    .score-ring.medium{{background:#fef3c7;color:#d97706;border:3px solid #fbbf24}}
    .score-ring.low{{background:#fef2f2;color:#dc2626;border:3px solid #f87171}}
    .score-detail{{flex:1;min-width:200px}}
    .score-detail .primary{{font-size:15px;font-weight:600;color:#0f172a;margin-bottom:2px}}
    .score-detail .secondary{{font-size:13px;color:#64748b}}
    .score-gate{{display:inline-block;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:600}}
    .score-gate.pass{{background:#d1fae5;color:#059669}}
    .score-gate.fail{{background:#fef2f2;color:#dc2626}}
    .finding{{border-top:1px solid #e2e8f0;padding-top:16px;margin-top:16px}}
    .finding:first-child{{border-top:none;padding-top:0;margin-top:0}}
    .finding-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:8px}}
    .finding-head h4{{font-size:14px;font-weight:600;color:#0f172a;margin:0;flex:1}}
    .finding p,.finding .desc{{font-size:13px;color:#475569;line-height:1.6;margin-top:6px}}
    .finding p strong{{color:#334155}}
    .badge{{display:inline-block;padding:2px 10px;border-radius:6px;font-size:12px;font-weight:500;white-space:nowrap}}
    .badge.critical{{background:#fef2f2;color:#dc2626}}
    .badge.high{{background:#fef3c7;color:#d97706}}
    .badge.medium{{background:#eff6ff;color:#2563eb}}
    .badge.low{{background:#f1f5f9;color:#64748b}}
    .badge.source-quick{{background:#eaf3ff;color:#1677ff}}
    .badge.source-llm{{background:#f5f3ff;color:#7c3aed}}
    .code-context{{margin:8px 0;padding:12px 14px;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:12px;overflow-x:auto;white-space:pre;font-family:"JetBrains Mono","Cascadia Code","Fira Code",Consolas,monospace;line-height:1.5}}
    .ast-context{{margin-top:12px;padding:12px 14px;border-radius:8px;background:#f0fdf4;border:1px solid #a7f3d0;font-size:13px}}
    .ast-context p{{margin:2px 0}}
    .sub-card{{margin-top:16px;padding:16px 20px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0}}
    .sub-card h4{{font-size:14px;font-weight:600;color:#0f172a;margin-bottom:10px}}
    .coverage-bar{{height:8px;border-radius:999px;background:#e2e8f0;overflow:hidden;margin-top:8px}}
    .coverage-fill{{height:100%;border-radius:999px;transition:width .3s}}
    .coverage-fill.high{{background:#34d399}}
    .coverage-fill.medium{{background:#fbbf24}}
    .coverage-fill.low{{background:#f87171}}
    .muted{{color:#64748b}}
    .tag{{display:inline-block;margin:0 6px 6px 0;padding:4px 10px;border-radius:6px;background:#f1f5f9;border:1px solid #e2e8f0;font-size:12px;color:#475569}}
    table{{width:100%;font-size:13px;border-collapse:collapse}}
    th{{text-align:left;padding:6px 8px;border-bottom:2px solid #e2e8f0;color:#64748b;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}}
    td{{padding:6px 8px;border-bottom:1px solid #f1f5f9}}
    tr:last-child td{{border-bottom:none}}
    a{{color:#1677ff;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    .finding-meta{{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;font-size:13px}}
    .finding-meta .tag{{font-size:12px;padding:2px 8px;border-radius:6px;background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}}
    @media (max-width:860px){{.sidebar{{display:none}}.content{{padding-left:0}}.grid{{grid-template-columns:1fr}}}}
  </style>
</head>
<body>
  <div class="app">
    <nav class="sidebar">
      <div class="toc-header">报告目录</div>
      <div class="toc">
        <a href="#sec-hero" class="toc-link">摘要信息</a>
        <a href="#sec-score" class="toc-link">安全评分</a>
        <a href="#sec-quick-scan" class="toc-link">快速扫描结果</a>
        <a href="#sec-llm-audit" class="toc-link">LLM 深度审计</a>
        <a href="#sec-coverage" class="toc-link">审计覆盖率</a>
      </div>
    </nav>
    <div class="content">
      {_build_hero_section(task_id, project_name, now, total_findings, severity_counts, scan_stats, findings, language_stats)}
      {_build_score_section(audit_score, severity_counts)}
      {_build_findings_section("快速扫描结果", quick_scan_findings, "source-quick", "规则层未发现高置信度结果。")}
      {_build_findings_section("LLM 深度审计结果", llm_findings, "source-llm", "LLM 未发现额外漏洞。")}
      {_build_exploit_chain_section(exploit_chain_report)}
      {_build_coverage_section(coverage_report)}
    </div>
  </div>
</body>
</html>"""
    return doc



def _build_hero_section(
    task_id: str,
    project_name: str,
    now: str,
    total_findings: int,
    severity_counts: Dict[str, int],
    scan_stats: Optional[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    language_stats: Optional[Dict[str, Any]] = None,
) -> str:
    """构建报告头部区域。"""
    # 从 findings 中统计各来源数量
    source_counts: Dict[str, int] = {}
    for f in findings:
        src = f.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    
    rule_findings = source_counts.get("quick_scan", 0) + source_counts.get("pattern_analyzer", 0) + source_counts.get("component_scan", 0)
    llm_findings = source_counts.get("file_review", 0) + source_counts.get("gapfill", 0) + source_counts.get("chain_analysis", 0)

    source_mode = str(scan_stats.get("source_mode") or "unknown") if scan_stats else "unknown"
    total_files_scanned = 0
    if scan_stats:
        total_files_scanned = scan_stats.get("total_files_scanned", scan_stats.get("total_files", 0))
    
    # 构建统计卡片
    stats_html = f"""
      <div class="grid">
        <div class="metric"><strong>扫描文件数</strong><span>{_escape(str(total_files_scanned))}</span></div>
        <div class="metric"><strong>规则层结果</strong><span>{_escape(str(rule_findings))}</span></div>
        <div class="metric"><strong>LLM 复核结果</strong><span>{_escape(str(llm_findings))}</span></div>
        <div class="metric"><strong>确认结果</strong><span>{_escape(str(total_findings))}</span></div>
        <div class="metric"><strong>来源模式</strong><span>{_escape(str(source_mode))}</span></div>
        <div class="metric"><strong>生成时间</strong><span>{_escape(str(now))}</span></div>
      </div>"""

    # 收集审计技能标签
    skill_tags_set: set = set()
    for f in findings:
        vt = f.get("vuln_type", "") or ""
        if "INJECTION" in vt or "COMMAND" in vt or "SQL" in vt:
            skill_tags_set.add("查询与注入")
        if "PATH_TRAVERSAL" in vt or "FILE" in vt or "UPLOAD" in vt:
            skill_tags_set.add("上传与存储")
        if "AUTH" in vt or "IDOR" in vt or "ACCESS" in vt:
            skill_tags_set.add("访问控制")
        if "XSS" in vt:
            skill_tags_set.add("XSS防护")
        if "SSRF" in vt or "XXE" in vt:
            skill_tags_set.add("SSRF/XXE")
        if "CRYPTO" in vt or "HASH" in vt or "PASSWORD" in vt or "CREDENTIALS" in vt:
            skill_tags_set.add("加密审计")
        if "DESERIALIZATION" in vt or "SERIALIZATION" in vt:
            skill_tags_set.add("反序列化")
        if "COMPONENT" in vt:
            skill_tags_set.add("供应链安全")
        if "CONFIG" in vt or "CORS" in vt:
            skill_tags_set.add("配置审计")
    skill_tags_set.add("GB/T 国标代码安全审计")
    skill_tags = "".join(f'<span class="tag">{_escape(t)}</span>' for t in sorted(skill_tags_set))

    # 语言统计表
    lang_html = ""
    if language_stats:
        langs = language_stats.get("languages", {})
        total = language_stats.get("total", {})
        if langs:
            rows = ""
            for lang, s in sorted(langs.items(), key=lambda x: -x[1].get("code", 0)):
                if s.get("code", 0) > 0:
                    rows += f"<tr><td>{_escape(lang)}</td><td style='text-align:right'>{s.get('files', 0)}</td><td style='text-align:right'>{s.get('code', 0):,}</td></tr>\n"
            if total:
                rows += f"<tr style='font-weight:600;border-top:2px solid #93c5fd'><td>合计</td><td style='text-align:right'>{total.get('files', 0)}</td><td style='text-align:right'>{total.get('code', 0):,}</td></tr>"
            lang_html = f"""
      <div class="sub-card">
        <h4 style="margin:0 0 10px">项目语言分布</h4>
        <table style="width:100%;font-size:13px;border-collapse:collapse">
          <thead><tr style="text-align:left;border-bottom:2px solid #93c5fd"><th style="padding:4px 8px">语言</th><th style="text-align:right;padding:4px 8px">文件数</th><th style="text-align:right;padding:4px 8px">代码行数</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>"""

    return f"""
    <section class="card hero" id="sec-hero">
      <h1>防御性代码审计报告</h1>
      <p class="muted">报告分为两层：规则型快速扫描，以及 LLM 深度复核。全程不包含利用方式或攻击载荷。</p>
      <div class="grid">
        <div class="metric"><strong>任务 ID</strong><br/>{_escape(task_id)}</div>
        <div class="metric"><strong>项目名称</strong><br/>{_escape(project_name)}</div>
        <div class="metric"><strong>任务阶段</strong><br/>completed</div>
      </div>
      {stats_html}
      {lang_html}
      <div class="callout">
        <strong>执行摘要</strong>
        <p>本次审计共发现 {total_findings} 个潜在安全漏洞（Critical: {severity_counts['C']}，High: {severity_counts['H']}，Medium: {severity_counts['M']}，Low: {severity_counts['L']}）。规则引擎基于 sink 模式匹配快速扫描代码仓库，识别出命令注入、SQL注入、路径遍历、XSS、SSRF 等攻击面。如果某个文件没有发现报告，不代表绝对安全，只表示当前规则集下未匹配到高置信度问题。</p>
        <div class="counts">
          <span style="color:#991b1b">Critical: {severity_counts['C']}</span> &nbsp;
          <span style="color:#92400e">High: {severity_counts['H']}</span> &nbsp;
          <span style="color:#1e40af">Medium: {severity_counts['M']}</span> &nbsp;
          <span style="color:#3b82f6">Low: {severity_counts['L']}</span>
        </div>
      </div>
      {f'<div style="margin-top:16px">{skill_tags}</div>' if skill_tags else ''}
    </section>"""


def _build_score_section(
    audit_score: Optional[Dict[str, Any]],
    severity_counts: Dict[str, int],
) -> str:
    """构建评分卡片区域。"""
    if not audit_score:
        return ""

    score = audit_score.get("score", 0)
    grade = audit_score.get("grade", "D")
    grade_desc = audit_score.get("grade_desc", "")
    gate = audit_score.get("gate", "fail")
    gate_reason = audit_score.get("gate_reason", "")
    ring_class = _score_ring_class(score)
    gate_class = "pass" if gate == "pass" else "fail"
    gate_label = "通过" if gate == "pass" else "未通过"

    return f"""
    <section class="card" id="sec-score">
      <h2>审计评分</h2>
      <div class="score-card">
        <div class="score-ring {ring_class}">{score}</div>
        <div class="score-detail">
          <div class="primary">安全评分: {score}/100 ({grade} — {grade_desc})</div>
          <div style="margin-top:8px">
            <span class="badge critical">Critical: {severity_counts['C']}</span>
            <span class="badge high">High: {severity_counts['H']}</span>
            <span class="badge medium">Medium: {severity_counts['M']}</span>
            <span class="badge low">Low: {severity_counts['L']}</span>
          </div>
          <div class="secondary" style="margin-top:6px;color:#94a3b8;font-size:12px">{_escape(gate_reason)}</div>
        </div>
        <span class="score-gate {gate_class}">{gate_label}</span>
      </div>
    </section>"""


def _build_findings_section(
    title: str,
    findings: List[Dict[str, Any]],
    source_badge_class: str,
    empty_message: str,
) -> str:
    """构建漏洞发现列表区域。"""
    sec_id = "sec-quick-scan" if "快速" in title else "sec-llm-audit"
    if not findings:
        return f"""
    <section class="card" id="{sec_id}">
      <h2>{_escape(title)}</h2>
      <p class="muted">{_escape(empty_message)}</p>
    </section>"""

    findings_html = ""
    for idx, f in enumerate(findings):
        findings_html += _render_finding(idx + 1, f, source_badge_class)

    return f"""
    <section class="card" id="{sec_id}">
      <h2>{_escape(title)} ({len(findings)} 条)</h2>
      {findings_html}
    </section>"""


def _render_finding(index: int, f: Dict[str, Any], source_badge_class: str) -> str:
    """渲染单个漏洞发现。"""
    severity = f.get("severity", "L")
    badge_class = _severity_badge_class(severity)
    severity_label = _severity_label(severity)
    title = f.get("title", f.get("vul_name", "未知漏洞"))
    vuln_type = f.get("vuln_type", f.get("vulnType", ""))
    location = f.get("location", f.get("file", ""))
    cvss_score = f.get("cvss_score", f.get("cvssScore", 0))
    cvss_raw = f.get("cvss_score_raw", cvss_score)
    owasp = f.get("owasp", "")
    gbt_mapping = f.get("gbt_mapping", f.get("gbtMapping", ""))
    cwe = f.get("cwe", "")
    evidence = f.get("evidence", f.get("reason", ""))
    impact_desc = f.get("impact_description", f.get("impact", ""))
    remediation = f.get("remediation", "")
    safe_validation = f.get("safe_validation", f.get("safeValidation", ""))
    verification_note = f.get("verification_note", "")
    ast_context = f.get("ast_context", {})
    code_snippet = f.get("code_snippet", f.get("codeSnippet", ""))
    confidence = f.get("confidence", 0)
    source = f.get("source", "unknown")
    cve = f.get("cve", "")
    language = f.get("language", "")
    sink = f.get("sink", [])
    evidence_points = f.get("evidence_points", [])
    status = f.get("status", "")
    verification_status = f.get("verification_status", "")

    # 代码片段
    snippet_html = ""
    if code_snippet:
        snippet_html = f'<pre class="code-context">{_escape(str(code_snippet))}</pre>'

    # CVE 标签
    cve_html = f'<span class="badge">{_escape(cve)}</span> ' if cve else ""

    # CWE 标签
    cwe_html = f'<span class="badge">{_escape(cwe)}</span> ' if cwe else ""

    # 置信度
    conf_pct = int(confidence * 100) if isinstance(confidence, (int, float)) else 0

    # 来源标签
    source_label = {"quick_scan": "规则扫描", "component_scan": "组件扫描", "pattern_analyzer": "模式匹配", "gapfill": "覆盖盲区", "file_review": "文件审计", "llm": "LLM复核"}.get(source, source)

    # 确认状态 badge
    confirmed_html = ""
    if status == "confirmed" or verification_status == "confirmed":
        confirmed_html = '<span class="badge called">✓ 已确认</span>'
    elif status == "pending" or verification_status == "pending":
        confirmed_html = '<span class="badge pending">待确认</span>'
    elif status == "false_positive" or verification_status == "false_positive":
        confirmed_html = '<span class="badge">✗ 误报</span>'

    # Sink + 证据点摘要
    sink_html = ""
    if sink or evidence_points:
        parts = []
        if sink:
            parts.append(f'<strong>危险Sink:</strong> {_escape(", ".join(sink) if isinstance(sink, list) else str(sink))}')
        if evidence_points:
            parts.append(f'<strong>证据点:</strong> {_escape(", ".join(evidence_points) if isinstance(evidence_points, list) else str(evidence_points))}')
        sink_html = f'<p>{" &nbsp;|&nbsp; ".join(parts)}</p>'

    # AST 深度分析
    ast_html = ""
    if isinstance(ast_context, dict) and ast_context.get("sink"):
        ac = ast_context
        # AST 代码上下文（来自 ast_context 或 code_snippet）
        ast_code = ac.get("code_context") or ac.get("codeSnippet") or ""
        code_html = f'<pre class="code-context">{_escape(str(ast_code))}</pre>' if ast_code else ""
        ast_html = f"""
      <div class="ast-context">
        <p><strong>--- AST 深度分析 ---</strong></p>
        <p><strong>危险sink：</strong>{_escape(str(ac.get('sink', 'n/a')))} ({_escape(str(ac.get('sink_severity', ac.get('sinkSeverity', 'n/a'))))})</p>
        <p><strong>风险描述：</strong>{_escape(str(ac.get('sink_desc', 'n/a')))}</p>
        <p><strong>用户输入检测：</strong>{'✓ 有' if ac.get('has_user_input') else '✗ 无'}</p>
        <p><strong>输入验证：</strong>{'✓ 有' if ac.get('has_validation') else '✗ 无'}</p>
        <p><strong>编码处理：</strong>{'✓ 有' if ac.get('has_encoding') else '✗ 无'}</p>
        {f'<p><strong>代码上下文：</strong></p>{code_html}' if code_html else ''}
        {f'<p><strong>深度建议：</strong>{_escape(str(ac.get("recommendation", "")))}</p>' if ac.get('recommendation') else ''}
      </div>"""

    return f"""
      <div class="finding">
        <div class="finding-head">
          <h4>{index}. {_escape(str(title))}</h4>
          <div>
            <span class="badge {badge_class}">{severity_label}</span>
            <span class="badge {source_badge_class}">{_escape(source_label)}</span>
            {cve_html}
            {cwe_html}
            {confirmed_html}
          </div>
        </div>
        <div class="finding-meta">
          <strong>位置:</strong> {_escape(str(location))} &nbsp;
          <strong>CVSS:</strong> {_escape(str(cvss_score))} &nbsp;
          {f'<strong>编程语言:</strong> {_escape(str(language))} &nbsp;' if language else ''}
          <strong>置信度:</strong> {conf_pct}% &nbsp;
          {f'<strong>OWASP:</strong> {_escape(str(owasp))} &nbsp;' if owasp else ''}
          {f'<strong>国标:</strong> {_escape(str(gbt_mapping))} &nbsp;' if gbt_mapping else ''}
        </div>
        {f'<p><strong>漏洞类型:</strong> {_escape(str(vuln_type))}</p>' if vuln_type else ''}
        {f'<p class="muted">验证说明：{_escape(str(verification_note))}</p>' if verification_note else ''}
        {f'<p><strong>证据:</strong> {_escape(str(evidence))}</p>' if evidence else ''}
        {f'<p><strong>影响:</strong> {_escape(str(impact_desc))}</p>' if impact_desc else ''}
        {f'<p><strong>修复建议:</strong> {_escape(str(remediation))}</p>' if remediation else ''}
        {f'<p><strong>安全验证建议:</strong> {_escape(str(safe_validation))}</p>' if safe_validation else ''}
        {sink_html}
        {snippet_html}
        {ast_html}
      </div>"""


def _build_coverage_section(coverage_report: Optional[Dict[str, Any]]) -> str:
    """构建覆盖率区域。"""
    if not coverage_report:
        return ""

    total = coverage_report.get("total_files", 0)
    reviewed = coverage_report.get("reviewed_files", 0)
    rate = coverage_report.get("coverage_rate", 0)
    unreviewed = coverage_report.get("unreviewed_code_files", 0)
    attack_classes = coverage_report.get("reviewed_attack_classes", [])
    gaps = coverage_report.get("subsystem_gaps", {})
    # total 包含非代码文件，单独计算
    non_code = max(0, total - reviewed - unreviewed)

    # 覆盖率进度条
    fill_class = "high" if rate >= 80 else ("medium" if rate >= 50 else "low")

    # 攻击类型标签
    attack_tags = " ".join(
        f'<span class="badge">{_escape(cls)}</span>' for cls in attack_classes[:10]
    )

    # 子系统盲区表格
    gap_rows = ""
    for subsys, count in list(gaps.items())[:10]:
        gap_rows += f"<tr><td>{_escape(subsys)}</td><td>{count}</td></tr>"

    gap_table = ""
    if gap_rows:
        gap_table = f"""
      <table>
        <tr><th>子系统</th><th>未审查文件数</th></tr>
        {gap_rows}
      </table>"""

    return f"""
    <section class="card" id="sec-coverage">
      <h2>审计覆盖率</h2>
      <div class="score-card">
        <div class="score-ring {fill_class}">{rate:.0f}%</div>
        <div class="score-detail">
          <strong>覆盖率: {rate:.1f}%</strong>
          <div class="counts">
            <span>总文件: {total}</span>
            <span>已审查: {reviewed}</span>
            <span>未审查代码文件: {unreviewed}</span>
            {f'<span>非代码文件: {non_code}</span>' if non_code > 0 else ''}
          </div>
        </div>
      </div>
      <div class="coverage-bar">
        <div class="coverage-fill {fill_class}" style="width:{min(rate, 100)}%"></div>
      </div>
      {f'<div style="margin-top:12px"><strong>已检查攻击类型:</strong> {attack_tags}</div>' if attack_tags else ''}
      {f'<div class="sub-card"><h4>未覆盖子系统</h4>{gap_table}</div>' if gap_table else ''}
    </section>"""


def _build_exploit_chain_section(chain_report: Optional[Dict[str, Any]]) -> str:
    """构建利用链分析区域。"""
    if not chain_report or not chain_report.get("chains"):
        return ""

    chains = chain_report["chains"]
    summary = chain_report.get("summary", {})

    chains_html = ""
    for i, chain in enumerate(chains):
        entries_html = ""
        for entry in chain.get("entries", []):
            sev_class = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium"}.get(
                str(entry.get("severity", "")).lower(), "sev-low"
            )
            entries_html += (
                f'<div class="finding {sev_class}" style="padding:6px 10px;margin:4px 0;border-radius:8px">'
                f'<strong>{_escape(entry.get("type", ""))}</strong> '
                f'<span style="color:#6b7280;font-size:12px">{_escape(entry.get("location", ""))}</span> '
                f'<span class="badge" style="font-size:11px">{_escape(str(entry.get("severity", "")))}</span>'
                f'</div>'
            )

        connections = chain.get("connections", [])
        conn_html = ""
        if connections:
            for conn in connections:
                conn_html += (
                    f'<span class="badge" style="background:#e0e7ff;color:#3730a3;font-size:11px;margin:2px">'
                    f'{_escape(conn.get("type", ""))}</span> '
                )

        risk_score = chain.get("risk_score", 0)
        risk_class = "sev-critical" if risk_score >= 80 else "sev-high" if risk_score >= 60 else "sev-medium"

        chains_html += (
            f'<div class="sub-card" style="margin-top:12px">'
            f'<h4>利用链 #{i + 1} '
            f'<span class="badge {risk_class}" style="font-size:11px">风险评分: {risk_score}</span></h4>'
            f'<div style="margin:8px 0">{entries_html}</div>'
            f'<div style="margin-top:6px">连接: {conn_html}</div>'
            f'<p style="font-size:13px;color:#4b5563;margin-top:8px">{_escape(chain.get("description", ""))}</p>'
            f'</div>'
        )

    total_chains = chain_report.get("total_chains", 0)
    max_risk = summary.get("max_risk_score", 0)

    return f"""
    <section class="card" id="sec-chains">
      <h2>利用链分析 <span class="badge" style="background:#fef3c7;color:#92400e">{total_chains} 条链</span></h2>
      <div style="display:flex;gap:20px;margin:12px 0;flex-wrap:wrap">
        <div class="metric"><strong>利用链数</strong><br/>{total_chains}</div>
        <div class="metric"><strong>最高风险评分</strong><br/>{max_risk}</div>
      </div>
      {chains_html}
    </section>"""


def write_report_to_file(
    report_dir: str,
    task_id: str,
    project_name: str,
    findings: List[Dict[str, Any]],
    audit_score: Optional[Dict[str, Any]] = None,
    coverage_report: Optional[Dict[str, Any]] = None,
    scan_stats: Optional[Dict[str, Any]] = None,
    quick_scan_findings: Optional[List[Dict[str, Any]]] = None,
    llm_findings: Optional[List[Dict[str, Any]]] = None,
    exploit_chain_report: Optional[Dict[str, Any]] = None,
    language_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """生成 HTML 报告并写入文件。

    Returns:
        包含 file_path 和 download_path 的字典
    """
    os.makedirs(report_dir, exist_ok=True)
    file_name = f"audit-report-{task_id}.html"
    file_path = os.path.join(report_dir, file_name)

    html_content = generate_html_report(
        task_id=task_id,
        project_name=project_name,
        findings=findings,
        audit_score=audit_score,
        coverage_report=coverage_report,
        scan_stats=scan_stats,
        quick_scan_findings=quick_scan_findings,
        llm_findings=llm_findings,
        exploit_chain_report=exploit_chain_report,
        language_stats=language_stats,
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return {
        "file_name": file_name,
        "file_path": file_path,
        "download_path": f"/reports/{file_name}",
    }
