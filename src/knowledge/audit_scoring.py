# -*- coding: utf-8 -*-
"""审计评分引擎 —— 整合自 gbt-codeagent/core/auditScoreEngine.js。

基于漏洞严重程度和数量计算安全评分（0-100），
生成门禁判定（pass/fail）和评级（A/B/C/D）。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# 严重程度权重
SEVERITY_WEIGHTS: Dict[str, float] = {
    "C": 10.0,   # Critical
    "H": 5.0,    # High
    "M": 2.0,    # Medium
    "L": 0.5,    # Low
}

# 门禁阈值
GATE_THRESHOLDS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "pass_score": 80,
        "max_critical": 0,
        "max_high": 2,
        "desc": "严格模式：不允许 Critical，High 不超过 2 个",
    },
    "normal": {
        "pass_score": 60,
        "max_critical": 1,
        "max_high": 5,
        "desc": "标准模式：Critical 不超过 1，High 不超过 5",
    },
    "relaxed": {
        "pass_score": 40,
        "max_critical": 3,
        "max_high": 10,
        "desc": "宽松模式：Critical 不超过 3，High 不超过 10",
    },
}

# 评级区间
GRADE_RANGES: List[Dict[str, Any]] = [
    {"grade": "A", "min_score": 90, "max_score": 100, "desc": "优秀，安全状况良好"},
    {"grade": "B", "min_score": 70, "max_score": 89, "desc": "良好，存在少量需关注的问题"},
    {"grade": "C", "min_score": 50, "max_score": 69, "desc": "一般，存在较多安全问题需修复"},
    {"grade": "D", "min_score": 0, "max_score": 49, "desc": "较差，存在严重安全问题"},
]


def calculate_audit_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算审计安全评分。

    Args:
        findings: 漏洞发现列表，每项需包含 severity 或 level 字段

    Returns:
        评分结果字典，包含 score, grade, gate, counts 等
    """
    counts = {"C": 0, "H": 0, "M": 0, "L": 0}
    for f in findings:
        level = _extract_severity(f)
        if level in counts:
            counts[level] += 1

    # 计算扣分
    total_deduction = 0.0
    for level, count in counts.items():
        weight = SEVERITY_WEIGHTS.get(level, 0)
        total_deduction += weight * count

    # 评分 = 100 × (1 - deduction / (deduction + k))
    # 使用双曲线衰减：扣分越大衰减越慢，永远不会降到 0，对大项目有区分度
    if total_deduction <= 0:
        score = 100
    else:
        k = 50  # 半衰常数：扣分=k 时评分=50
        score = max(0, min(100, round(100 * (1 - total_deduction / (total_deduction + k)), 1)))

    # 评级
    grade = "D"
    grade_desc = ""
    for g in GRADE_RANGES:
        if g["min_score"] <= score <= g["max_score"]:
            grade = g["grade"]
            grade_desc = g["desc"]
            break

    # 门禁判定（默认 normal 模式）
    gate = _evaluate_gate(score, counts, "normal")

    return {
        "score": score,
        "grade": grade,
        "grade_desc": grade_desc,
        "gate": gate["result"],
        "gate_reason": gate["reason"],
        "gate_mode": "normal",
        "counts": counts,
        "total_findings": sum(counts.values()),
        "total_deduction": round(total_deduction, 2),
    }


def _extract_severity(finding: Dict[str, Any]) -> str:
    """从 finding 中提取严重等级。"""
    for key in ("severity", "level", "severity_level"):
        val = finding.get(key, "")
        if isinstance(val, str):
            val_upper = val.strip().upper()
            if val_upper in ("CRITICAL", "C"):
                return "C"
            if val_upper in ("HIGH", "H"):
                return "H"
            if val_upper in ("MEDIUM", "M"):
                return "M"
            if val_upper in ("LOW", "L"):
                return "L"
        if isinstance(val, dict):
            prefix = val.get("prefix", "")
            if prefix in ("C", "H", "M", "L"):
                return prefix
    # 从 vulnId 推断
    vuln_id = finding.get("vulnId", finding.get("vuln_id", ""))
    if isinstance(vuln_id, str) and len(vuln_id) >= 1:
        prefix = vuln_id[0].upper()
        if prefix in ("C", "H", "M", "L"):
            return prefix
    return "L"


def _evaluate_gate(
    score: float,
    counts: Dict[str, int],
    mode: str = "normal",
) -> Dict[str, str]:
    """评估门禁判定。"""
    threshold = GATE_THRESHOLDS.get(mode, GATE_THRESHOLDS["normal"])
    reasons = []

    if counts["C"] > threshold["max_critical"]:
        reasons.append(
            f"Critical 漏洞 {counts['C']} 个，超过上限 {threshold['max_critical']}"
        )
    if counts["H"] > threshold["max_high"]:
        reasons.append(
            f"High 漏洞 {counts['H']} 个，超过上限 {threshold['max_high']}"
        )
    if score < threshold["pass_score"]:
        reasons.append(
            f"评分 {score} 低于通过线 {threshold['pass_score']}"
        )

    if reasons:
        return {"result": "fail", "reason": "; ".join(reasons)}
    return {"result": "pass", "reason": "所有门禁条件满足"}


def generate_audit_report(findings: List[Dict[str, Any]]) -> str:
    """生成审计评分报告的 Markdown 文本。"""
    result = calculate_audit_score(findings)
    counts = result["counts"]
    total = result["total_findings"]

    lines = [
        "## 审计评分报告",
        "",
        f"| 指标 | 值 |",
        f"|------|-----|",
        f"| 安全评分 | {result['score']}/100 |",
        f"| 安全评级 | {result['grade']} — {result['grade_desc']} |",
        f"| 门禁判定 | {'通过' if result['gate'] == 'pass' else '未通过'} |",
        f"| 门禁原因 | {result['gate_reason']} |",
        "",
        "### 漏洞统计",
        "",
        "| 严重等级 | 数量 |",
        "|----------|------|",
        f"| Critical | {counts['C']} |",
        f"| High | {counts['H']} |",
        f"| Medium | {counts['M']} |",
        f"| Low | {counts['L']} |",
        f"| **合计** | **{total}** |",
    ]
    return "\n".join(lines)
