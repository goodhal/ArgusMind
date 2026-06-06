# -*- coding: utf-8 -*-
"""漏洞评分体系 —— 整合自 gbt-codeagent。

评分公式: Score = R × 0.40 + I × 0.35 + C × 0.25
CVSS 3.1 映射: CVSS = Score / 3.0 × 10.0
漏洞编号: {C/H/M/L}-{TYPE}-{NNN}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# === 三维评分定义 ===

REACHABILITY_LEVELS: Dict[int, Dict[str, str]] = {
    3: {"label": "高", "desc": "无需认证，HTTP直接可达"},
    2: {"label": "中", "desc": "需要普通用户认证"},
    1: {"label": "低", "desc": "需要管理员权限或内网访问"},
    0: {"label": "无", "desc": "代码不可达/死代码"},
}

IMPACT_LEVELS: Dict[int, Dict[str, str]] = {
    3: {"label": "高", "desc": "RCE/任意文件写入/完全数据泄露/系统沦陷"},
    2: {"label": "中", "desc": "敏感数据泄露/越权操作/部分文件读取"},
    1: {"label": "低", "desc": "有限信息泄露/低影响配置读取"},
    0: {"label": "无", "desc": "无实际安全影响"},
}

COMPLEXITY_LEVELS: Dict[int, Dict[str, str]] = {
    3: {"label": "低复杂度", "desc": "单次请求即可利用，无前置条件"},
    2: {"label": "中复杂度", "desc": "需要构造特殊payload或多步操作"},
    1: {"label": "高复杂度", "desc": "需要特定环境/竞态条件/链式利用"},
    0: {"label": "不可利用", "desc": "有效防护，无法绕过"},
}

# === 严重等级映射 ===

SEVERITY_LEVELS: List[Dict[str, Any]] = [
    {"prefix": "C", "label": "Critical", "min_score": 2.70, "max_score": 3.00, "cvss_min": 9.0, "cvss_max": 10.0, "desc": "可直接导致系统沦陷"},
    {"prefix": "H", "label": "High", "min_score": 2.10, "max_score": 2.69, "cvss_min": 7.0, "cvss_max": 8.9, "desc": "可造成重大损害"},
    {"prefix": "M", "label": "Medium", "min_score": 1.20, "max_score": 2.09, "cvss_min": 4.0, "cvss_max": 6.9, "desc": "可造成一定损害"},
    {"prefix": "L", "label": "Low", "min_score": 0.10, "max_score": 1.19, "cvss_min": 0.1, "cvss_max": 3.9, "desc": "安全加固建议"},
]

# === 漏洞类型代码 ===

VULN_TYPE_CODES: Dict[str, str] = {
    "COMMAND_INJECTION": "CMD",
    "SQL_INJECTION": "SQL",
    "SQL_INJECTION_MYBATIS": "SQL",
    "SQL_INJECTION_ORDERBY": "SQL",
    "SQL_INJECTION_GROUPBY": "SQL",
    "SQL_INJECTION_HQL": "SQL",
    "NOSQL_INJECTION": "NOSQL",
    "CODE_INJECTION": "CODE",
    "SPEL_INJECTION": "SPEL",
    "SSTI": "SSTI",
    "EXPRESSION_INJECTION": "EXPR",
    "PATH_TRAVERSAL": "PATH",
    "FILE_UPLOAD": "UPLOAD",
    "FILE_READ": "FILE",
    "FILE_WRITE": "WRITE",
    "ARCHIVE_EXTRACT": "ARCHIVE",
    "HARD_CODE_PASSWORD": "PASS",
    "PLAINTEXT_PASSWORD": "PASS",
    "WEAK_CRYPTO": "CRYPTO",
    "WEAK_HASH": "HASH",
    "PREDICTABLE_RANDOM": "RAND",
    "DESERIALIZATION": "DESER",
    "SSRF": "SSRF",
    "XXE": "XXE",
    "AUTH_BYPASS": "AUTH",
    "AUTH_BYPASS_URI": "AUTH",
    "AUTH_BYPASS_SUFFIX": "AUTH",
    "AUTH_BYPASS_SPRING": "AUTH",
    "AUTH_CSRF_DISABLED": "CSRF",
    "AUTH_INFO_EXPOSURE": "AUTH",
    "IDOR": "AUTH",
    "INFO_LEAK": "INFO",
    "LOG_INJECTION": "LOG",
    "SESSION_FIXATION": "SESS",
    "COOKIE_MANIPULATION": "SESS",
    "XSS": "XSS",
    "XPATH_INJECTION": "XPATH",
    "LDAP_INJECTION": "LDAP",
    "BUFFER_OVERFLOW": "BUF",
    "FORMAT_STRING": "FMT",
    "INTEGER_OVERFLOW": "INT",
    "PROCESS_CONTROL": "PROC",
    "OPEN_REDIRECT": "REDIR",
    "CORS_MISCONFIGURATION": "CFG",
    "CSRF": "CSRF",
    "CRLF_INJECTION": "CRLF",
    "RACE_CONDITION": "RACE",
    "UNCONTROLLED_MEMORY": "MEM",
    "IMPROPER_EXCEPTION_HANDLING": "CFG",
    "INFINITE_LOOP": "LOOP",
    "WEAK_PASSWORD_POLICY": "POL",
    "PLAINTEXT_TRANSMISSION": "TRANS",
    "COMPONENT_VULNERABILITY": "CMP",
    "STRUTS_WILDCARD": "CONFIG",
    "AUTH_SERVLETPATH_SAFE": "INFO",
    "BUSINESS_LOGIC": "LOGIC",
    "FILESYSTEM": "FS",
    "UNKNOWN": "VULN",
}

# === 可利用性标注对评级的影响 ===

EXPLOITABILITY_IMPACT: Dict[str, Dict[str, Any]] = {
    "已确认可利用": {"R": 1.0, "C": 1.0, "desc": "已验证可利用"},
    "待验证": {"R": 1.0, "C": 0.67, "desc": "未验证，降低复杂度分值"},
    "不可利用": {"R": 0, "C": 0, "desc": "不可利用"},
    "环境依赖": {"R": 0.67, "C": 0.67, "desc": "降低可达性和复杂度"},
}

# === 典型漏洞评分参考 ===

TYPICAL_SCORES: Dict[str, Dict[str, Any]] = {
    "SQL_INJECTION:3:3:3": {"score": 3.00, "cvss": 10.0, "level": "C", "example": "SQL注入+无认证+String拼接"},
    "SQL_INJECTION:3:3:2": {"score": 2.75, "cvss": 9.2, "level": "C", "example": "SQL注入+无认证+预编译绕过"},
    "SQL_INJECTION:2:3:2": {"score": 2.35, "cvss": 7.8, "level": "H", "example": "SQL注入+需认证+条件利用"},
    "SQL_INJECTION:1:2:1": {"score": 1.35, "cvss": 4.5, "level": "M", "example": "ORDER BY注入+环境依赖(Oracle-only)"},
    "XXE:3:3:3": {"score": 3.00, "cvss": 10.0, "level": "C", "example": "XXE有回显+无认证"},
    "XXE:2:3:3": {"score": 2.60, "cvss": 8.7, "level": "H", "example": "XXE有回显+需认证"},
    "XXE:2:2:2": {"score": 2.00, "cvss": 6.7, "level": "M", "example": "XXE无回显+需认证"},
    "FILE_UPLOAD:3:3:2": {"score": 2.75, "cvss": 9.2, "level": "C", "example": "任意文件上传+无类型校验+Web目录"},
    "FILE_UPLOAD:3:2:2": {"score": 2.40, "cvss": 8.0, "level": "H", "example": "文件上传+路径穿越+类型绕过"},
    "FILE_READ:3:2:2": {"score": 2.40, "cvss": 8.0, "level": "H", "example": "任意文件读取+无路径校验"},
    "FILE_READ:2:2:2": {"score": 2.00, "cvss": 6.7, "level": "M", "example": "文件读取+基础路径限制+需认证"},
    "AUTH_BYPASS:3:2:2": {"score": 2.40, "cvss": 8.0, "level": "H", "example": "鉴权绕过+分号绕过+管理接口"},
    "AUTH_BYPASS:3:3:2": {"score": 2.75, "cvss": 9.2, "level": "C", "example": "完全鉴权绕过+Manager接口"},
    "COMMAND_INJECTION:3:3:3": {"score": 3.00, "cvss": 10.0, "level": "C", "example": "命令注入+无认证+直接利用"},
    "DESERIALIZATION:3:3:2": {"score": 2.75, "cvss": 9.2, "level": "C", "example": "反序列化RCE+Fastjson+无认证"},
    "SSRF:3:2:2": {"score": 2.40, "cvss": 8.0, "level": "H", "example": "SSRF+可访问内网+无认证"},
    "COMPONENT_VULNERABILITY:3:3:1": {"score": 2.50, "cvss": 8.3, "level": "H", "example": "Log4Shell+无认证+可RCE"},
}


def score_vulnerability(
    reachability: int = 2,
    impact: int = 2,
    complexity: int = 2,
    exploitability: Optional[str] = None,
) -> Dict[str, Any]:
    """核心评分函数。

    Args:
        reachability: 可达性 (0-3)
        impact: 影响范围 (0-3)
        complexity: 利用复杂度 (0-3)
        exploitability: 可利用性标注

    Returns:
        评分结果字典
    """
    R = int(reachability) or 2
    I = int(impact) or 2
    C = int(complexity) or 2

    adjusted_R = float(R)
    adjusted_C = float(C)

    if exploitability and exploitability in EXPLOITABILITY_IMPACT:
        factor = EXPLOITABILITY_IMPACT[exploitability]
        adjusted_R = R * factor["R"]
        adjusted_C = C * factor["C"]

    raw_score = adjusted_R * 0.40 + I * 0.35 + adjusted_C * 0.25
    score = round(raw_score, 2)
    cvss = round(score / 3.0 * 10.0, 1)

    level_info = SEVERITY_LEVELS[-1]  # Low default
    for lvl in SEVERITY_LEVELS:
        if lvl["min_score"] <= score <= lvl["max_score"]:
            level_info = lvl
            break

    return {
        "score": score,
        "cvss": cvss,
        "level": level_info["prefix"],
        "level_label": level_info["label"],
        "level_desc": level_info["desc"],
        "breakdown": f"{adjusted_R:.1f}/{I}/{adjusted_C:.1f}",
        "raw_R": R,
        "raw_I": I,
        "raw_C": C,
        "adjusted_R": adjusted_R,
        "adjusted_I": I,
        "adjusted_C": adjusted_C,
        "reachability_desc": REACHABILITY_LEVELS.get(R, {}).get("desc", "未知"),
        "impact_desc": IMPACT_LEVELS.get(I, {}).get("desc", "未知"),
        "complexity_desc": COMPLEXITY_LEVELS.get(C, {}).get("desc", "未知"),
        "exploitability": exploitability,
    }


def score_from_reference(
    vuln_type: str, reachability: int, impact: int, complexity: int
) -> Dict[str, Any]:
    """从典型评分表快速评分。"""
    key = f"{vuln_type}:{reachability}:{impact}:{complexity}"
    if key in TYPICAL_SCORES:
        result = dict(TYPICAL_SCORES[key])
        result["breakdown"] = f"{reachability}/{impact}/{complexity}"
        result["reachability_desc"] = REACHABILITY_LEVELS.get(reachability, {}).get("desc", "未知")
        result["impact_desc"] = IMPACT_LEVELS.get(impact, {}).get("desc", "未知")
        result["complexity_desc"] = COMPLEXITY_LEVELS.get(complexity, {}).get("desc", "未知")
        return result
    return score_vulnerability(reachability, impact, complexity)


def get_vuln_type_defaults(vuln_type: str) -> Dict[str, int]:
    """从漏洞类型的通用描述生成可达性/影响/复杂度默认值。"""
    defaults: Dict[str, Dict[str, int]] = {
        "COMMAND_INJECTION": {"R": 3, "I": 3, "C": 3},
        "SQL_INJECTION": {"R": 3, "I": 3, "C": 3},
        "CODE_INJECTION": {"R": 3, "I": 3, "C": 3},
        "SPEL_INJECTION": {"R": 3, "I": 3, "C": 3},
        "SSTI": {"R": 3, "I": 3, "C": 3},
        "EXPRESSION_INJECTION": {"R": 3, "I": 3, "C": 3},
        "DESERIALIZATION": {"R": 3, "I": 3, "C": 2},
        "SSRF": {"R": 3, "I": 2, "C": 2},
        "XXE": {"R": 3, "I": 3, "C": 2},
        "PATH_TRAVERSAL": {"R": 3, "I": 2, "C": 2},
        "FILE_UPLOAD": {"R": 3, "I": 3, "C": 2},
        "FILE_READ": {"R": 3, "I": 2, "C": 2},
        "FILE_WRITE": {"R": 3, "I": 3, "C": 2},
        "ARCHIVE_EXTRACT": {"R": 3, "I": 2, "C": 2},
        "NOSQL_INJECTION": {"R": 3, "I": 3, "C": 2},
        "LDAP_INJECTION": {"R": 3, "I": 2, "C": 2},
        "AUTH_BYPASS": {"R": 3, "I": 3, "C": 2},
        "AUTH_BYPASS_URI": {"R": 3, "I": 3, "C": 2},
        "AUTH_BYPASS_SUFFIX": {"R": 3, "I": 3, "C": 2},
        "HARD_CODE_PASSWORD": {"R": 3, "I": 2, "C": 3},
        "XSS": {"R": 3, "I": 2, "C": 2},
        "IDOR": {"R": 3, "I": 2, "C": 2},
        "WEAK_CRYPTO": {"R": 2, "I": 2, "C": 1},
        "WEAK_HASH": {"R": 2, "I": 2, "C": 1},
        "PREDICTABLE_RANDOM": {"R": 2, "I": 2, "C": 2},
        "COMPONENT_VULNERABILITY": {"R": 3, "I": 3, "C": 1},
        "OPEN_REDIRECT": {"R": 2, "I": 1, "C": 3},
        "CRLF_INJECTION": {"R": 3, "I": 1, "C": 3},
        "BUSINESS_LOGIC": {"R": 3, "I": 2, "C": 1},
    }
    return defaults.get(vuln_type, {"R": 2, "I": 2, "C": 2})


class VulnIdGenerator:
    """统一漏洞编号生成器。

    编号格式: {C/H/M/L}-{TYPE}-{NNN}
    """

    def __init__(self) -> None:
        self._counter: Dict[str, Dict[str, int]] = {}

    def generate(self, vuln_type: str, severity: str) -> str:
        severity_map = {
            "严重": "C", "critical": "C",
            "高危": "H", "high": "H",
            "中危": "M", "medium": "M",
            "低危": "L", "low": "L",
        }
        prefix = severity_map.get(severity, "L")
        type_code = VULN_TYPE_CODES.get(vuln_type, "VULN")

        self._counter.setdefault(prefix, {})
        self._counter[prefix].setdefault(type_code, 0)
        self._counter[prefix][type_code] += 1

        return f"{prefix}-{type_code}-{self._counter[prefix][type_code]:03d}"

    def get_counts(self) -> Dict[str, Dict[str, int]]:
        return {k: dict(v) for k, v in self._counter.items()}

    def reset(self) -> None:
        self._counter.clear()

    def count_by_level(self) -> Dict[str, int]:
        return {
            "C": sum(self._counter.get("C", {}).values()),
            "H": sum(self._counter.get("H", {}).values()),
            "M": sum(self._counter.get("M", {}).values()),
            "L": sum(self._counter.get("L", {}).values()),
        }


def generate_vuln_stats_table(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成漏洞统计报告。"""
    counts = {"C": 0, "H": 0, "M": 0, "L": 0}
    for f in findings:
        vuln_id = f.get("vulnId", "")
        if vuln_id.startswith("C-"):
            counts["C"] += 1
        elif vuln_id.startswith("H-"):
            counts["H"] += 1
        elif vuln_id.startswith("M-"):
            counts["M"] += 1
        elif vuln_id.startswith("L-"):
            counts["L"] += 1

    total = sum(counts.values())
    markdown = "\n".join([
        "## 漏洞统计",
        "",
        "| 严重等级 | CVSS | 数量 | 说明 |",
        "|----------|------|------|------|",
        f"| C (Critical) | 9.0-10.0 | {counts['C']} | 可直接导致系统沦陷 |",
        f"| H (High) | 7.0-8.9 | {counts['H']} | 可造成重大损害 |",
        f"| M (Medium) | 4.0-6.9 | {counts['M']} | 可造成一定损害 |",
        f"| L (Low) | 0.1-3.9 | {counts['L']} | 安全加固建议 |",
        "",
        "## 审计结论",
        "",
        "| 统计项 | 数量 |",
        "|--------|------|",
        f"| 总检测点 | {total} |",
        f"| Critical | {counts['C']} |",
        f"| High | {counts['H']} |",
        f"| Medium | {counts['M']} |",
        f"| Low | {counts['L']} |",
    ])

    return {"counts": counts, "total": total, "markdown": markdown}
