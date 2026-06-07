# -*- coding: utf-8 -*-
"""快速扫描过滤器 —— 合并 CandidateFilter + ContextAwareFilter。

对快速扫描结果一次性完成：
1. 安全线索评分 + 风险候选预筛选（原 CandidateFilter）
2. 守卫模式检测 + 置信度调整 + 测试文件降权（原 ContextAwareFilter）
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.sanitizer_patterns import get_sanitizer_patterns
from src.knowledge.framework_adapters import check_framework_safety


# ==================== 候选评分配置 ====================

MUST_PASS_VULN_TYPES: Set[str] = {
    # 注入类（必过）
    "COMMAND_INJECTION", "CODE_INJECTION", "SQL_INJECTION", "NOSQL_INJECTION",
    "JNDI_INJECTION", "SSTI", "PROTOTYPE_POLLUTION", "XPATH_INJECTION",
    # 反序列化 / 缓冲区溢出（必过）
    "DESERIALIZATION", "INSECURE_DESERIALIZATION", "BUFFER_OVERFLOW",
    # 路径遍历 / 文件操作（必过）
    "PATH_TRAVERSAL", "ARBITRARY_FILE_READ", "FILE_INCLUSION",
    "UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD",
    # SSRF / XXE（必过）
    "SSRF", "XXE",
    # 认证 / 访问控制（必过）
    "AUTH_BYPASS", "MISSING_ACCESS_CONTROL", "TRUST_BOUNDARY_VIOLATION",
    # 密钥 / 凭据（必过）
    "CREDENTIAL_EXPOSURE", "HARDCODED_CREDENTIALS", "HARD_CODE_PASSWORD",
    # 输出类（必过）
    "XSS", "OPEN_REDIRECT",
    # 其他高危（必过）
    "CORS_MISCONFIGURATION", "RACE_CONDITION", "FORMAT_STRING",
    "PLAINTEXT_TRANSMISSION", "INTEGER_OVERFLOW",
    "LOG_INJECTION", "WEAK_CRYPTO", "WEAK_HASH", "CSRF",
    "IDOR", "SESSION_FIXATION", "INSECURE_RANDOM",
    "REGEX_DOS", "MASS_ASSIGNMENT", "RATE_LIMITING",
    "JWT_VULNERABILITIES", "FILE_OPERATIONS", "HARDCODED_SECRETS",
}

_SEVERITY_SCORES: Dict[str, int] = {
    "C": 15, "H": 10, "M": 5, "L": 2,
    "critical": 15, "high": 10, "medium": 5, "low": 2,
}

DEFAULT_CANDIDATE_THRESHOLD = 5

# ==================== 守卫模式配置 ====================

GUARD_WINDOW_LINES = 5

GUARD_PATTERNS: Dict[str, List[re.Pattern]] = {
    "COMMAND_INJECTION": [
        re.compile(r'"[^"]*"\s*\+?\s*"[^"]*"'),
        re.compile(r"Array\.(from|of|isArray)"),
    ],
    "SQL_INJECTION": [
        re.compile(r"PreparedStatement|prepareStatement|createQuery\s*\([^)]*\.class"),
        re.compile(r"\?[\s,)]"),
        re.compile(r"setParameter|setString|setInt|setLong"),
        re.compile(r"NamedParameterJdbcTemplate|JdbcTemplate\s*\(\s*dataSource"),
    ],
    "CODE_INJECTION": [
        re.compile(r"\.replace\s*\(.*pattern", re.I),
        re.compile(r"\.sanitize|\.escape|htmlspecialchars|strip_tags"),
        re.compile(r"JSON\.parse\s*\("),
    ],
    "XSS": [
        re.compile(r"\.textContent\s*=|\.innerText\s*="),
        re.compile(r"\.replace\s*\(.*<[^>]*>"),
        re.compile(r"escapeHtml|sanitizeHtml|DOMPurify|xss-filters"),
        re.compile(r"text/plain|Content-Security-Policy"),
    ],
    "PATH_TRAVERSAL": [
        re.compile(r"\.normalize\s*\("),
        re.compile(r"\.resolve\s*\("),
        re.compile(r"path\.join\s*\(", re.I),
        re.compile(r"SecurityManager|AccessController\.checkPermission"),
        re.compile(r"basename\s*\(|path\.basename", re.I),
    ],
    "DESERIALIZATION": [
        re.compile(r"ValidatingObjectInputStream|LookAheadObjectInputStream"),
        re.compile(r"resolveClass\s*\("),
        re.compile(r"setAcceptClasses|setRejectClasses|setAllowedTypes"),
        re.compile(r"ObjectInputFilter|serialFilter|jdk\.serialFilter"),
        re.compile(r"useSafeClasses|safeDeserialization|enableSafeMode"),
    ],
    "SSRF": [
        re.compile(r"ALLOWED_HOSTS|ALLOWED_DOMAINS|whitelist|blocklist"),
        re.compile(r"\.startsWith\s*\(\s*['\"]\/api\/|\.includes\s*\(\s*['\"]\/internal"),
        re.compile(r"isSafeUrl|validateUrl|checkHost|isInternal"),
        re.compile(r"InetAddress\.getByName|isLoopbackAddress|isSiteLocalAddress"),
    ],
    "HARD_CODE_PASSWORD": [
        re.compile(r"process\.env\.|os\.environ|System\.getenv|getenv\s*\("),
        re.compile(r"config\[|config\.get\s*\(|getConfig\s*\(|\.env\."),
        re.compile(r"keyVault|secretManager|vault|credentialsFromFile"),
        re.compile(r"@Value\s*\(\s*\"\$\{"),
    ],
    "XXE": [
        re.compile(r"setFeature\s*\(.*disallow-doctype|setFeature\s*\(.*external-general-entities"),
        re.compile(r"setFeature\s*\(.*external-parameter-entities|setFeature\s*\(.*load-external-dtd"),
        re.compile(r"XMLConstants\.FEATURE_SECURE_PROCESSING"),
        re.compile(r"setExpandEntityReferences\s*\(\s*false"),
    ],
    "CORS_MISCONFIGURATION": [
        re.compile(r"ALLOWED_ORIGINS|allowedOrigins|CORS_ORIGIN_WHITELIST"),
        re.compile(r"originWhitelist|corsWhitelist|corsAllowedOrigins"),
        re.compile(r"@CrossOrigin\s*\(\s*origins\s*=\s*\"[^\"]+\""),
        re.compile(r"corsConfigurationSource\s*\("),
    ],
}

_STRING_LITERAL_PATTERN = re.compile(r'^["\'][^"\'{}]*["\']\s*$')
_METHOD_CALL_PATTERN = re.compile(r'^\s*\w+\s*\(\s*["\'][^"\']*["\']\s*\)\s*$')
_TEST_FILE_PATTERN = re.compile(
    r'[\\/](test|tests|__tests__|spec|mock|fixture|example|sample|demo|stub|placeholder|dummy)[\\/]',
    re.I,
)
_TEST_EXT_PATTERN = re.compile(r'\.(test|spec|mock)\.', re.I)
_VULNERABLE_SAMPLE_PATTERN = re.compile(
    r'(vulnerable|exploit|insecure|unsafe|deliberate|intentional)_?'
    r'(code|sample|app|file|python|java|cpp|csharp|cs|dotnet)',
    re.I,
)


# ==================== QuickScanFilter ====================

class QuickScanFilter:
    """快速扫描过滤器。

    合并了原 CandidateFilter（风险评分+预筛选）和 ContextAwareFilter（守卫检测+置信度调整），
    一次遍历完成所有过滤逻辑。
    """

    def __init__(
        self,
        project_root: str = "",
        candidate_threshold: int = DEFAULT_CANDIDATE_THRESHOLD,
        confidence_threshold: float = 0.3,
    ) -> None:
        self._project_root = project_root
        self._candidate_threshold = candidate_threshold
        self._confidence_threshold = confidence_threshold
        self._file_cache: Dict[str, List[str]] = {}
        self._hint_score_cache: Dict[str, int] = {}  # 文件路径 → 安全线索加分缓存
        self._filtered_items: List[Dict[str, Any]] = []  # 追踪被过滤的发现
        self._stats = {
            "total": 0, "passed": 0, "filtered": 0,
            "must_pass": 0, "guard_mitigated": 0, "test_deprioritized": 0,
        }

    def reset_stats(self) -> None:
        self._stats = {
            "total": 0, "passed": 0, "filtered": 0,
            "must_pass": 0, "guard_mitigated": 0, "test_deprioritized": 0,
        }
        self._hint_score_cache.clear()
        self._filtered_items.clear()

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def get_filtered(self) -> List[Dict[str, Any]]:
        """返回本次过滤中被移除的原始发现列表。"""
        return list(self._filtered_items)

    def filter(
        self,
        findings: List[Dict[str, Any]],
        project_root: str = "",
    ) -> List[Dict[str, Any]]:
        """一次性完成候选评分 + 守卫检测 + 置信度调整 + 过滤。"""
        if project_root:
            self._project_root = project_root

        self.reset_stats()
        result = []

        for finding in findings:
            self._stats["total"] += 1
            processed = self._process_finding(finding)

            if processed is None:
                self._stats["filtered"] += 1
                finding["_filter_reason"] = "process_finding_rejected"
                self._filtered_items.append(finding)
                continue

            # 候选评分检查
            score = processed.get("_filter_score", 0)
            vuln_type = processed.get("vulnType", processed.get("vuln_type", processed.get("category_name", "")))
            if vuln_type in MUST_PASS_VULN_TYPES:
                self._stats["must_pass"] += 1
                self._stats["passed"] += 1
                result.append(processed)
            elif score >= self._candidate_threshold:
                self._stats["passed"] += 1
                result.append(processed)
            else:
                self._stats["filtered"] += 1
                processed["_filter_reason"] = f"low_score:{score}<{self._candidate_threshold}"
                self._filtered_items.append(processed)

        return result

    def _process_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理单个发现：评分 + 守卫检测 + 置信度调整。"""
        if not finding or not isinstance(finding, dict):
            return None

        # 将上游传递的文件行内容预填缓存，避免重复 IO
        _file_lines = finding.get("_file_lines")
        file_path = finding.get("location", finding.get("file", ""))
        if _file_lines and file_path and file_path not in self._file_cache:
            self._file_cache[file_path] = _file_lines

        # --- 候选评分 ---
        score = self._score_candidate(finding)
        finding["_filter_score"] = score

        # --- 守卫检测 + 置信度调整 ---
        file_path = finding.get("location", finding.get("file", ""))
        line_num = finding.get("line", 0)
        vuln_type = finding.get("vulnType", finding.get("type", finding.get("vuln_type", "")))

        # 提取行号
        if not line_num and finding.get("location"):
            parts = str(finding["location"]).split(":")
            if len(parts) >= 2:
                try:
                    line_num = int(parts[1])
                except ValueError:
                    pass

        # 测试文件降权
        if _is_test_or_mock_file(file_path):
            self._stats["test_deprioritized"] += 1
            finding["confidence"] = min(finding.get("confidence", 0.8), 0.15)
            finding["guardContext"] = {"isTestFile": True, "notes": ["test_or_mock_file"]}
            return finding

        # 故意不安全的示例代码不调整
        if _VULNERABLE_SAMPLE_PATTERN.search(file_path):
            return finding

        # 缺少文件路径或行号，不调整
        if not file_path or line_num < 1:
            return finding

        # 读取文件内容
        lines = self._read_file_lines(file_path)
        if not lines:
            return finding

        line_index = line_num - 1
        if line_index >= len(lines):
            return finding

        # 评估守卫上下文
        file_ext = _detect_extension(file_path)
        guard_result = _evaluate_guard_context(lines, line_index, vuln_type, file_ext)

        if guard_result.has_guard_pattern:
            self._stats["guard_mitigated"] += 1

        # 调整置信度
        current_confidence = finding.get("confidence", 0.8)
        adjusted_confidence = min(current_confidence, guard_result.confidence)
        finding["confidence"] = adjusted_confidence
        finding["guardContext"] = {
            "hasStringLiteralArg": guard_result.has_string_literal_arg,
            "hasGuardPattern": guard_result.has_guard_pattern,
            "confidence": guard_result.confidence,
            "notes": guard_result.notes,
        }

        # 置信度低于阈值则过滤
        if adjusted_confidence < self._confidence_threshold:
            return None

        return finding

    def _score_candidate(self, finding: Dict[str, Any]) -> int:
        """为单个发现计算风险评分。"""
        score = 0

        # 1. 严重程度基础分
        severity = str(finding.get("severity", finding.get("level", ""))).lower()
        score += _SEVERITY_SCORES.get(severity, 2)

        # 2. 漏洞类型加分
        vuln_type = finding.get("vulnType", finding.get("vuln_type", finding.get("category_name", "")))
        if vuln_type in MUST_PASS_VULN_TYPES:
            score += 10

        # 3. 代码内容安全线索加分（按文件缓存，避免同一文件重复正则扫描）
        file_path = finding.get("location", finding.get("file", ""))
        if file_path in self._hint_score_cache:
            score += self._hint_score_cache[file_path]
        else:
            hint_score = 0
            lines = self._read_file_lines(file_path)
            if lines:
                code_content = "\n".join(lines)
                ext = _detect_extension(file_path)
                from src.services.security_hint_profile import get_security_hint_profile, security_hint_score
                profile = get_security_hint_profile(code_content, ext)
                hint_score = security_hint_score(profile)
                # 将画像也存入缓存，供后续过滤使用
                finding["_security_profile"] = profile
            self._hint_score_cache[file_path] = hint_score
            score += hint_score

        # 4. 证据相关加分
        if finding.get("evidence") or finding.get("reason"):
            score += 2

        return max(0, score)

    def _read_file_lines(self, file_path: str) -> List[str]:
        """读取文件行内容，使用缓存避免重复读取。"""
        if not file_path:
            return []
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            full_path = os.path.join(self._project_root, file_path) if self._project_root else file_path
            if not os.path.isfile(full_path):
                return []
            content = Path(full_path).read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")
            self._file_cache[file_path] = lines
            return lines
        except Exception:
            return []

    def clear_cache(self) -> None:
        """清除文件缓存。"""
        self._file_cache.clear()
        self._hint_score_cache.clear()


# ==================== 辅助函数 ====================

@dataclass
class GuardContext:
    """守卫上下文评估结果。"""
    has_string_literal_arg: bool = False
    has_guard_pattern: bool = False
    confidence: float = 1.0
    notes: List[str] = field(default_factory=list)


def _is_test_or_mock_file(file_path: str) -> bool:
    if not file_path:
        return False
    lower = file_path.lower()
    return bool(_TEST_FILE_PATTERN.search(lower) or _TEST_EXT_PATTERN.search(lower))


def _evaluate_guard_context(lines: List[str], line_index: int, vuln_type: str, file_ext: str = "") -> GuardContext:
    """评估指定行的守卫上下文。整合 Guards + Sanitizer + Framework 三层检测。"""
    start = max(0, line_index - GUARD_WINDOW_LINES)
    end = min(len(lines), line_index + GUARD_WINDOW_LINES + 1)
    window_text = "\n".join(lines[start:end])
    line_content = lines[line_index].strip() if line_index < len(lines) else ""

    result = GuardContext()

    # 检查字符串字面量参数
    if _STRING_LITERAL_PATTERN.match(line_content) or _METHOD_CALL_PATTERN.match(line_content):
        result.has_string_literal_arg = True
        result.notes.append("argument_appears_to_be_string_literal")

    # 1) 检查守卫模式
    patterns = GUARD_PATTERNS.get(vuln_type, [])
    if patterns and any(p.search(window_text) for p in patterns):
        result.has_guard_pattern = True
        result.notes.append("security_guard_pattern_detected")

    # 2) 检查净化函数
    sanitizer_patterns = get_sanitizer_patterns(vuln_type)
    if sanitizer_patterns and any(p.search(window_text) for p in sanitizer_patterns):
        result.has_guard_pattern = True
        result.notes.append("sanitizer_function_detected")

    # 3) 检测框架级安全措施
    if file_ext:
        lang_map = {".java": "java", ".py": "python", ".js": "javascript", ".ts": "typescript", ".php": "php"}
        lang = lang_map.get(file_ext, "")
        if lang:
            fw = check_framework_safety(lang, window_text)
            if fw.get("auth") or fw.get("authz") or fw.get("ownership"):
                result.has_guard_pattern = True
                result.notes.append("framework_auth_or_ownership_check")
            if fw.get("csrf"):
                result.has_guard_pattern = True
                result.notes.append("framework_csrf_protection")
            if fw.get("validation"):
                result.has_guard_pattern = True
                result.notes.append("framework_input_validation")

    # 综合置信度调整
    if result.has_string_literal_arg and not result.has_guard_pattern:
        result.confidence = 0.2
        result.notes.append("probably_false_positive_string_arg")
    if result.has_guard_pattern and not result.has_string_literal_arg:
        result.confidence = 0.3
        result.notes.append("mitigated_by_guard")
    if result.has_string_literal_arg and result.has_guard_pattern:
        result.confidence = 0.1
        result.notes.append("doubly_mitigated")

    return result


def _detect_extension(file_path: str) -> str:
    """从文件路径推断扩展名。"""
    if not file_path:
        return ""
    for ext in (".py", ".js", ".ts", ".java", ".go", ".php", ".c", ".cpp", ".cs", ".rb", ".rs"):
        if file_path.lower().endswith(ext):
            return ext
    return ""
