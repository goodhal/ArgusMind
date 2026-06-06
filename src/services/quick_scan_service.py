# -*- coding: utf-8 -*-
"""快速扫描服务 —— 整合自 gbt-codeagent/services/quickScanService.js。

在 LLM 深度审计之前，基于规则引擎对项目进行快速扫描：
1. 正则模式匹配（按语言/漏洞类型）
2. 组件漏洞扫描（依赖文件检测）
3. CVSS 评分与 OWASP 映射
4. 结果去重与标准化

快速扫描结果可作为 CandidateFilter 的输入，预筛选高风险候选送入 LLM。
"""

from __future__ import annotations

import os
import re
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.audit_config import (
    FILE_EXTENSION_MAP,
    LANGUAGE_EXTENSIONS,
    COMPONENT_VULN_RULES,
    VULN_CWE_MAP,
    detect_language,
)
from src.knowledge.owasp_mapping import OWASP_MAPPING, OWASP_NAMES
from src.knowledge.vuln_scoring import (
    VulnIdGenerator,
    score_vulnerability,
    get_vuln_type_defaults,
    VULN_TYPE_CODES,
)
from src.knowledge.component_vulns import COMPONENT_VULNS
from src.knowledge.gbt_standards import VULN_GBT_MAP, get_gbt_mapping
from src.knowledge.security_domains import QUICK_GREP_RULES
from src.knowledge.detection_patterns import DETECTION_PATTERNS
from src.knowledge.vuln_profiles import VULN_PROFILES
from src.services.code_comment_parser import CodeCommentParser


# ---------- 动态线程池大小计算 ----------
def _get_optimal_workers(max_limit: int = 8) -> int:
    """根据 CPU 核心数动态计算合适的线程池大小（I/O 密集型任务）。"""
    cpu_count = os.cpu_count() or 4
    # I/O 密集型：CPU * 2，最多不超过 max_limit
    return min(cpu_count * 2, max_limit)


# === Sink 元数据（证据点定义）===

SINK_METADATA: Dict[str, Dict[str, Any]] = {
    "COMMAND_INJECTION": {
        "type": "CMD",
        "evidence_points": ["EVID_CMD_EXEC_POINT", "EVID_CMD_STRING_CONSTRUCTION", "EVID_CMD_USER_PARAM_MAPPING"],
        "sink_functions": ["exec()", "system()", "shell_exec()", "Runtime.exec()", "ProcessBuilder", "Popen", "subprocess"],
    },
    "SQL_INJECTION": {
        "type": "SQL",
        "evidence_points": ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION", "EVID_SQL_USER_PARAM_MAPPING"],
        "sink_functions": ["query()", "execute()", "Statement", "JdbcTemplate", "createQuery", "raw SQL"],
    },
    "CODE_INJECTION": {
        "type": "CODE",
        "evidence_points": ["EVID_CODE_EXEC_POINT", "EVID_CODE_STRING_CONSTRUCTION", "EVID_CODE_USER_PARAM_MAPPING"],
        "sink_functions": ["eval()", "exec()", "Function()", "GroovyShell", "ScriptEngine"],
    },
    "PATH_TRAVERSAL": {
        "type": "FILE",
        "evidence_points": ["EVID_FILE_READ_SINK", "EVID_FILE_PATH_CONSTRUCTION", "EVID_FILE_USER_PARAM_MAPPING"],
        "sink_functions": ["FileInputStream", "File()", "readFile", "include()", "require()"],
    },
    "XSS": {
        "type": "XSS",
        "evidence_points": ["EVID_XSS_OUTPUT_POINT", "EVID_XSS_USER_INPUT_INTO_OUTPUT", "EVID_XSS_ESCAPE_OR_RAW_CONTROL"],
        "sink_functions": ["innerHTML", "document.write", "echo", "print", "resp.Write"],
    },
    "SSRF": {
        "type": "SSRF",
        "evidence_points": ["EVID_SSRF_URL_CONSTRUCTION", "EVID_SSRF_USER_PARAM_MAPPING", "EVID_SSRF_DNSIP_AND_INNER_BLOCK"],
        "sink_functions": ["URL()", "urlopen", "openConnection", "Request()"],
    },
    "XXE": {
        "type": "XXE",
        "evidence_points": ["EVID_XXE_PARSER_CALL", "EVID_XXE_INPUT_SOURCE", "EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO"],
        "sink_functions": ["XMLReader", "SAXParser", "DocumentBuilder", "loadXML", "simplexml_load_string"],
    },
    "DESERIALIZATION": {
        "type": "DESER",
        "evidence_points": ["EVID_DESER_CALLSITE", "EVID_DESER_INPUT_SOURCE", "EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN"],
        "sink_functions": ["unserialize", "ObjectInputStream", "XMLDecoder", "pickle.load", "yaml.load"],
    },
    "AUTH_BYPASS": {
        "type": "AUTH",
        "evidence_points": ["EVID_AUTH_CHECK_BYPASS", "EVID_AUTH_TOKEN_DECODE_JUDGMENT", "EVID_AUTH_PERMISSION_CHECK_EXEC"],
        "sink_functions": ["referer check", "session check", "SecurityContext"],
    },
    "IDOR": {
        "type": "IDOR",
        "evidence_points": ["EVID_IDOR_OWNERSHIP_CONDITION", "EVID_IDOR_USER_PARAM_MAPPING", "EVID_IDOR_MISSING_CHECK"],
        "sink_functions": ["getAllByUsername", "findById", "getUser"],
    },
    "OPEN_REDIRECT": {
        "type": "REDIR",
        "evidence_points": ["EVID_REDIR_OUTPUT_POINT", "EVID_REDIR_DEST_SOURCE_MAPPING", "EVID_REDIR_DEST_VALIDATION_NORMALIZATION"],
        "sink_functions": ["redirect:", "sendRedirect", "setHeader(Location)"],
    },
    "CSRF": {
        "type": "CSRF",
        "evidence_points": ["EVID_CSRF_TOKEN_SOURCE", "EVID_CSRF_TOKEN_RECEIVE", "EVID_CSRF_TOKEN_VERIFY", "EVID_CSRF_BYPASS_BRANCH"],
        "sink_functions": ["csrfToken", "csrf"],
    },
    "LOG_INJECTION": {
        "type": "LOG",
        "evidence_points": ["EVID_LOG_INJECTION_SINK", "EVID_LOG_USER_INPUT_MAPPING", "EVID_LOG_ESCAPE_OR_SANITIZE"],
        "sink_functions": ["logger.error", "logger.info", "log()"],
    },
}


# === 影响描述与修复建议 ===

_IMPACT_DESCRIPTIONS: Dict[str, str] = {
    "COMMAND_INJECTION": "攻击者可通过注入恶意命令在服务器上执行任意系统命令，可能导致服务器被完全控制",
    "SQL_INJECTION": "攻击者可通过注入恶意SQL语句访问、修改或删除数据库中的敏感数据，可能导致数据泄露或篡改",
    "CODE_INJECTION": "攻击者可通过注入恶意代码在应用程序上下文中执行任意代码，可能导致应用程序被完全控制",
    "SPEL_INJECTION": "攻击者可通过注入恶意SpEL表达式执行任意代码，可能导致应用程序被完全控制",
    "SSTI": "攻击者可通过注入恶意模板代码执行任意代码，可能导致应用程序被完全控制",
    "JNDI_INJECTION": "攻击者可通过JNDI注入加载远程恶意类，可能导致远程代码执行",
    "PATH_TRAVERSAL": "攻击者可通过路径遍历访问服务器上的任意文件，可能导致敏感文件泄露或系统文件被篡改",
    "XSS": "攻击者可通过注入恶意脚本在用户浏览器中执行任意JavaScript代码，可能导致用户会话劫持或敏感信息泄露",
    "SSRF": "攻击者可通过服务器发起任意HTTP请求，可能访问内网服务或泄露敏感信息",
    "XXE": "攻击者可通过恶意XML实体访问服务器文件系统或发起SSRF攻击，可能导致敏感信息泄露",
    "DESERIALIZATION": "恶意构造的反序列化数据可能导致远程代码执行，攻击者可完全控制服务器",
    "AUTH_BYPASS": "认证绕过可能导致未授权用户访问受保护资源，造成数据泄露或权限提升",
    "IDOR": "不安全的直接对象引用可能导致攻击者访问其他用户的数据，造成数据泄露",
    "OPEN_REDIRECT": "开放重定向可能导致攻击者将用户重定向到恶意网站，进行钓鱼攻击",
    "CSRF": "跨站请求伪造可能导致攻击者在用户不知情的情况下执行恶意操作",
    "CORS_MISCONFIGURATION": "CORS配置不当可能导致跨域请求被滥用，造成敏感数据泄露",
    "LOG_INJECTION": "日志注入可能导致日志文件被篡改或注入恶意内容，影响日志审计的准确性",
    "WEAK_CRYPTO": "使用弱加密算法可能被暴力破解或已知攻击方法破解，导致敏感数据泄露",
    "WEAK_HASH": "使用弱哈希算法可能被碰撞攻击或彩虹表攻击破解，导致密码或敏感数据泄露",
    "HARD_CODE_PASSWORD": "硬编码的密码可能被逆向工程获取，攻击者可直接使用这些凭据访问系统",
    "HARDCODED_CREDENTIALS": "硬编码的凭据可能被逆向工程获取，攻击者可直接使用这些凭据访问系统",
    "COMPONENT_VULNERABILITY": "使用存在已知漏洞的组件，攻击者可直接利用公开漏洞进行攻击",
    "FILE_UPLOAD": "未限制的文件上传可能导致攻击者上传恶意文件（webshell等），获取服务器控制权",
    "FILE_OPERATIONS": "不安全的文件操作可能导致任意文件读写，攻击者可读取敏感文件或写入恶意内容",
    "SESSION_FIXATION": "会话固定攻击可能导致攻击者劫持用户会话，访问用户账户",
    "RACE_CONDITION": "竞态条件可能导致数据不一致或安全检查被绕过，造成权限提升或数据篡改",
    "NOSQL_INJECTION": "攻击者可通过注入恶意NoSQL查询语句访问或修改数据库数据，可能导致数据泄露",
    "INTEGER_OVERFLOW": "整数溢出可能导致程序崩溃或安全检查被绕过，攻击者可利用此缺陷进行攻击",
    "PROTOTYPE_POLLUTION": "原型链污染可能导致攻击者注入恶意属性，影响应用程序逻辑或导致代码执行",
    "BUFFER_OVERFLOW": "缓冲区溢出可能导致程序崩溃或执行任意代码，攻击者可完全控制系统",
    "INSECURE_DESERIALIZATION": "恶意构造的反序列化数据可能导致远程代码执行，攻击者可完全控制服务器",
    "FORMAT_STRING": "格式化字符串漏洞可能导致信息泄露或代码执行，攻击者可利用此缺陷进行攻击",
}

# 验证说明（按漏洞类型）
_VERIFICATION_NOTES: Dict[str, str] = {
    "COMMAND_INJECTION": "检测到命令执行调用点，需确认入参是否来自用户输入且未经过滤",
    "SQL_INJECTION": "检测到SQL查询拼接或危险方法调用，需确认参数是否可被用户控制",
    "CODE_INJECTION": "检测到动态代码执行调用，需确认输入来源是否为外部可控数据",
    "SPEL_INJECTION": "检测到SpEL表达式解析调用，需确认表达式是否包含用户输入",
    "SSTI": "检测到模板引擎调用，需确认模板内容是否包含用户输入",
    "JNDI_INJECTION": "检测到JNDI查询调用，需确认查询地址是否来自外部输入",
    "PATH_TRAVERSAL": "检测到文件操作调用，需确认文件路径是否可被用户控制",
    "XSS": "检测到输出写入点，需确认输出内容是否包含未转义的用户输入",
    "SSRF": "检测到URL请求调用，需确认目标URL是否可被用户控制",
    "XXE": "检测到XML解析调用，需确认是否禁用了外部实体解析",
    "DESERIALIZATION": "检测到反序列化调用，需确认输入数据是否来自不可信来源",
    "AUTH_BYPASS": "检测到认证相关代码，需确认认证逻辑是否存在绕过可能",
    "IDOR": "检测到资源访问代码，需确认是否校验了资源所有权",
    "OPEN_REDIRECT": "检测到重定向调用，需确认目标URL是否被校验",
    "FILE_UPLOAD": "检测到文件写入操作，需确认文件类型和内容是否经过安全校验",
    "FILE_OPERATIONS": "检测到文件操作，需确认操作路径和内容是否来自用户输入",
}

# AST 上下文分析用的输入/验证/编码检测正则
_AST_INPUT_PATTERNS = [
    re.compile(r'\b(request\.getParameter|request\.getQueryString|@RequestParam|@PathVariable|@RequestBody|getInputStream|getReader|getParameterMap)\b', re.I),
    re.compile(r'\b(sys\.argv|os\.environ|input\s*\(|req\.(body|query|params|form)|request\.(form|args|json|values|files))\b', re.I),
]
_AST_VALIDATION_PATTERNS = [
    re.compile(r'\b(validate|sanitize|escape|check|verify|guard|filter|clean|normalize|canonical|isSafe|isValid|isAllowed)\b', re.I),
    re.compile(r'\b(Pattern\s*\.\s*matches|Matcher\s*\.\s*matches|StringUtils\s*\.\s*(isBlank|isEmpty)|Objects\s*\.\s*requireNonNull)\b', re.I),
]
_AST_ENCODING_PATTERNS = [
    re.compile(r'\b(encode|escapeHtml|htmlEscape|URLEncoder|encodeURIComponent|StringEscapeUtils|HtmlUtils\s*\.\s*htmlEscape|ESAPI\s*\.\s*encoder)\b', re.I),
    re.compile(r'\b(PreparedStatement|setParameter|setString|setInt|setLong|NamedParameterJdbcTemplate)\b', re.I),
]

_REMEDIATION_ADVICE: Dict[str, str] = {
    "COMMAND_INJECTION": "使用参数化命令执行，避免字符串拼接",
    "SQL_INJECTION": "使用参数化查询（PreparedStatement/ORM安全方法），禁止字符串拼接SQL",
    "CODE_INJECTION": "禁止eval/exec等动态代码执行，使用白名单替代",
    "SPEL_INJECTION": "避免直接使用用户输入构造SpEL表达式",
    "SSTI": "使用沙箱模板引擎，禁止用户输入直接进入模板",
    "PATH_TRAVERSAL": "校验并规范化文件路径，限制访问范围",
    "XSS": "对用户输入进行HTML转义，使用CSP策略",
    "SSRF": "校验URL白名单，禁止访问内网地址",
    "XXE": "禁用外部实体解析，使用安全XML解析器配置",
    "DESERIALIZATION": "禁止反序列化不可信数据，使用白名单过滤",
    "AUTH_BYPASS": "实施统一的认证中间件，避免Referer等可伪造字段验证",
    "IDOR": "增加资源所有权校验，确保用户只能访问自己的数据",
    "OPEN_REDIRECT": "校验重定向目标URL白名单",
    "CSRF": "实施CSRF Token机制",
    "LOG_INJECTION": "对日志内容进行转义，禁止换行符注入",
    "WEAK_CRYPTO": "使用AES-256等强加密算法",
    "WEAK_HASH": "使用SHA-256+等强哈希算法，加盐处理",
    "HARD_CODE_PASSWORD": "使用配置文件或密钥管理服务存储密码",
    "COMPONENT_VULNERABILITY": "升级组件到安全版本",
}


# === 从 DETECTION_PATTERNS 构建快速扫描正则规则 ===

# DETECTION_PATTERNS 使用中文漏洞名作为 key，需映射到英文以对齐 QuickScanFilter 的 MUST_PASS_VULN_TYPES
_VULN_TYPE_CN_TO_EN: Dict[str, str] = {
    "命令注入": "COMMAND_INJECTION",
    "SQL注入": "SQL_INJECTION",
    "路径遍历": "PATH_TRAVERSAL",
    "SSRF": "SSRF",
    "反序列化": "DESERIALIZATION",
    "代码注入": "CODE_INJECTION",
    "JNDI注入": "JNDI_INJECTION",
    "SSTI": "SSTI",
    "XXE": "XXE",
    "XSS": "XSS",
    "认证绕过": "AUTH_BYPASS",
    "硬编码凭据": "HARDCODED_CREDENTIALS",
    "文件上传": "FILE_UPLOAD",
    "文件包含": "FILE_INCLUSION",
    "CORS": "CORS_MISCONFIGURATION",
    "NoSQL注入": "NOSQL_INJECTION",
    "原型链污染": "PROTOTYPE_POLLUTION",
    "缓冲区溢出": "BUFFER_OVERFLOW",
    "CSRF": "CSRF",
    "命令执行": "COMMAND_INJECTION",
}

def _build_quick_scan_patterns() -> Dict[str, List[Dict[str, Any]]]:
    """从 DETECTION_PATTERNS 和 QUICK_GREP_RULES 构建快速扫描正则。"""
    patterns: Dict[str, List[Dict[str, Any]]] = {}

    # 从 DETECTION_PATTERNS 提取 sink 模式
    for lang, vulns in DETECTION_PATTERNS.items():
        lang_patterns: List[Dict[str, Any]] = []
        for vuln_name, vuln_list in vulns.items():
            for entry in vuln_list:
                sink_str = entry.get("sink", "")
                if not sink_str:
                    continue
                # 将逗号分隔的 sink 描述转为正则
                sink_parts = [s.strip() for s in sink_str.split(",") if s.strip()]
                for part in sink_parts:
                    # 从 sink 描述中提取函数名，构建函数调用模式
                    regex = _sink_to_regex(part)
                    if regex is None:
                        continue
                    lang_patterns.append({
                        "pattern": regex,
                        "vuln_type": _VULN_TYPE_CN_TO_EN.get(vuln_name, vuln_name.upper()),
                        "sink_part": part,
                        "severity": _infer_severity(vuln_name),
                    })
        if lang_patterns:
            patterns[lang] = lang_patterns

    # 从 QUICK_GREP_RULES 补充（结构: Dict[vuln_type, List[Dict[pattern, description]]]）
    # 通用规则只编译一次，存入 _common_patterns，scan_file 时按语言合并
    common_patterns: List[Dict[str, Any]] = []
    for vuln_type_key, rule_list in QUICK_GREP_RULES.items():
        for rule in rule_list:
            pattern_str = rule.get("pattern", "")
            description = rule.get("description", "")
            if not pattern_str:
                continue
            try:
                regex = re.compile(pattern_str, re.IGNORECASE)
            except re.error:
                continue
            common_patterns.append({
                "pattern": regex,
                "vuln_type": vuln_type_key.upper(),
                "sink_part": description or pattern_str[:50],
                "severity": _infer_severity(vuln_type_key),
            })

    return patterns, common_patterns


def _sink_to_regex(sink_desc: str) -> Optional[re.Pattern]:
    """将 sink 描述转为函数调用匹配正则。

    例如：
      "exec()" → \bexec\s*\(
      "Runtime.getRuntime().exec()" → Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(
      "eval" → \beval\s*\(
    """
    if not sink_desc:
        return None

    # 去掉尾部括号和分号
    cleaned = sink_desc.rstrip().rstrip(";")
    # 判断是否是方法链（含点号）
    if "." in cleaned:
        # 方法链：逐段转义，最后一段提取函数名
        parts = cleaned.split(".")
        regex_parts = []
        for i, p in enumerate(parts):
            p = p.strip()
            if not p:
                continue
            # 提取标识符部分（去掉括号和参数）
            name = re.match(r"([A-Za-z_]\w*)", p)
            if not name:
                continue
            escaped_name = re.escape(name.group(1))
            if i == len(parts) - 1:
                # 最后一段：匹配函数调用
                regex_parts.append(escaped_name + r"\s*\(")
            else:
                # 中间段：匹配方法名 + 可选括号
                regex_parts.append(escaped_name + r"\s*\(\s*\)")
        if not regex_parts:
            return None
        pattern_str = r"\s*\.\s*".join(regex_parts)
    else:
        # 单函数名
        name = re.match(r"([A-Za-z_]\w*)", cleaned)
        if not name:
            return None
        pattern_str = r"\b" + re.escape(name.group(1)) + r"\s*\("

    try:
        return re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return None


def _build_line_offsets(content: str) -> List[int]:
    """预计算换行符位置表，用于 O(log n) 行号查找。"""
    offsets = []
    for i, ch in enumerate(content):
        if ch == "\n":
            offsets.append(i)
    return offsets


def _offset_to_line(offsets: List[int], pos: int) -> int:
    """根据换行位置表，用二分查找将字符偏移转为行号（1-based）。"""
    return bisect_right(offsets, pos) + 1


def _infer_severity(vuln_name: str) -> str:
    """从漏洞名称推断严重等级。"""
    critical_kw = {"命令注入", "代码执行", "反序列化", "RCE", "COMMAND_INJECTION", "CODE_INJECTION", "DESERIALIZATION"}
    high_kw = {"SQL注入", "注入", "XXE", "SSRF", "认证绕过", "SQL_INJECTION", "XXE", "SSRF", "AUTH_BYPASS"}
    name_upper = vuln_name.upper()
    for kw in critical_kw:
        if kw.upper() in name_upper:
            return "C"
    for kw in high_kw:
        if kw.upper() in name_upper:
            return "H"
    return "M"


def _analyze_ast_context(
    lines: List[str], line_idx: int, vuln_type: str, language: str
) -> Dict[str, Any]:
    """轻量级 AST 级上下文分析：检测用户输入、输入验证、编码处理。

    在发现行上下 20 行范围内搜索模式，返回：
    - has_user_input: 是否检测到用户输入源
    - has_validation: 是否检测到输入验证
    - has_encoding: 是否检测到编码/转义处理
    - recommendation: 深度建议
    """
    # 取发现行上下 20 行作为分析窗口
    start = max(0, line_idx - 20)
    end = min(len(lines), line_idx + 21)
    window = "\n".join(lines[start:end])

    has_user_input = any(p.search(window) for p in _AST_INPUT_PATTERNS)
    has_validation = any(p.search(window) for p in _AST_VALIDATION_PATTERNS)
    has_encoding = any(p.search(window) for p in _AST_ENCODING_PATTERNS)

    # 按漏洞类型生成深度建议
    recommendations = {
        "COMMAND_INJECTION": "使用参数化命令执行（如 ProcessBuilder 的 List<String> 参数），严格过滤或白名单限制可执行命令",
        "SQL_INJECTION": "使用 PreparedStatement 或 MyBatis #{} 参数绑定，避免字符串拼接构造 SQL",
        "CODE_INJECTION": "避免 eval/exec 等动态代码执行；如必须使用，严格限制输入为白名单值",
        "SPEL_INJECTION": "使用 SimpleEvaluationContext 替代 StandardEvaluationContext，或禁用表达式解析",
        "SSTI": "使用沙箱模板引擎，禁止用户输入直接进入模板；对模板变量进行严格校验",
        "JNDI_INJECTION": "固定 JNDI 查询名称，禁止来自用户输入的动态 JNDI 地址",
        "PATH_TRAVERSAL": "使用 Path.normalize() / getCanonicalPath() 规范化路径，校验路径前缀在允许目录内",
        "XSS": "对用户输入进行 HTML 转义或使用安全净化库；启用 CSP 策略限制脚本执行",
        "SSRF": "对请求 URL 实施白名单校验，禁止访问内网地址（127.0.0.0/8、10.0.0.0/8 等）",
        "XXE": "禁用 DTD 和外部实体解析，使用安全的 XML 解析器配置",
        "DESERIALIZATION": "禁止反序列化不可信数据；采用类型白名单，使用安全的序列化方案（如 JSON）",
        "AUTH_BYPASS": "使用统一的认证拦截器/中间件；避免依赖 Referer 等可伪造字段进行权限判断",
        "IDOR": "在数据访问层增加资源所有权校验，确保用户只能访问自己的数据",
        "OPEN_REDIRECT": "对重定向 URL 实施白名单校验或使用间接引用标识",
        "FILE_UPLOAD": "校验文件 MIME 类型和魔数，限制上传文件大小和类型，重命名为服务端生成的随机名",
        "FILE_OPERATIONS": "校验文件路径是否在允许范围内，使用规范路径比较防止路径穿越",
    }
    recommendation = recommendations.get(vuln_type, "建议对用户输入进行严格验证和转义处理")

    if has_validation and has_encoding:
        recommendation += "（检测到验证和编码措施，但仍需确认其完整性和正确性）"
    elif has_validation:
        recommendation += "（检测到输入验证，但建议增加输出编码作为纵深防御）"
    elif has_encoding:
        recommendation += "（检测到编码措施，但建议在输入侧增加验证）"

    # Sink 信息
    sink_info = SINK_METADATA.get(vuln_type, {})
    sink_func = ", ".join(sink_info.get("sink_functions", [])[:3]) or "n/a"

    # 简洁风险标签（3-6字中文标签，避免复用完整影响描述）
    _SINK_RISK_LABELS: Dict[str, str] = {
        "COMMAND_INJECTION": "命令执行风险sink",
        "SQL_INJECTION": "SQL注入风险sink",
        "CODE_INJECTION": "代码执行风险sink",
        "SPEL_INJECTION": "SpEL注入风险sink",
        "SSTI": "模板注入风险sink",
        "JNDI_INJECTION": "JNDI注入风险sink",
        "PATH_TRAVERSAL": "路径遍历风险sink",
        "XSS": "XSS风险sink",
        "SSRF": "SSRF风险sink",
        "XXE": "XXE风险sink",
        "DESERIALIZATION": "反序列化风险sink",
        "AUTH_BYPASS": "认证绕过风险点",
        "IDOR": "越权访问风险点",
        "OPEN_REDIRECT": "重定向风险sink",
        "FILE_UPLOAD": "文件上传风险sink",
        "FILE_OPERATIONS": "文件操作风险sink",
    }
    sink_desc = _SINK_RISK_LABELS.get(vuln_type, "潜在安全风险")

    # Sink 严重度标签
    _SINK_SEVERITY_MAP: Dict[str, str] = {
        "CMD": "critical", "SQL": "critical", "CODE": "critical",
        "DESER": "critical", "SSRF": "high", "XXE": "high",
        "XSS": "high", "FILE": "medium", "AUTH": "high",
        "LOG": "medium", "CRYPTO": "medium", "HASH": "medium",
        "REDIR": "medium", "CSRF": "high", "IDOR": "high",
    }
    sink_type = sink_info.get("type", "")
    sink_severity = _SINK_SEVERITY_MAP.get(sink_type, "medium") if sink_type else "medium"

    return {
        "sink": sink_func,
        "sink_severity": sink_severity,
        "sink_desc": sink_desc,
        "has_user_input": has_user_input,
        "has_validation": has_validation,
        "has_encoding": has_encoding,
        "recommendation": recommendation,
    }


class QuickScanService:
    """快速扫描服务。

    在 LLM 深度审计前，基于正则规则对项目进行快速扫描，
    生成标准化漏洞发现，供 CandidateFilter 预筛选。
    """

    def __init__(self) -> None:
        self._lang_patterns, self._common_patterns = _build_quick_scan_patterns()
        self._vuln_id_gen = VulnIdGenerator()
        self._scanned_files: int = 0
        self._total_findings: int = 0
        self._comment_parser = CodeCommentParser()

    def reset(self) -> None:
        """重置扫描状态。"""
        self._vuln_id_gen.reset()
        self._scanned_files = 0
        self._total_findings = 0

    def get_stats(self) -> Dict[str, Any]:
        """获取扫描统计。"""
        return {
            "scanned_files": self._scanned_files,
            "total_findings": self._total_findings,
            "vuln_id_counts": self._vuln_id_gen.count_by_level(),
        }

    def scan_file(self, file_path: str, project_root: str) -> List[Dict[str, Any]]:
        """扫描单个文件。

        Args:
            file_path: 文件绝对路径
            project_root: 项目根目录

        Returns:
            发现列表
        """
        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        language = detect_language(file_path)

        if not language:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return []

        lines = content.split("\n")
        # 合并语言特定规则 + 通用规则（通用规则只编译一份，按需合并）
        lang_patterns = self._lang_patterns.get(language, [])
        all_patterns = lang_patterns + self._common_patterns
        if not all_patterns:
            return []

        # 预计算换行位置表，避免每次匹配 O(n) 的 count("\n")
        line_offsets = _build_line_offsets(content)

        findings = []
        seen: Set[str] = set()  # 去重 key: vuln_type:line

        for rule in all_patterns:
            regex = rule["pattern"]
            vuln_type = rule["vuln_type"]
            severity = rule["severity"]

            for match in regex.finditer(content):
                line_num = _offset_to_line(line_offsets, match.start())
                dedup_key = f"{vuln_type}:{line_num}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                finding = self._build_finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    language=language,
                    rel_path=rel_path,
                    line_num=line_num,
                    lines=lines,
                )
                if finding:
                    findings.append(finding)

        # 第二遍：vuln_profiles 精确语言级扫描（补充 DETECTION_PATTERNS 遗漏的漏洞）
        profile_findings = self._scan_with_profiles(content, lines, line_offsets, language, rel_path, seen)
        findings.extend(profile_findings)

        self._scanned_files += 1
        self._total_findings += len(findings)
        return findings

    def _build_finding(
        self,
        *,
        vuln_type: str,
        severity: str,
        language: str,
        rel_path: str,
        line_num: int,
        lines: List[str],
        extra_cwe: str = "",
        extra_remediation: str = "",
        source: str = "quick_scan",
        confidence: float = 0.75,
    ) -> Optional[Dict[str, Any]]:
        """构建标准化的 finding 字典。"""
        snippet = self._extract_snippet(lines, line_num - 1)
        vuln_id = self._vuln_id_gen.generate(vuln_type, severity)

        defaults = get_vuln_type_defaults(vuln_type)
        score_result = score_vulnerability(
            reachability=defaults["R"],
            impact=defaults["I"],
            complexity=defaults["C"],
        )

        owasp_ids = OWASP_MAPPING.get(vuln_type, [])
        owasp_display = ", ".join(
            f"{oid} {OWASP_NAMES.get(oid, '')}" for oid in owasp_ids
        )

        gbt_mapping = get_gbt_mapping(vuln_type, language) or "GB/T39412-2020 通用基线"
        sink_meta = SINK_METADATA.get(vuln_type, {})
        cwe = extra_cwe or VULN_CWE_MAP.get(vuln_type, "")
        remediation = extra_remediation or _REMEDIATION_ADVICE.get(vuln_type, "建议人工复核代码上下文")

        return {
            "source": source,
            "vuln_id": vuln_id,
            "title": f"发现 {vuln_type} 漏洞",
            "severity": severity,
            "confidence": confidence,
            "location": f"{rel_path}:{line_num}",
            "file": rel_path,
            "line": line_num,
            "vuln_type": vuln_type,
            "cwe": cwe,
            "language": language,
            "owasp_ids": owasp_ids,
            "owasp": owasp_display,
            "gbt_mapping": gbt_mapping,
            "cvss_score": score_result["cvss"],
            "cvss_score_raw": score_result.get("cvss_raw", score_result["cvss"]),
            "cvss_breakdown": score_result["breakdown"],
            "reachability": score_result["raw_R"],
            "impact_level": score_result["raw_I"],
            "complexity": score_result["raw_C"],
            "reachability_desc": score_result["reachability_desc"],
            "impact_desc": score_result["impact_desc"],
            "complexity_desc": score_result["complexity_desc"],
            "evidence": f"在 {rel_path}:{line_num} 发现 {vuln_type} 相关代码",
            "impact_description": _IMPACT_DESCRIPTIONS.get(vuln_type, "潜在安全风险"),
            "remediation": remediation,
            "safe_validation": "建议人工复核代码上下文，确认是否存在实际安全风险；可通过发送测试 payload 验证漏洞是否确实可利用",
            "verification_note": _VERIFICATION_NOTES.get(vuln_type, "需人工确认是否存在实际安全风险"),
            "ast_context": _analyze_ast_context(lines, line_num - 1, vuln_type, language),
            "code_snippet": snippet,
            "sink_metadata": sink_meta,
            "sink": sink_meta.get("sink_functions", []),
            "evidence_points": sink_meta.get("evidence_points", []),
            "status": "待验证",
            "_file_lines": lines,
        }

    def _scan_with_profiles(
        self,
        content: str,
        lines: List[str],
        line_offsets: List[int],
        language: str,
        rel_path: str,
        seen: Set[str],
    ) -> List[Dict[str, Any]]:
        """使用 vuln_profiles 进行语言级精确扫描。

        对 VULN_PROFILES 中该语言的所有漏洞类型进行风险模式匹配，
        同时在匹配行上下窗口中检测安全模式来调整置信度。
        """
        findings: List[Dict[str, Any]] = []
        if language not in ("java", "python", "javascript", "typescript", "php", "go", "csharp", "ruby"):
            return findings

        # 映射 DETECTION_PATTERNS 语言到 vuln_profiles 语言
        lang_key = {"typescript": "javascript"}.get(language, language)

        for vuln_type, profile in VULN_PROFILES.items():
            lang_profiles = profile.get("languages", {}).get(lang_key, {})
            risk_patterns = lang_profiles.get("risk", [])
            if not risk_patterns:
                continue

            severity = profile.get("default_severity", "MEDIUM")
            cwe = profile.get("cwe", "")
            remediation = lang_profiles.get("remediation", "")
            safe_patterns = lang_profiles.get("safe", [])

            for pattern in risk_patterns:
                for match in pattern.finditer(content):
                    line_num = _offset_to_line(line_offsets, match.start())
                    dedup_key = f"{vuln_type}:{line_num}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # 安全模式检测：取匹配行上下 5 行窗口
                    start = max(0, line_num - 6)
                    end = min(len(lines), line_num + 5)
                    window = "\n".join(lines[start:end])
                    has_safe = safe_patterns and any(p.search(window) for p in safe_patterns)

                    confidence = 0.35 if has_safe else 0.75

                    finding = self._build_finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        language=language,
                        rel_path=rel_path,
                        line_num=line_num,
                        lines=lines,
                        extra_cwe=cwe,
                        extra_remediation=remediation,
                        source="quick_scan",
                        confidence=confidence,
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def scan_component_vulns(self, project_root: str) -> List[Dict[str, Any]]:
        """扫描项目依赖文件中的组件漏洞。

        检查 pom.xml、build.gradle、package.json、requirements.txt 等文件。
        """
        findings = []
        dep_files = [
            "pom.xml", "build.gradle", "gradle.properties",
            "package.json", "requirements.txt", "go.mod", "Gemfile",
            "Cargo.toml", "composer.json",
        ]

        for dep_file in dep_files:
            dep_path = os.path.join(project_root, dep_file)
            if not os.path.isfile(dep_path):
                continue

            try:
                with open(dep_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            rel_path = dep_file

            # 使用 COMPONENT_VULN_RULES 中的正则规则
            for severity_level, rules in COMPONENT_VULN_RULES.items():
                for rule in rules:
                    pattern = rule.get("pattern", "")
                    if isinstance(pattern, str):
                        try:
                            regex = re.compile(pattern, re.IGNORECASE)
                        except re.error:
                            continue
                    else:
                        continue

                    if regex.search(content):
                        vuln_id = self._vuln_id_gen.generate("COMPONENT_VULNERABILITY", severity_level[:1].upper())

                        # 从规则名提取 CVE
                        cve_match = re.search(r"CVE-\d+-\d+", rule.get("name", ""))
                        cve = cve_match.group(0) if cve_match else ""

                        finding = {
                            "source": "component_scan",
                            "vuln_id": vuln_id,
                            "title": rule.get("name", "组件漏洞"),
                            "severity": severity_level[:1].upper(),
                            "confidence": 0.95,
                            "location": rel_path,
                            "file": rel_path,
                            "line": 1,
                            "vuln_type": "COMPONENT_VULNERABILITY",
                            "language": "unknown",
                            "owasp_ids": ["A06:2021"],
                            "owasp": "A06:2021 易受攻击和过时的组件",
                            "gbt_mapping": "GB/T39412-6.2.2.1 敏感信息暴露",
                            "cvss_score": 9.8 if severity_level == "critical" else (8.0 if severity_level == "high" else 5.9),
                            "evidence": f"在 {rel_path} 中发现存在已知漏洞的组件: {rule.get('function', '')}",
                            "impact_description": rule.get("description", ""),
                            "remediation": rule.get("description", "升级到安全版本"),
                            "component": rule.get("function", ""),
                            "cve": cve,
                            "status": "待验证",
                        }
                        findings.append(finding)

        self._total_findings += len(findings)
        return findings

    def scan_project(
        self,
        project_root: str,
        file_list: Optional[List[str]] = None,
        on_progress: Any = None,
    ) -> Dict[str, Any]:
        """扫描整个项目。

        Args:
            project_root: 项目根目录
            file_list: 可选的文件列表（相对路径），为空时自动遍历
            on_progress: 进度回调函数

        Returns:
            扫描结果字典，包含 findings 和 stats
        """
        self.reset()

        # 收集文件
        if file_list is None:
            file_list = self._collect_files(project_root)

        # 过滤出支持的文件
        supported_files = []
        for rel_path in file_list:
            abs_path = os.path.join(project_root, rel_path)
            if os.path.isfile(abs_path) and detect_language(abs_path):
                supported_files.append(abs_path)

        # 扫描文件（并行，8 线程上限）
        all_findings = []
        total = len(supported_files)

        if total <= 10:
            # 小项目串行扫描，避免线程开销
            for idx, abs_path in enumerate(supported_files):
                file_findings = self.scan_file(abs_path, project_root)
                all_findings.extend(file_findings)
                if on_progress and (idx + 1) % 10 == 0:
                    try:
                        on_progress(idx + 1, total)
                    except Exception:
                        pass
        else:
            # 大项目并行扫描（根据 CPU 核心数动态调整）
            max_workers = _get_optimal_workers(max_limit=8)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self.scan_file, abs_path, project_root): abs_path
                    for abs_path in supported_files
                }
                done_count = 0
                for future in as_completed(futures):
                    try:
                        file_findings = future.result()
                        all_findings.extend(file_findings)
                    except Exception:
                        pass
                    done_count += 1
                    if on_progress and done_count % 20 == 0:
                        try:
                            on_progress(done_count, total)
                        except Exception:
                            pass

        # 去重
        deduped = self._deduplicate_findings(all_findings)

        # 注释抑制过滤
        active_findings = self._filter_suppressed(deduped, project_root)

        # 组件漏洞扫描
        component_findings = self.scan_component_vulns(project_root)

        combined = active_findings + component_findings

        return {
            "findings": combined,
            "stats": {
                "total_files_scanned": total,
                "total_findings": len(combined),
                "code_findings": len(active_findings),
                "component_findings": len(component_findings),
                "suppressed_findings": len(deduped) - len(active_findings),
            },
        }

    def _collect_files(self, project_root: str) -> List[str]:
        """收集项目中的文件。"""
        skip_dirs = {
            "node_modules", ".git", "__pycache__", ".idea", ".vscode",
            "target", "build", "dist", ".next", ".nuxt", "vendor",
            ".gradle", ".mvn", "venv", ".env", "env",
        }
        skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz"}

        files = []
        for root, dirs, filenames in os.walk(project_root):
            # 跳过不需要的目录
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in filenames:
                _, ext = os.path.splitext(fname)
                if ext.lower() in skip_exts:
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, project_root).replace("\\", "/")
                files.append(rel_path)
        return files

    @staticmethod
    def _extract_snippet(lines: List[str], line_idx: int, context: int = 4) -> str:
        """提取代码片段（默认上下各 5 行，共约 11 行以展示方法签名上下文）。"""
        # 使用 context+1 前后各多取1行，确保能展示方法签名
        ctx = context + 1
        start = max(0, line_idx - ctx)
        end = min(len(lines), line_idx + ctx + 1)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_idx else "   "
            snippet_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")
        return "\n".join(snippet_lines)

    @staticmethod
    def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重：相同文件+行号+漏洞类型只保留一个。"""
        seen: Set[str] = set()
        deduped = []
        for f in findings:
            key = f"{f.get('file', '')}:{f.get('line', '')}:{f.get('vuln_type', '')}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def _filter_suppressed(
        self, findings: List[Dict[str, Any]], project_root: str
    ) -> List[Dict[str, Any]]:
        """过滤被代码注释抑制的发现。

        按文件分组解析注释，过滤被抑制的发现。
        """
        # 按文件分组
        file_findings: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            file_path = f.get("file", "")
            file_findings.setdefault(file_path, []).append(f)

        active: List[Dict[str, Any]] = []
        for rel_path, group in file_findings.items():
            abs_path = os.path.join(project_root, rel_path)
            language = detect_language(abs_path) or "javascript"

            # 读取文件内容并解析注释
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
            except (OSError, IOError):
                active.extend(group)
                continue

            comments = self._comment_parser.parse_code_comments(code, language)
            result = self._comment_parser.filter_suppressed_findings(group, comments)
            active.extend(result["active"])

        return active
