# -*- coding: utf-8 -*-
"""AST 增强分析器 —— 整合自 gbt-codeagent/services/astEnhancer.js。

对规则扫描产生的漏洞发现进行 AST 级别的上下文增强分析：
- 危险 sink 数据库（50+ 种 cross-language patterns）
- 按漏洞类型分类的深度上下文分析
- 置信度提升/降低
- 访问控制分析（继承链 + 认证检查 + 权限注解）
- 净化措施检测（参数化查询、ORM 使用、输入验证、编码处理）
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# 危险 Sink 数据库（跨语言）
# ═══════════════════════════════════════════════════════════════

DANGEROUS_SINKS: Dict[str, Dict[str, str]] = {
    # 动态代码执行
    "eval": {
        "severity": "critical", "desc": "动态代码执行",
        "vuln_type": "CODE_INJECTION",
        "languages": ["javascript", "typescript", "python", "php"],
    },
    "exec": {
        "severity": "critical", "desc": "命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["python", "php", "ruby"],
    },
    "system": {
        "severity": "critical", "desc": "系统命令调用",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["php", "perl", "c"],
    },
    "subprocess": {
        "severity": "critical", "desc": "子进程命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["python"],
    },
    "os.system": {
        "severity": "critical", "desc": "系统命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["python"],
    },
    "popen": {
        "severity": "high", "desc": "进程创建",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["python"],
    },
    "spawn": {
        "severity": "high", "desc": "进程创建",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["javascript", "nodejs"],
    },
    "execSync": {
        "severity": "critical", "desc": "同步命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["javascript", "typescript"],
    },
    "execFile": {
        "severity": "high", "desc": "进程文件执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["javascript", "typescript"],
    },
    "Runtime.exec": {
        "severity": "critical", "desc": "Java 命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["java"],
    },
    "Runtime.getRuntime": {
        "severity": "critical", "desc": "Java Runtime 命令执行",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["java"],
    },
    "ProcessBuilder": {
        "severity": "high", "desc": "Java 进程构建",
        "vuln_type": "COMMAND_INJECTION",
        "languages": ["java"],
    },
    # SQL 注入
    "executeQuery": {
        "severity": "high", "desc": "原始 SQL 查询",
        "vuln_type": "SQL_INJECTION",
        "languages": ["java"],
    },
    "executeUpdate": {
        "severity": "high", "desc": "SQL 更新执行",
        "vuln_type": "SQL_INJECTION",
        "languages": ["java"],
    },
    "createStatement": {
        "severity": "high", "desc": "Statement 创建",
        "vuln_type": "SQL_INJECTION",
        "languages": ["java"],
    },
    "raw": {
        "severity": "medium", "desc": "动态查询构造",
        "vuln_type": "SQL_INJECTION",
        "languages": ["python", "javascript", "php"],
    },
    "execute": {
        "severity": "high", "desc": "SQL 执行",
        "vuln_type": "SQL_INJECTION",
        "languages": ["python", "javascript", "java", "go"],
    },
    "cursor.execute": {
        "severity": "high", "desc": "数据库游标执行",
        "vuln_type": "SQL_INJECTION",
        "languages": ["python"],
    },
    "db.Query": {
        "severity": "high", "desc": "Go 数据库查询",
        "vuln_type": "SQL_INJECTION",
        "languages": ["go"],
    },
    "db.Exec": {
        "severity": "high", "desc": "Go 数据库执行",
        "vuln_type": "SQL_INJECTION",
        "languages": ["go"],
    },
    # XSS
    "innerHTML": {
        "severity": "high", "desc": "动态 HTML 插入",
        "vuln_type": "XSS",
        "languages": ["javascript", "typescript"],
    },
    "dangerouslySetInnerHTML": {
        "severity": "high", "desc": "React 动态 HTML",
        "vuln_type": "XSS",
        "languages": ["javascript", "typescript"],
    },
    "document.write": {
        "severity": "high", "desc": "文档写入",
        "vuln_type": "XSS",
        "languages": ["javascript"],
    },
    "v-html": {
        "severity": "high", "desc": "Vue 动态 HTML",
        "vuln_type": "XSS",
        "languages": ["vue", "javascript"],
    },
    "Response.Write": {
        "severity": "high", "desc": "ASP.NET 响应写入",
        "vuln_type": "XSS",
        "languages": ["csharp"],
    },
    # SSRF
    "fetch": {
        "severity": "medium", "desc": "HTTP 请求",
        "vuln_type": "SSRF",
        "languages": ["javascript", "typescript"],
    },
    "axios": {
        "severity": "medium", "desc": "HTTP 客户端",
        "vuln_type": "SSRF",
        "languages": ["javascript", "typescript"],
    },
    "http.request": {
        "severity": "medium", "desc": "HTTP 请求",
        "vuln_type": "SSRF",
        "languages": ["javascript", "python"],
    },
    "requests.get": {
        "severity": "medium", "desc": "HTTP GET 请求",
        "vuln_type": "SSRF",
        "languages": ["python"],
    },
    "requests.post": {
        "severity": "medium", "desc": "HTTP POST 请求",
        "vuln_type": "SSRF",
        "languages": ["python"],
    },
    "urllib.request": {
        "severity": "medium", "desc": "URL 库请求",
        "vuln_type": "SSRF",
        "languages": ["python"],
    },
    "RestTemplate": {
        "severity": "medium", "desc": "Spring REST 调用",
        "vuln_type": "SSRF",
        "languages": ["java"],
    },
    "HttpClient": {
        "severity": "medium", "desc": "HTTP 客户端",
        "vuln_type": "SSRF",
        "languages": ["java", "csharp"],
    },
    "http.Get": {
        "severity": "medium", "desc": "Go HTTP Get",
        "vuln_type": "SSRF",
        "languages": ["go"],
    },
    # 路径穿越
    "readFile": {
        "severity": "medium", "desc": "文件读取",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["javascript", "typescript"],
    },
    "readFileSync": {
        "severity": "medium", "desc": "同步文件读取",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["javascript", "typescript"],
    },
    "os.open": {
        "severity": "medium", "desc": "文件打开",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["python"],
    },
    "open(": {
        "severity": "medium", "desc": "文件打开",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["python"],
    },
    "File(": {
        "severity": "medium", "desc": "文件操作",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["java"],
    },
    "FileInputStream": {
        "severity": "medium", "desc": "文件输入流",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["java"],
    },
    "os.ReadFile": {
        "severity": "medium", "desc": "Go 文件读取",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["go"],
    },
    "ioutil.ReadFile": {
        "severity": "medium", "desc": "Go ioutil 文件读取",
        "vuln_type": "PATH_TRAVERSAL",
        "languages": ["go"],
    },
    # XXE
    "XMLParser": {
        "severity": "high", "desc": "XML 解析器",
        "vuln_type": "XXE",
        "languages": ["javascript", "typescript"],
    },
    "DocumentBuilder": {
        "severity": "high", "desc": "文档构建器",
        "vuln_type": "XXE",
        "languages": ["java"],
    },
    "SAXParser": {
        "severity": "high", "desc": "SAX 解析器",
        "vuln_type": "XXE",
        "languages": ["java"],
    },
    "SAXReader": {
        "severity": "high", "desc": "SAX 读取器",
        "vuln_type": "XXE",
        "languages": ["java"],
    },
    "XMLReader": {
        "severity": "high", "desc": "XML 读取器",
        "vuln_type": "XXE",
        "languages": ["java"],
    },
    "TransformerFactory": {
        "severity": "high", "desc": "XSLT 工厂",
        "vuln_type": "XSLT_INJECTION",
        "languages": ["java"],
    },
    "XSLTProcessor": {
        "severity": "high", "desc": "XSLT 处理器",
        "vuln_type": "XSLT_INJECTION",
        "languages": ["javascript"],
    },
    # 反序列化
    "pickle.loads": {
        "severity": "critical", "desc": "Pickle 反序列化",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["python"],
    },
    "pickle.load": {
        "severity": "critical", "desc": "Pickle 加载",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["python"],
    },
    "yaml.load": {
        "severity": "critical", "desc": "不安全的 YAML 加载",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["python"],
    },
    "yaml.unsafe_load": {
        "severity": "critical", "desc": "不安全的 YAML 加载",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["python"],
    },
    "unserialize": {
        "severity": "critical", "desc": "PHP 反序列化",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["php"],
    },
    "readObject": {
        "severity": "critical", "desc": "对象读取",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["java"],
    },
    "ObjectInputStream": {
        "severity": "critical", "desc": "对象输入流",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["java"],
    },
    "deserialize": {
        "severity": "critical", "desc": "反序列化调用",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["java"],
    },
    "json.Unmarshal": {
        "severity": "low", "desc": "Go JSON 反序列化",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "languages": ["go"],
    },
    # 弱加密
    "md5": {
        "severity": "medium", "desc": "MD5 哈希（弱）",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["*"],
    },
    "sha1": {
        "severity": "medium", "desc": "SHA1 哈希（弱）",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["*"],
    },
    "DES": {
        "severity": "medium", "desc": "DES 加密（弱）",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["*"],
    },
    "RC4": {
        "severity": "medium", "desc": "RC4 加密（弱）",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["*"],
    },
    "MessageDigest.getInstance": {
        "severity": "medium", "desc": "Java 加密摘要",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["java"],
    },
    "Cipher.getInstance": {
        "severity": "medium", "desc": "Java 加密实例",
        "vuln_type": "WEAK_CRYPTO",
        "languages": ["java"],
    },
    # 模板注入（SSTI）
    "render_template_string": {
        "severity": "high", "desc": "Flask 模板注入",
        "vuln_type": "SSTI",
        "languages": ["python"],
    },
    "Template(": {
        "severity": "high", "desc": "Jinja2 模板创建",
        "vuln_type": "SSTI",
        "languages": ["python"],
    },
    "evaluate(": {
        "severity": "high", "desc": "表达式评估",
        "vuln_type": "CODE_INJECTION",
        "languages": ["java"],
    },
    # 弱随机数
    "random": {
        "severity": "medium", "desc": "伪随机数",
        "vuln_type": "INSECURE_RANDOM",
        "languages": ["python"],
    },
    "Math.random": {
        "severity": "medium", "desc": "JS 伪随机数",
        "vuln_type": "INSECURE_RANDOM",
        "languages": ["javascript", "typescript"],
    },
    "java.util.Random": {
        "severity": "medium", "desc": "Java 伪随机数",
        "vuln_type": "INSECURE_RANDOM",
        "languages": ["java"],
    },
    "rand.": {
        "severity": "medium", "desc": "Go 伪随机数",
        "vuln_type": "INSECURE_RANDOM",
        "languages": ["go"],
    },
    # JNDI 注入
    "InitialContext.lookup": {
        "severity": "critical", "desc": "JNDI 查询",
        "vuln_type": "JNDI_INJECTION",
        "languages": ["java"],
    },
    "JndiTemplate": {
        "severity": "critical", "desc": "Spring JNDI 模板",
        "vuln_type": "JNDI_INJECTION",
        "languages": ["java"],
    },
    # SpEL 注入
    "SpelExpressionParser": {
        "severity": "high", "desc": "SpEL 表达式解析",
        "vuln_type": "SPEL_INJECTION",
        "languages": ["java"],
    },
    "ExpressionParser": {
        "severity": "high", "desc": "表达式解析器",
        "vuln_type": "SPEL_INJECTION",
        "languages": ["java"],
    },
}

# ═══════════════════════════════════════════════════════════════
# 认证/访问控制检查模式
# ═══════════════════════════════════════════════════════════════

AUTH_PATTERNS = {
    "required": [
        "authenticate", "verify", "checkPermission", "authorize",
        "isAuthenticated", "hasRole", "hasPermission", "requireAuth",
        "login", "checkSession", "@Authenticated", "@Secured",
    ],
    "optional": [
        "optional", "public", "anonymous", "guest", "permitAll", "anonymousOk",
    ],
}

AUTH_ANNOTATION_PATTERNS = [
    re.compile(r"@(PreAuthorize|Secured|RequiresPermissions|RolesAllowed)"),
    re.compile(r"@(Auth|Authenticated|Anonymous)"),
    re.compile(r"@(has_role|has_permission|login_required)"),
    re.compile(r"#(auth|permission|role)"),
]

ACCESS_CONTROL_PATTERNS = {
    "inherit": [
        "extends", "implements", "BaseController", "BaseService", "Parent",
    ],
    "check": [
        "checkOwner", "checkTenant", "validateOwnership", "canAccess",
        "canModify", "isOwner", "hasAccess",
    ],
}

# ═══════════════════════════════════════════════════════════════
# 上下文模式库
# ═══════════════════════════════════════════════════════════════

_USER_INPUT_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(req|request|params|query|body|headers|cookies)\b"),
    re.compile(r"\b(input|userInput|user_input|formData|form_data)\b"),
    re.compile(r"\b(getPost|getQuery|getParam|get_post|get_query|get_param)\b"),
    re.compile(r"\$_(GET|POST|REQUEST|COOKIES)"),
    re.compile(r"\bHttpServletRequest\b"),
    re.compile(r"\brequest\.(args|form|json|data|values)\b"),
    re.compile(r"\bc\.(Query|Param|PostForm|DefaultQuery|DefaultPostForm)\b"),
]

_VALIDATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(validate|sanitize|escape|encode|clean)\b", re.IGNORECASE),
    re.compile(r"\b(check|verify|assert)\b", re.IGNORECASE),
    re.compile(r"\b(regex|pattern|match)\b", re.IGNORECASE),
    re.compile(r"\b(whitelist|blacklist|allowlist|blocklist)\b", re.IGNORECASE),
    re.compile(r"\b@(Valid|Validated|NotNull|NotEmpty|NotBlank|Size|Min|Max|Pattern)\b"),
]

_ENCODING_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(encodeURI|encodeURIComponent|escape|htmlEncode|entityEncode)\b"),
    re.compile(r"\b(html\.escape|escape_html|cgi\.escape|markupsafe\.escape)\b"),
    re.compile(r"\b(ESAPI\.encoder|Encoder\.encodeForHTML|OWASP\.Encoder)\b"),
    re.compile(r"\bhtml\.EscapeString\b"),  # Go
]

_PARAMETERIZATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"[?$]\d|:\w"),  # ?1, $1, :name 格式
    re.compile(r"\b(PreparedStatement|prepareStatement|createQuery|createNativeQuery)\b"),
    re.compile(r"\b(executemany|execute_values)\b"),  # Python 参数化批量
    re.compile(r"\b\.(Prepare|Named|Where|Find)\b"),  # ORM 风格
]

_ORM_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(sequelize|typeorm|prisma|bookshelf|mongoose|ActiveRecord)\b", re.IGNORECASE),
    re.compile(r"\b(SQLAlchemy|Django\s*ORM|Peewee|Pony\s*ORM)\b", re.IGNORECASE),
    re.compile(r"\b(Hibernate|JPA|MyBatis|Spring\s*Data)\b", re.IGNORECASE),
    re.compile(r"\b(GORM|ent|sqlx|sqlboiler)\b", re.IGNORECASE),
    re.compile(r"\b(Entity\s*Framework|Dapper|NHibernate)\b", re.IGNORECASE),
    re.compile(r"\b(Doctrine|Eloquent|Propel)\b", re.IGNORECASE),
]

_XSS_SANITIZATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(DOMPurify|sanitizeHtml|sanitize-html)\b"),
    re.compile(r"\b(html\.escape|escape_html|htmlspecialchars|htmlentities)\b"),
    re.compile(r"\b(bleach\.clean|bleach\.linkify)\b"),
    re.compile(r"\b(ESAPI\.encoder|Encoder\.encodeForHTML)\b"),
    re.compile(r"\b(template\.HTMLEscape|html/template)\b"),  # Go
    re.compile(r"\b(createTextNode|textContent|setAttribute)\b"),  # JS 安全 DOM
]

_URL_VALIDATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(urlparse|urllib\.parse|URL\(\"\"\"|new\s+URL\()\b"),
    re.compile(r"\b(is_valid_url|validate_url|check_url|filter_url)\b", re.IGNORECASE),
    re.compile(r"\b(allowed_hosts|allowed_domains|whitelist_domains|allowlist)\b", re.IGNORECASE),
    re.compile(r"\b(SSRFProtect|SSRF_Filter|safe_url)\b", re.IGNORECASE),
]

_PATH_VALIDATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(os\.path\.normpath|os\.path\.realpath|os\.path\.abspath)\b"),
    re.compile(r"\b(path\.Clean|filepath\.Clean|filepath\.Base)\b"),  # Go
    re.compile(r"\b(is_subpath|is_safe_path|check_path|validate_path)\b", re.IGNORECASE),
    re.compile(r"\b(secure_filename|safe_join)\b"),  # Flask/Werkzeug
    re.compile(r"\b(FilenameUtils\.getName|Paths\.get)\b"),  # Java
]

_XML_SAFETY_PATTERNS: List[re.Pattern] = [
    re.compile(r"FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA"),
    re.compile(r"setFeature.*DISALLOW_DOCTYPE"),
    re.compile(r"dtd_validation|resolve_entities|forbid_dtd"),
    re.compile(r"(\"http://apache\.org/xml/features/disallow-doctype-decl\"|XMLConstants\.FEATURE_SECURE_PROCESSING)"),
]

_DESERIALIZATION_SAFETY_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(yaml\.safe_load|yaml\.SafeLoader|yaml\.CSafeLoader)\b"),
    re.compile(r"\b(json\.loads|orjson\.loads|ujson\.loads)\b"),  # JSON 替代方案
    re.compile(r"\b(LookupCodec|ObjectInputFilter|validatedObject)\b"),  # Java 防护
    re.compile(r"\b(class_whitelist|allowed_classes|safe_globals)\b", re.IGNORECASE),
]


@dataclass
class ASTContext:
    """AST 增强分析上下文。"""

    sink: str = ""
    sink_severity: str = ""
    sink_desc: str = ""
    vuln_type: str = ""
    context_lines: List[Dict[str, Any]] = field(default_factory=list)
    has_user_input: bool = False
    has_validation: bool = False
    has_encoding: bool = False
    has_sanitization: bool = False
    has_parameterization: bool = False
    has_orm: bool = False
    has_url_validation: bool = False
    has_path_validation: bool = False
    query_type: str = "unknown"
    recommendation: str = ""
    # 访问控制特化字段
    class_name: str = ""
    has_auth_check: bool = False
    has_owner_check: bool = False
    has_auth_annotation: bool = False


class ASTEnricherService:
    """AST 增强分析服务。

    对漏洞发现进行上下文感知的深度分析，提升置信度并提供更丰富的证据。
    不需要 tree-sitter 等复杂 AST 解析器，使用基于 grep 和模式匹配的
    轻量级方法，适用于所有文本格式的源代码语言。
    """

    def __init__(self) -> None:
        self._file_cache: Dict[str, List[str]] = {}

    def enhance_findings(
        self,
        findings: List[Dict[str, Any]],
        source_root: str,
    ) -> List[Dict[str, Any]]:
        """对一批 findings 进行 AST 增强分析。

        Args:
            findings: 漏洞发现列表
            source_root: 项目源代码根目录

        Returns:
            增强后的 findings 列表（含 ast_context 字段）
        """
        if not findings or len(findings) < 20:
            # 发现 < 20 条时增强增益小，跳过节省时间（与 gbt-codeagent 行为一致）
            return findings

        enhanced = []
        for finding in findings:
            enriched = dict(finding)
            context = self._analyze_finding(finding, source_root)
            if context:
                enriched["ast_context"] = context
                # 置信度提升（与 gbt-codeagent 一致）
                vuln_type = finding.get("vuln_type", finding.get("vulnType", ""))
                confidence_delta = self._get_confidence_delta(vuln_type, context)
                original = float(finding.get("confidence", 0.5))
                enriched["confidence"] = round(min(original + confidence_delta, 1.0), 2)
            enhanced.append(enriched)

        return enhanced

    def _get_confidence_delta(self, vuln_type: str, context: Dict[str, Any]) -> float:
        """根据漏洞类型和上下文计算置信度增量。"""
        base_delta = 0.0

        # 基础：找到了匹配的 dangerous sink
        if context.get("sink"):
            base_delta += 0.05

        # 有用户输入 → 加 0.1
        if context.get("has_user_input"):
            base_delta += 0.1

        # 无任何防护 → 加 0.1
        has_any_defense = (
            context.get("has_validation")
            or context.get("has_encoding")
            or context.get("has_sanitization")
            or context.get("has_parameterization")
            or context.get("has_orm")
            or context.get("has_url_validation")
            or context.get("has_path_validation")
        )
        if not has_any_defense:
            base_delta += 0.1

        # 按类型微调
        type_deltas = {
            "INSECURE_DESERIALIZATION": 0.15,
            "COMMAND_INJECTION": 0.1,
            "CODE_INJECTION": 0.1,
            "SQL_INJECTION": 0.1,
            "XSS": 0.1,
            "SSRF": 0.1,
            "PATH_TRAVERSAL": 0.1,
            "XXE": 0.1,
            "JNDI_INJECTION": 0.1,
            "SPEL_INJECTION": 0.1,
            "WEAK_CRYPTO": 0.05,
            "INSECURE_RANDOM": 0.05,
        }
        if vuln_type in type_deltas:
            base_delta += type_deltas[vuln_type]

        return round(base_delta, 2)

    def _analyze_finding(
        self,
        finding: Dict[str, Any],
        source_root: str,
    ) -> Optional[Dict[str, Any]]:
        """对单个 finding 进行 AST 增强分析。"""
        vuln_type = finding.get("vuln_type", finding.get("vulnType", ""))
        evidence = finding.get("evidence", finding.get("code_snippet", ""))
        location = finding.get("location", finding.get("file", ""))

        if not vuln_type or not location:
            return None

        # 读取文件内容
        file_path = self._resolve_file_path(location, source_root)
        if not file_path or not os.path.isfile(file_path):
            return None

        lines = self._read_file_cached(file_path)
        if not lines:
            return None

        line_num = self._extract_line_number(location)
        context_lines = self._get_context_lines(lines, line_num)

        # 按漏洞类型分发分析
        if vuln_type in ("COMMAND_INJECTION", "CODE_INJECTION"):
            return self._analyze_injection(context_lines, evidence, line_num, vuln_type)
        if vuln_type == "SQL_INJECTION":
            return self._analyze_sql(context_lines, evidence, line_num)
        if vuln_type == "XSS":
            return self._analyze_xss(context_lines, evidence, line_num)
        if vuln_type == "SSRF":
            return self._analyze_ssrf(context_lines, evidence, line_num)
        if vuln_type == "PATH_TRAVERSAL":
            return self._analyze_path_traversal(context_lines, evidence, line_num)
        if vuln_type in ("XXE", "XSLT_INJECTION"):
            return self._analyze_xml(context_lines, evidence, line_num)
        if vuln_type == "INSECURE_DESERIALIZATION":
            return self._analyze_deserialization(context_lines, evidence, line_num)
        if vuln_type in ("WEAK_CRYPTO", "INSECURE_RANDOM"):
            return self._analyze_crypto(context_lines, evidence, line_num)
        if vuln_type in ("AUTH_BYPASS", "IDOR"):
            return self._analyze_access_control(context_lines, evidence, line_num)
        # 通用分析
        return self._analyze_generic(context_lines, evidence, line_num, vuln_type)

    # ---------- 文件辅助 ----------

    def _resolve_file_path(self, location: str, source_root: str) -> Optional[str]:
        """从 location 解析文件路径。"""
        file_part = location.split(":")[0].strip()
        if not file_part:
            return None
        if os.path.isabs(file_part):
            return file_part
        # 防止路径穿越
        parts = file_part.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            return None
        return os.path.normpath(os.path.join(source_root, file_part))

    def _extract_line_number(self, location: str) -> int:
        """从 location 中提取行号。"""
        parts = location.split(":")
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except (ValueError, IndexError):
                pass
        return 1

    def _read_file_cached(self, file_path: str) -> List[str]:
        """带缓存的读取文件。"""
        if file_path in self._file_cache:
            return self._file_cache[file_path]
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            self._file_cache[file_path] = lines
            return lines
        except Exception as e:
            logger.warning("读取文件失败 %s: %s", file_path, e)
            return []

    def _get_context_lines(self, lines: List[str], line_num: int, before: int = 10, after: int = 5) -> List[str]:
        """获取上下文行。"""
        start = max(0, line_num - before - 1)
        end = min(len(lines), line_num + after)
        return lines[start:end]

    def _format_context_lines(self, lines: List[str], start_line: int) -> List[Dict[str, Any]]:
        """格式化上下文行为字典列表。"""
        return [
            {"line_num": start_line + i + 1, "content": line.rstrip()}
            for i, line in enumerate(lines)
        ]

    # ---------- 模式检测辅助 ----------

    def _check_patterns(self, lines: List[str], patterns: List[re.Pattern]) -> bool:
        """检查上下文行中是否匹配任一模式。"""
        return any(
            any(pattern.search(line) for pattern in patterns)
            for line in lines
        )

    def _find_matched_sink(self, evidence: str) -> Optional[Dict[str, str]]:
        """从 evidence 中找到匹配的 dangerous sink。"""
        evidence_lower = evidence.lower()
        for sink_name, sink_info in DANGEROUS_SINKS.items():
            if sink_name.lower() in evidence_lower:
                return {"name": sink_name, **sink_info}
        return None

    # ---------- 各漏洞类型分析 ----------

    def _analyze_injection(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
        vuln_type: str,
    ) -> Optional[Dict[str, Any]]:
        """分析注入风险。"""
        sink = self._find_matched_sink(evidence)
        if not sink:
            return None

        return {
            "sink": sink["name"],
            "sink_severity": sink.get("severity", "high"),
            "sink_desc": sink.get("desc", ""),
            "vuln_type": vuln_type,
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 11)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_validation": self._check_patterns(context_lines, _VALIDATION_PATTERNS),
            "has_encoding": self._check_patterns(context_lines, _ENCODING_PATTERNS),
            "recommendation": self._gen_injection_recommendation(sink["name"]),
        }

    def _analyze_sql(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析 SQL 注入风险。"""
        return {
            "sink": "sql_execute",
            "sink_severity": "high",
            "sink_desc": "SQL 执行",
            "vuln_type": "SQL_INJECTION",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_validation": self._check_patterns(context_lines, _VALIDATION_PATTERNS),
            "has_parameterization": self._check_patterns(context_lines, _PARAMETERIZATION_PATTERNS),
            "has_orm": self._check_patterns(context_lines, _ORM_PATTERNS),
            "query_type": self._detect_query_type(context_lines),
            "recommendation": self._gen_sql_recommendation(context_lines),
        }

    def _analyze_xss(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析 XSS 风险。"""
        return {
            "sink": "xss_output",
            "sink_severity": "high",
            "sink_desc": "XSS 风险输出",
            "vuln_type": "XSS",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_sanitization": self._check_patterns(context_lines, _XSS_SANITIZATION_PATTERNS),
            "has_encoding": self._check_patterns(context_lines, _ENCODING_PATTERNS),
            "recommendation": "使用 DOMPurify 或等效库对输出进行 HTML 实体编码；使用安全 DOM API (textContent/createTextNode)",
        }

    def _analyze_ssrf(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析 SSRF 风险。"""
        return {
            "sink": "ssrf_request",
            "sink_severity": "medium",
            "sink_desc": "SSRF 风险请求",
            "vuln_type": "SSRF",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_url_validation": self._check_patterns(context_lines, _URL_VALIDATION_PATTERNS),
            "recommendation": "对用户提供的 URL 做白名单校验，禁止访问内网地址",
        }

    def _analyze_path_traversal(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析路径穿越风险。"""
        return {
            "sink": "file_operation",
            "sink_severity": "medium",
            "sink_desc": "文件操作",
            "vuln_type": "PATH_TRAVERSAL",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 11)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_path_validation": self._check_patterns(context_lines, _PATH_VALIDATION_PATTERNS),
            "recommendation": "使用 os.path.normpath/os.path.realpath 规范化路径，并校验文件是否在允许目录下",
        }

    def _analyze_xml(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析 XXE/XSLT 风险。"""
        return {
            "sink": "xml_parser",
            "sink_severity": "high",
            "sink_desc": "XML 解析器",
            "vuln_type": "XXE",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_validation": self._check_patterns(context_lines, _XML_SAFETY_PATTERNS),
            "recommendation": "禁用外部实体解析 (FEATURE_SECURE_PROCESSING, disallow-doctype-decl)；使用安全 XML 解析器配置",
        }

    def _analyze_deserialization(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析反序列化风险。"""
        return {
            "sink": "deserialization",
            "sink_severity": "critical",
            "sink_desc": "反序列化操作",
            "vuln_type": "INSECURE_DESERIALIZATION",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": self._check_patterns(context_lines, _USER_INPUT_PATTERNS),
            "has_validation": self._check_patterns(context_lines, _DESERIALIZATION_SAFETY_PATTERNS),
            "recommendation": "使用 yaml.safe_load / json.loads 等安全替代；对 pickled 数据做 HMAC 完整性校验；Java 侧使用 ObjectInputFilter",
        }

    def _analyze_crypto(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析弱加密/弱随机数风险。"""
        return {
            "sink": "weak_crypto",
            "sink_severity": "medium",
            "sink_desc": "弱加密/哈希/随机数",
            "vuln_type": "WEAK_CRYPTO",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_validation": self._check_patterns(context_lines, _VALIDATION_PATTERNS),
            "recommendation": "替换为 SHA-256/SHA-3 (哈希)、AES-256-GCM (加密)、secrets 模块/java.security.SecureRandom/crypto/rand (随机数)",
        }

    def _analyze_access_control(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
    ) -> Optional[Dict[str, Any]]:
        """分析访问控制风险。"""
        has_auth = self._check_patterns(context_lines, [
            re.compile(p, re.IGNORECASE)
            for p_raw in AUTH_PATTERNS["required"]
            for p in [re.escape(p_raw)]
        ])
        has_annotation = self._check_patterns(context_lines, AUTH_ANNOTATION_PATTERNS)

        return {
            "sink": "access_control",
            "sink_severity": "high",
            "sink_desc": "访问控制缺失",
            "vuln_type": "AUTH_BYPASS",
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 16)),
            "has_auth_check": has_auth,
            "has_auth_annotation": has_annotation,
            "recommendation": "为所有敏感操作添加认证/授权检查；使用框架内置的 @PreAuthorize / @login_required 等注解",
        }

    def _analyze_generic(
        self,
        context_lines: List[str],
        evidence: str,
        line_num: int,
        vuln_type: str,
    ) -> Optional[Dict[str, Any]]:
        """通用分析（兜底）。"""
        has_input = self._check_patterns(context_lines, _USER_INPUT_PATTERNS)
        has_validation = self._check_patterns(context_lines, _VALIDATION_PATTERNS)

        if has_input and not has_validation:
            rec = "检测到用户输入进入存在风险的代码路径且缺乏有效验证机制，建议补充输入校验和白名单过滤，确认输入来源和攻击面。"
        elif has_input and has_validation:
            rec = "检测到用户输入且存在部分校验机制，建议人工评估输入验证是否覆盖所有攻击面（如特殊字符、边界值、编码绕过等）。"
        else:
            rec = "该代码点存在潜在安全风险，未检测到直接的对外部用户输入的引用，建议结合业务逻辑确认数据来源的可信度。"
        rec += "如果确认无法被外部访问，可标记为误报。"

        return {
            "sink": "generic_risk",
            "sink_severity": "medium",
            "sink_desc": "潜在安全风险",
            "vuln_type": vuln_type,
            "context_lines": self._format_context_lines(context_lines, max(0, line_num - 9)),
            "has_user_input": has_input,
            "has_validation": has_validation,
            "recommendation": rec,
        }

    # ---------- SQL 特化检测 ----------

    def _detect_query_type(self, lines: List[str]) -> str:
        """检测 SQL 查询类型。"""
        for line in lines:
            if re.search(r"\b(raw|query|execute)\s*\(\s*['\"`]|\.query\s*\(", line, re.IGNORECASE):
                return "raw_sql"
            if re.search(r"\b(find|create|update|delete|where|filter|select)\s*\(", line, re.IGNORECASE):
                return "orm"
            if re.search(r"\b(prepare|bind|param|executemany)\s*\(", line, re.IGNORECASE):
                return "parameterized"
        return "unknown"

    # ---------- 建议生成 ----------

    def _gen_injection_recommendation(self, sink_name: str) -> str:
        """生成注入风险建议。"""
        recs = {
            "exec": "使用 subprocess.run([cmd, arg1, arg2], shell=False) 替代 os.system() 或 shell=True",
            "subprocess": "确保 shell=False（默认），参数作为列表传递而非拼接字符串",
            "os.system": "禁止使用 os.system()，改用 subprocess.run() 并关闭 shell",
            "eval": "禁止使用 eval()；如需动态表达式计算，使用 ast.literal_eval() 或安全沙箱",
            "Runtime.exec": "使用 ProcessBuilder 并将参数列表化传递，禁止拼接用户输入到命令字符串",
            "spawn": "使用 child_process.spawn 时，命令和参数分开传递，禁止拼接",
            "execSync": "使用 execFileSync 替代 execSync，参数列表化",
        }
        return recs.get(sink_name, "对用户输入做严格的参数校验和白名单过滤")

    def _gen_sql_recommendation(self, lines: List[str]) -> str:
        """生成 SQL 安全建议。"""
        if self._check_patterns(lines, _ORM_PATTERNS):
            return "已检测到 ORM 框架使用，确保不使用原生 SQL 拼接；使用参数化查询 API"
        if self._check_patterns(lines, _PARAMETERIZATION_PATTERNS):
            return "已检测到参数化查询，确认所有用户输入都通过占位符传递"
        return "使用参数化查询（PreparedStatement / cursor.execute(sql, params) / db.Query(sql, args...)）替代字符串拼接"

    def clear_cache(self) -> None:
        """清理文件读取缓存。"""
        self._file_cache.clear()


# 全局单例
_global_ast_enricher: Optional[ASTEnricherService] = None


def get_global_ast_enricher() -> ASTEnricherService:
    """获取全局 AST 增强分析器单例。"""
    global _global_ast_enricher
    if _global_ast_enricher is None:
        _global_ast_enricher = ASTEnricherService()
    return _global_ast_enricher
