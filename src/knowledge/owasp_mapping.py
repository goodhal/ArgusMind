# -*- coding: utf-8 -*-
"""OWASP Top 10 映射 —— 整合自 gbt-codeagent。"""

# 漏洞类型 -> OWASP Top 10 2021 映射
OWASP_MAPPING: dict[str, list[str]] = {
    "SQL_INJECTION": ["A03:2021"],
    "SQL_INJECTION_MYBATIS": ["A03:2021"],
    "SQL_INJECTION_ORDERBY": ["A03:2021"],
    "SQL_INJECTION_GROUPBY": ["A03:2021"],
    "SQL_INJECTION_HQL": ["A03:2021"],
    "COMMAND_INJECTION": ["A03:2021"],
    "CODE_INJECTION": ["A03:2021"],
    "SPEL_INJECTION": ["A03:2021"],
    "SSTI": ["A03:2021"],
    "JNDI_INJECTION": ["A03:2021"],
    "XSS": ["A03:2021"],
    "XSS_REFLECTED": ["A03:2021"],
    "XSS_STORED": ["A03:2021"],
    "XPATH_INJECTION": ["A03:2021"],
    "FORMAT_STRING": ["A03:2021"],
    "FORMAT_STRING_VULNERABILITY": ["A03:2021"],
    "LOG_INJECTION": ["A03:2021"],
    "PATH_TRAVERSAL": ["A01:2021"],
    "ARBITRARY_FILE_READ": ["A01:2021"],
    "FILE_READ": ["A01:2021"],
    "SSRF": ["A10:2021"],
    "FILE_UPLOAD": ["A04:2021"],
    "UNRESTRICTED_FILE_UPLOAD": ["A04:2021"],
    "INSECURE_FILE_VALIDATION": ["A04:2021"],
    "WEAK_CRYPTO": ["A02:2021"],
    "WEAK_HASH": ["A02:2021"],
    "RSA_WEAK_PADDING": ["A02:2021"],
    "HARD_CODE_PASSWORD": ["A02:2021"],
    "HARDCODED_CREDENTIALS": ["A07:2021"],
    "PLAINTEXT_PASSWORD": ["A02:2021"],
    "PLAINTEXT_TRANSMISSION": ["A02:2021"],
    "PREDICTABLE_RANDOM": ["A02:2021"],
    "WEAK_RANDOM": ["A02:2021"],
    "HASH_WITHOUT_SALT": ["A02:2021"],
    "WEAK_PASSWORD_POLICY": ["A07:2021"],
    "INSECURE_COOKIE_AUTH": ["A07:2021"],
    "DESERIALIZATION": ["A08:2021"],
    "AUTH_BYPASS": ["A07:2021"],
    "AUTH_BYPASS_URI": ["A07:2021"],
    "AUTH_BYPASS_SUFFIX": ["A07:2021"],
    "AUTH_BYPASS_SPRING": ["A07:2021"],
    "AUTH_CSRF_DISABLED": ["A01:2021"],
    "AUTH_INFO_EXPOSURE": ["A07:2021"],
    "AUTH_SERVLETPATH_SAFE": ["A07:2021"],
    "REFERER_AUTH_BYPASS": ["A07:2021"],
    "IDOR": ["A01:2021"],
    "MISSING_ACCESS_CONTROL": ["A01:2021"],
    "SESSION_FIXATION": ["A07:2021"],
    "COOKIE_MANIPULATION": ["A07:2021"],
    "CSRF": ["A01:2021"],
    "CSRF_MISSING": ["A01:2021"],
    "CSRF_DISABLED": ["A01:2021"],
    "CSRF_PROTECTION": ["A01:2021"],
    "INFO_LEAK": ["A01:2021"],
    "INFORMATION_DISCLOSURE": ["A01:2021"],
    "EXCEPTION_INFO_LEAK": ["A01:2021"],
    "ASSERT_MISUSE": ["A05:2021"],
    "IMPROPER_EXCEPTION_HANDLING": ["A05:2021"],
    "INFINITE_LOOP": ["A05:2021"],
    "OPEN_REDIRECT": ["A01:2021"],
    "CORS_MISCONFIGURATION": ["A05:2021"],
    "RACE_CONDITION": ["A05:2021"],
    "BUFFER_OVERFLOW": ["A03:2021"],
    "INTEGER_OVERFLOW": ["A03:2021"],
    "UNCONTROLLED_MEMORY": ["A03:2021"],
    "PROCESS_CONTROL": ["A03:2021"],
    "NO_RATE_LIMIT": ["A07:2021"],
    "BLACKLIST_VALIDATION": ["A03:2021"],
    "SWAGGER_EXPOSURE": ["A05:2021"],
    "STRUTS_WILDCARD": ["A05:2021"],
    "COMPONENT_VULNERABILITY": ["A06:2021"],
    "XXE": ["A03:2021"],
}

# OWASP Top 10 2021 中文名称映射
OWASP_NAMES: dict[str, str] = {
    "A01:2021": "失效的访问控制",
    "A02:2021": "加密机制失效",
    "A03:2021": "注入",
    "A04:2021": "不安全的设计",
    "A05:2021": "安全配置错误",
    "A06:2021": "易受攻击和过时的组件",
    "A07:2021": "身份认证与授权失效",
    "A08:2021": "软件和数据完整性失效",
    "A09:2021": "安全日志和监控失败",
    "A10:2021": "服务端请求伪造",
}

# 中文 vuln_type 别名 -> 标准英文 key（用于 OWASP_MAPPING 查找）
_CN_ALIASES: dict[str, str] = {
    "路径遍历": "PATH_TRAVERSAL",
    "命令注入": "COMMAND_INJECTION",
    "SQL注入": "SQL_INJECTION",
    "SQL 注入": "SQL_INJECTION",
    "日志注入": "LOG_INJECTION",
    "信息泄漏": "INFORMATION_DISCLOSURE",
    "信息泄露": "INFORMATION_DISCLOSURE",
    "开放重定向": "OPEN_REDIRECT",
    "弱加密算法": "WEAK_CRYPTO",
    "弱哈希算法": "WEAK_HASH",
    "使用不安全的加密算法": "WEAK_CRYPTO",
    "资源泄漏": "RACE_CONDITION",
    "权限控制缺失": "MISSING_ACCESS_CONTROL",
    "跨站脚本": "XSS",
    "跨站请求伪造": "CSRF",
    "文件上传": "FILE_UPLOAD",
    "反序列化": "DESERIALIZATION",
    "硬编码凭证": "HARDCODED_CREDENTIALS",
    "硬编码密码": "HARD_CODE_PASSWORD",
    "不安全的随机数": "WEAK_RANDOM",
    "XXE注入": "XXE",
    "SSRF": "SSRF",
    "业务逻辑缺陷": "BUSINESS_LOGIC",
}

# CWE 编号 -> OWASP Top 10 2021 映射（反向查找）
CWE_TO_OWASP: dict[str, list[str]] = {
    # 注入类
    "CWE-78": ["A03:2021"],   # OS Command Injection
    "CWE-77": ["A03:2021"],   # Command Injection
    "CWE-89": ["A03:2021"],   # SQL Injection
    "CWE-90": ["A03:2021"],   # LDAP Injection
    "CWE-79": ["A03:2021"],   # XSS
    "CWE-91": ["A03:2021"],   # XPath Injection
    "CWE-94": ["A03:2021"],   # Code Injection
    "CWE-95": ["A03:2021"],   # Eval Injection
    "CWE-98": ["A03:2021"],   # File Include
    "CWE-113": ["A03:2021"],  # HTTP Response Splitting
    "CWE-116": ["A03:2021"],  # Improper Encoding
    "CWE-117": ["A03:2021"],  # Log Injection
    "CWE-120": ["A03:2021"],  # Buffer Overflow
    "CWE-131": ["A03:2021"],  # Incorrect Buffer Size
    "CWE-134": ["A03:2021"],  # Format String
    "CWE-190": ["A03:2021"],  # Integer Overflow
    "CWE-601": ["A10:2021"],  # Open Redirect -> SSRF category
    "CWE-918": ["A10:2021"],  # SSRF
    # 访问控制
    "CWE-22": ["A01:2021"],   # Path Traversal
    "CWE-23": ["A01:2021"],   # Relative Path Traversal
    "CWE-35": ["A01:2021"],   # Path Traversal
    "CWE-200": ["A01:2021"],  # Information Exposure
    "CWE-201": ["A01:2021"],  # Sensitive Data Exposure
    "CWE-209": ["A01:2021"],  # Information Exposure Through Error Messages
    "CWE-213": ["A01:2021"],  # Exposure of Sensitive Information
    "CWE-284": ["A01:2021"],  # Improper Access Control
    "CWE-285": ["A01:2021"],  # Improper Authorization
    "CWE-287": ["A07:2021"],  # Improper Authentication
    "CWE-306": ["A07:2021"],  # Missing Authentication
    "CWE-307": ["A07:2021"],  # Improper Restriction of Excessive Authentication
    "CWE-384": ["A07:2021"],  # Session Fixation
    "CWE-598": ["A07:2021"],  # GET Request with Sensitive Info
    "CWE-639": ["A01:2021"],  # IDOR
    "CWE-862": ["A01:2021"],  # Missing Authorization
    "CWE-863": ["A01:2021"],  # Incorrect Authorization
    # 加密
    "CWE-327": ["A02:2021"],  # Broken Crypto
    "CWE-328": ["A02:2021"],  # Weak Hash
    "CWE-321": ["A02:2021"],  # Hard-coded Crypto Key
    "CWE-311": ["A02:2021"],  # Missing Encryption
    "CWE-326": ["A02:2021"],  # Inadequate Encryption
    "CWE-798": ["A07:2021"],  # Hard-coded Credentials
    "CWE-259": ["A07:2021"],  # Hard-coded Password
    # 配置错误
    "CWE-16": ["A05:2021"],   # Configuration
    "CWE-209": ["A05:2021"],  # Information Exposure Through Error
    "CWE-250": ["A05:2021"],  # Excessive Privileges
    "CWE-404": ["A05:2021"],  # Improper Resource Shutdown
    "CWE-434": ["A04:2021"],  # Unrestricted File Upload
    "CWE-674": ["A04:2021"],  # Uncontrolled Recursion -> Insecure Design
    "CWE-682": ["A04:2021"],  # Incorrect Calculation -> Insecure Design
    "CWE-841": ["A04:2021"],  # Improper Enforcement of Behavioral Workflow
    # 组件漏洞
    "CWE-1035": ["A06:2021"], # OWASP Top 10 2017 Category
    "CWE-1104": ["A06:2021"], # Use of Vulnerable Third-Party Component
    # 日志与监控
    "CWE-223": ["A09:2021"],  # Omission of Security-Relevant Info
    "CWE-532": ["A09:2021"],  # Log File Exposure
    "CWE-778": ["A09:2021"],  # Insufficient Logging
    # 完整性
    "CWE-494": ["A08:2021"],  # Download of Code Without Integrity Check
    "CWE-502": ["A08:2021"],  # Deserialization
    "CWE-829": ["A08:2021"],  # Inclusion of Functionality from Untrusted Control Sphere
    # 并发
    "CWE-362": ["A04:2021"],  # Race Condition -> Insecure Design
}
