# -*- coding: utf-8 -*-
"""语言审计规则 —— 整合自 gbt-codeagent。"""

from typing import Dict, List

# 语言支持的漏洞类型映射
LANGUAGE_VULN_MAP: Dict[str, List[str]] = {
    "java": [
        "COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL",
        "XSS", "XXE", "DESERIALIZATION", "SSRF", "AUTH_BYPASS", "WEAK_CRYPTO",
        "SPEL_INJECTION", "JNDI_INJECTION", "SSTI", "LOG_INJECTION",
        "OPEN_REDIRECT", "IDOR", "AUTH_MISSING", "INFO_LEAK", "FILE_UPLOAD",
        "CSRF", "INSECURE_RANDOM", "COOKIE_SECURITY", "BUSINESS_LOGIC",
        "MASS_ASSIGNMENT", "REGEX_DOS", "IDEMPOTENCY",
    ],
    "python": [
        "COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL",
        "DESERIALIZATION", "SSRF", "WEAK_CRYPTO", "HARD_CODE_PASSWORD",
        "SSTI", "LOG_INJECTION", "OPEN_REDIRECT", "XXE", "XSS", "IDOR",
        "FILE_UPLOAD", "AUTH_MISSING", "INSECURE_RANDOM", "COOKIE_SECURITY",
        "BUSINESS_LOGIC", "MASS_ASSIGNMENT", "REGEX_DOS", "IDEMPOTENCY",
    ],
    "javascript": [
        "COMMAND_INJECTION", "SQL_INJECTION", "XSS", "SSRF", "OPEN_REDIRECT",
        "CSRF", "PATH_TRAVERSAL", "CODE_INJECTION", "DESERIALIZATION",
        "SSTI", "LOG_INJECTION", "XXE", "IDOR", "FILE_UPLOAD",
        "AUTH_MISSING", "INSECURE_RANDOM", "COOKIE_SECURITY",
        "MASS_ASSIGNMENT", "REGEX_DOS",
    ],
    "typescript": [
        "COMMAND_INJECTION", "SQL_INJECTION", "XSS", "SSRF", "OPEN_REDIRECT",
        "CSRF", "PATH_TRAVERSAL", "CODE_INJECTION", "DESERIALIZATION",
        "SSTI", "LOG_INJECTION", "XXE", "IDOR", "FILE_UPLOAD",
        "AUTH_MISSING", "INSECURE_RANDOM", "COOKIE_SECURITY",
        "MASS_ASSIGNMENT", "REGEX_DOS",
    ],
    "go": [
        "COMMAND_INJECTION", "SQL_INJECTION", "PATH_TRAVERSAL", "SSRF",
        "WEAK_CRYPTO", "CODE_INJECTION", "SSTI", "OPEN_REDIRECT",
        "XXE", "XSS", "INSECURE_RANDOM",
    ],
    "cpp": [
        "COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL",
        "BUFFER_OVERFLOW", "FORMAT_STRING", "INTEGER_OVERFLOW", "LOG_INJECTION",
        "INFO_LEAK", "INSECURE_RANDOM",
    ],
    "csharp": [
        "COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL",
        "DESERIALIZATION", "XSS", "SSRF", "XXE", "OPEN_REDIRECT",
        "SSTI", "LOG_INJECTION", "CSRF", "IDOR", "FILE_UPLOAD",
        "INSECURE_RANDOM", "COOKIE_SECURITY",
    ],
    "php": [
        "COMMAND_INJECTION", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "SSRF",
        "CODE_INJECTION", "DESERIALIZATION", "OPEN_REDIRECT", "CSRF", "XXE",
        "SSTI", "LOG_INJECTION", "FILE_UPLOAD", "INSECURE_RANDOM",
        "MAIL_INJECTION",
    ],
    "ruby": [
        "COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL",
        "SSRF", "DESERIALIZATION", "XSS", "XXE", "OPEN_REDIRECT",
        "SSTI", "INSECURE_RANDOM",
    ],
    "rust": [
        "COMMAND_INJECTION", "SQL_INJECTION", "PATH_TRAVERSAL", "SSRF",
        "CODE_INJECTION", "SSTI", "OPEN_REDIRECT", "INSECURE_RANDOM",
    ],
}

# 语言特定审计规则
LANGUAGE_AUDIT_RULES: Dict[str, Dict] = {
    "java": {
        "null_safety": {
            "description": "Null Safety",
            "checks": [
                "Method calls on potentially-null return values without null check",
                "Auto-unboxing of nullable wrapper types",
            ],
            "skip_if": ["Optional used", "@Nullable annotated + checked", "null-guard present"],
        },
        "thread_safety": {
            "description": "Thread Safety",
            "checks": [
                "Check-then-act patterns, lazy init without double-check locking",
            ],
            "skip_if": ["method-local variables", "immutable objects", "final fields", "single-thread components"],
        },
        "resource": {
            "description": "Resource & Performance",
            "checks": [
                "Stream/Connection/Reader not in try-with-resources",
                "DB query inside loop (N+1)",
            ],
            "skip_if": ["try-with-resources", "framework-managed resources", "known-small data"],
        },
        "framework": {
            "description": "Framework",
            "checks": [
                "Spring: @Transactional on private methods, missing @PreAuthorize",
                "MyBatis: ${} vs #{} — flag ${} for user-controlled params",
                "JPA: JPQL concatenation instead of parameter binding",
            ],
        },
    },
    "javascript": {
        "injection": {
            "description": "Injection & Execution",
            "checks": [
                "eval() / Function() / setTimeout(string) / setInterval(string)",
                "innerHTML / insertAdjacentHTML with user content — XSS",
                "document.write()",
            ],
            "skip_if": ["textContent", "DOMPurify", "hardcoded content"],
        },
        "prototype_pollution": {
            "description": "Prototype Pollution",
            "checks": [
                "Object.assign / _.merge / spread into target from user input without __proto__ filtering",
            ],
            "skip_if": ["Object.create(null)", "sanitized against __proto__/constructor"],
        },
        "nodejs": {
            "description": "Node.js (server-side)",
            "checks": [
                "child_process.exec() with user input — command injection",
                "fs with user-controlled paths — path traversal",
                "require() with dynamic paths — code injection",
            ],
            "skip_if": ["execFile() with args array", "path.resolve() + allowlist"],
        },
    },
    "python": {
        "execution": {
            "description": "Execution & Injection",
            "checks": [
                "eval()/exec()/compile() with user input — critical",
                "os.system()/subprocess.call(shell=True) — command injection",
                "pickle.load()/yaml.load() on untrusted data — deserialization",
            ],
            "skip_if": ["subprocess.run(args=[])", "yaml.safe_load()", "json.loads()", "ast.literal_eval()"],
        },
        "path_traversal": {
            "description": "Path Traversal",
            "checks": [
                "open(user_input), os.path.join(user_input) without sanitization",
            ],
            "skip_if": ["pathlib.Path.resolve() checked", "UUID-generated filename"],
        },
        "template_injection": {
            "description": "Template Injection",
            "checks": [
                "render_template_string(user_input) in Flask/Jinja2",
            ],
            "skip_if": ["template source from file only"],
        },
        "framework": {
            "description": "Framework",
            "checks": [
                "Django: DEBUG=True, SECRET_KEY hardcoded, ALLOWED_HOSTS=['*'], @csrf_exempt",
            ],
            "skip_if": ["DEBUG from env", "SECRET_KEY from secrets manager"],
        },
    },
    "go": {
        "error_handling": {
            "description": "Error Handling",
            "checks": [
                "Error returned but unchecked (_ assigned)",
                "panic() in library/handler code",
            ],
            "skip_if": ["intentional ignore with comment", "defer cleanup"],
        },
        "concurrency": {
            "description": "Concurrency",
            "checks": [
                "Goroutine leak (no cancellation/done channel)",
                "Data race (shared variable, no sync.Mutex/atomic)",
                "WaitGroup.Add() inside goroutine",
            ],
            "skip_if": ["context.Context cancellation", "-race tested", "single-goroutine"],
        },
        "security": {
            "description": "Security",
            "checks": [
                "template.HTML(userInput) in html/template — XSS",
                "os/exec.Command('sh', '-c', userInput) — command injection",
                "math/rand for tokens/session IDs — use crypto/rand",
                "MD5/SHA1 for password hashing — use bcrypt/argon2",
            ],
            "skip_if": ["html/template auto-escaping", "exec.Command with args array", "crypto/rand"],
        },
    },
    "php": {
        "injection": {
            "description": "Injection",
            "checks": [
                "system/exec/shell_exec/passthru with user input",
                "mysqli_query(拼接), PDO::query(拼接)",
                "include/require(动态路径)",
                "unserialize(用户输入)",
            ],
            "skip_if": ["escapeshellcmd/arg", "PDO::prepare + bindValue", "白名单, basename", "json_decode"],
        },
    },
    "cpp": {
        "memory_safety": {
            "description": "Memory Safety",
            "checks": [
                "sprintf/strcpy/strcat/gets(无边界)",
                "system/popen/execl with user input",
                "fopen/open(用户可控路径)",
            ],
            "skip_if": ["snprintf/strncpy(有边界)", "realpath"],
        },
    },
    "csharp": {
        "injection": {
            "description": "Injection",
            "checks": [
                "Process.Start(用户输入)",
                "SqlCommand 拼接",
                "File.ReadAllText/WriteAllText(用户可控)",
                "HttpClient.GetAsync(用户可控 URL)",
                "BinaryFormatter, SoapFormatter",
            ],
            "skip_if": ["ProcessStartInfo + args", "SqlParameter", "Path.GetFullPath/Combine", "URL 白名单", "类型白名单"],
        },
    },
}

# 代码质量规则（从 open-code-review 借鉴）
CODE_QUALITY_RULES = {
    "dead_code": {
        "description": "Dead Code Detection",
        "checks": [
            "Unreachable code (condition always false, code after return/throw)",
            "Unused variables (declared but never read)",
            "Large blocks of commented-out code (no preservation intent)",
            "Empty loop bodies",
        ],
        "severity": "medium",
    },
    "spelling": {
        "description": "Spelling Errors",
        "checks": [
            "Spelling errors in variable/function/class names at declaration sites",
            "Spelling errors in log messages or exception messages",
            "Spelling errors in user-visible text",
        ],
        "severity": "low",
    },
}

# 代码质量规则文件路径
CODE_QUALITY_RULES_PATH = "src/knowledge/config_reference/rules/code_quality/"
