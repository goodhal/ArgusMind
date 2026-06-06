"""ArgusMind 分析器常量模块

整合自 code-review-graph 项目的安全关键词和配置常量
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# 安全关键词
# ---------------------------------------------------------------------------
SECURITY_KEYWORDS: frozenset[str] = frozenset({
    "auth", "login", "password", "token", "session", "crypt", "secret",
    "credential", "permission", "sql", "query", "execute", "connect",
    "socket", "request", "http", "sanitize", "validate", "encrypt",
    "decrypt", "hash", "sign", "verify", "admin", "privilege",
    "eval", "exec", "system", "popen", "subprocess", "os.system",
    "pickle", "unpickle", "deserialize", "yaml.load", "jsonpickle",
    "template", "render", "jinja", "mustache", "template_injection",
    "xss", "csrf", "ssrf", "xxe", "path_traversal", "file_read",
    "file_write", "command_injection", "sql_injection", "injection",
})

# ---------------------------------------------------------------------------
# 风险评分权重配置
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    "flow_participation": 0.25,  # 流参与度最大权重
    "cross_community": 0.15,     # 社区交叉最大权重
    "test_coverage_base": 0.30,  # 测试覆盖基准权重
    "security_sensitive": 0.20,  # 安全敏感权重
    "caller_count": 0.10,        # 调用者数量最大权重
}

# ---------------------------------------------------------------------------
# 可配置限制（通过环境变量覆盖）
# ---------------------------------------------------------------------------
MAX_IMPACT_NODES = int(os.environ.get("ARGUS_MAX_IMPACT_NODES", "500"))
MAX_IMPACT_DEPTH = int(os.environ.get("ARGUS_MAX_IMPACT_DEPTH", "2"))
MAX_SEARCH_RESULTS = int(os.environ.get("ARGUS_MAX_SEARCH_RESULTS", "20"))
MAX_CHANGED_FUNCS = int(os.environ.get("ARGUS_MAX_CHANGED_FUNCS", "500"))

# ---------------------------------------------------------------------------
# 严重性级别
# ---------------------------------------------------------------------------
SEVERITY_LEVELS = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.1,
    "info": 0.0,
}
