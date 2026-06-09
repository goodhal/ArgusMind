# -*- coding: utf-8 -*-
"""审计覆盖率追踪器 —— 整合自 gbt-codeagent/services/coverageService.js。

追踪哪些文件和攻击类型已被审查，发现盲区并生成定向审查任务。
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# 配置日志记录
logger = logging.getLogger(__name__)


# 代码文件扩展名
_CODE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".rs", ".kt",
    ".scala", ".swift", ".m", ".vue", ".svelte",
}


def _normalize_path(p: str) -> str:
    """统一路径分隔符为 /，去除首尾空白和行号。
    
    注意：只去除行号部分（格式: path:行号），保留 Windows 盘符（如 C:）。
    
    Args:
        p: 原始路径
        
    Returns:
        规范化后的路径
    """
    if not isinstance(p, str):
        logger.warning(f"路径不是字符串类型: {type(p)}")
        return str(p).strip().replace("\\", "/")
    
    normalized = p.strip().replace("\\", "/")
    
    # 只去除行号部分（格式: path:数字），保留 Windows 盘符（如 C:）
    # 使用正则表达式匹配末尾的 :数字 模式
    normalized = re.sub(r":\d+$", "", normalized)
    
    return normalized


def _is_code_file(path: str) -> bool:
    """判断是否为代码文件。"""
    ext = os.path.splitext(path)[1].lower()
    return ext in _CODE_EXTENSIONS


def _extract_subsystem(path: str) -> str:
    """从文件路径提取子系统（前两级目录）。"""
    parts = _normalize_path(path).split("/")
    # 跳过 src / app 等常见顶层目录
    skip = {"src", "app", "lib", "pkg", "internal", "cmd", "web", "server", "client"}
    meaningful = [p for p in parts[:-1] if p and p not in skip]
    return "/".join(meaningful[:2]) if meaningful else "root"


def _to_relative_path(file_path: str, project_path: str) -> str:
    """
    将文件路径转换为项目相对路径。
    
    参考 gbt-codeagent 的 toRelative 函数：
    - 如果是绝对路径，截取 project_path 后的部分
    - 如果路径已包含行号，先去除行号
    - 统一使用 / 作为路径分隔符
    
    Args:
        file_path: 文件路径（可能是绝对路径、相对路径或带行号的路径）
        project_path: 项目根目录路径
    
    Returns:
        项目相对路径
    """
    # 先去除行号
    normalized_file = _normalize_path(file_path)
    normalized_project = _normalize_path(project_path)
    
    # 确保项目路径以 / 结尾，方便截取
    if not normalized_project.endswith("/"):
        normalized_project += "/"
    
    # 如果是绝对路径，截取 project_path 后的部分
    if normalized_file.startswith(normalized_project):
        relative = normalized_file[len(normalized_project):]
        return relative
    
    # 如果文件路径包含项目路径（但格式略有不同），尝试匹配最后几级
    if normalized_project in normalized_file:
        idx = normalized_file.find(normalized_project)
        relative = normalized_file[idx + len(normalized_project):]
        return relative.lstrip("/")
    
    # fallback: 返回规范化后的原始路径（去除行号）
    return normalized_file


# 已知的攻击类型清单
ALL_ATTACK_CLASSES: List[str] = [
    "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "DESERIALIZATION",
    "XSS", "SSRF", "XXE", "PATH_TRAVERSAL", "AUTH_BYPASS", "IDOR",
    "HARD_CODED_SECRET", "WEAK_CRYPTO", "INFO_LEAK", "FILE_UPLOAD",
    "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "SESSION_FIXATION",
    "CORS_MISCONFIGURATION", "OPEN_REDIRECT", "LOG_INJECTION", "REDOS",
]

# 扩展名 → 适用的攻击类型
_EXTENSION_ATTACK_CLASSES: Dict[str, List[str]] = {
    ".java": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "SSRF", "XXE",
              "AUTH_BYPASS", "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "IDOR"],
    ".py": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "PATH_TRAVERSAL",
            "SSRF", "SSTI", "CODE_INJECTION"],
    ".js": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
            "SSRF", "CODE_INJECTION", "PROTOTYPE_POLLUTION"],
    ".ts": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
            "SSRF", "CODE_INJECTION"],
    ".go": ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION"],
    ".php": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
             "FILE_UPLOAD", "DESERIALIZATION"],
    ".cs": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "XSS", "AUTH_BYPASS"],
    ".cpp": ["COMMAND_INJECTION", "BUFFER_OVERFLOW", "PATH_TRAVERSAL", "CODE_INJECTION"],
    ".c": ["COMMAND_INJECTION", "BUFFER_OVERFLOW", "PATH_TRAVERSAL", "CODE_INJECTION"],
}

# Sink 关键词映射（用于盲区搜索）
# 参考 gbt-codeagent coverageService.js 扩展
_SINK_KEYWORDS: Dict[str, List[str]] = {
    "SQL_INJECTION": [
        "executeQuery", "executeUpdate", "createQuery", "Statement",
        "PreparedStatement", "JdbcTemplate", "query(", "execute(",
        "NamedParameterJdbcTemplate", "EntityManager", "nativeQuery",
        "createNativeQuery", "RawQuery", "cursor.execute", "db.query",
        "db.execute", "sqlalchemy", "psycopg", "sqlite3", "mysql.connector"
    ],
    "COMMAND_INJECTION": [
        "Runtime.getRuntime", "ProcessBuilder", "exec(", "ProcessImpl",
        "os.system", "subprocess", "subprocess.run", "subprocess.Popen",
        "shell=True", "execve", "fork", "spawn", "system(", "popen(",
        "command.Command", "shlex", "popen2", "popen3", "popen4"
    ],
    "DESERIALIZATION": [
        "readObject", "ObjectInputStream", "Yaml.load", "parseObject",
        "readValue", "fromJson", "pickle.load", "json.loads", "marshal.load",
        "unpickle", "serpent.load", "msgpack.unpackb", "cPickle.load",
        "Jackson", "Gson", "ObjectMapper", "Serializer", "deserialize",
        "protobuf", "Avro", "Kryo", "Fastjson"
    ],
    "PATH_TRAVERSAL": [
        "FileInputStream", "FileOutputStream", "File(", "Files.read",
        "Paths.get", "os.path.join", "open(", "with open(", "file(",
        "os.walk", "glob.glob", "pathlib", "Path(", "os.listdir",
        "os.scandir", "shutil.copy", "shutil.move", "send_file"
    ],
    "SSRF": [
        "HttpClient", "RestTemplate", "URL.openConnection", "fetch(",
        "WebClient", "requests.get", "requests.post", "urllib.request",
        "urllib2", "httplib", "http.client", "socket.socket", "urllib3",
        "aiohttp", "curl", "wget", "urlopen", "socket.connect",
        "InetAddress.getByName", "DNS.lookup", "netcat", "nc -zv"
    ],
    "SSTI": [
        "Thymeleaf", "templateEngine", "process(", "FreeMarker", "Velocity",
        "Jinja2", "render_template", "template.render", "eval(", "exec(",
        "JSP", "PHP", "ERB", "Mustache", "Handlebars", "React.render",
        "Vue.compile", "EJS", "Pug", "Nunjucks", "Twig"
    ],
    "JNDI_INJECTION": [
        "InitialContext", "lookup(", "JNDI", "Context.lookup",
        "new InitialContext", "NamingEnumeration", "DirContext",
        "LdapContext", "LDAP", "RMI", "CORBA", "IIOP"
    ],
    "XSS": [
        "innerHTML", "document.write", "eval(", "setTimeout(", "setInterval(",
        "new Function(", "location.href", "document.location", "window.open",
        "JSONP", "evalJSONP", "script.src", "createElement('script')",
        "appendChild", "insertBefore", "outerHTML", "insertAdjacentHTML",
        "document.cookie", "sessionStorage", "localStorage"
    ],
    "AUTH_BYPASS": [
        "SecurityContext", "Authentication", "Principal", "UserDetails",
        "JwtDecoder", "TokenValidator", "decodeJwt", "verifyToken",
        "isAuthenticated", "hasRole", "hasAuthority", "permitAll",
        "denyAll", "AnonymousAuthentication", "RememberMeAuthentication",
        "BasicAuthenticationFilter", "JwtAuthenticationFilter"
    ],
    "IDOR": [
        "PathVariable", "RequestParam", "getParameter", "PathVariable",
        "user_id", "account_id", "order_id", "resource_id", "item_id",
        "file_id", "document_id", "record_id", "id=", "uuid=", "uid="
    ],
    "FILE_UPLOAD": [
        "MultipartFile", "FileUpload", "transferTo", "save(", "write(",
        "upload(", "file.save", "fs.writeFile", "fs.writeFileSync",
        "move_uploaded_file", "file_get_contents", "file_put_contents",
        "tmpfile", "tempfile", "NamedTemporaryFile"
    ],
    "WEAK_CRYPTO": [
        "MD5", "SHA-1", "DES", "3DES", "RC4", "Base64", "Base64.encode",
        "Base64.decode", "MD5CryptoServiceProvider", "TripleDES",
        "WeakKey", "ECB", "CBC", "NoPadding", "PBEWithMD5AndDES",
        "CryptoStream", "HashAlgorithm", "MessageDigest"
    ],
    "INFO_LEAK": [
        "printStackTrace", "System.out.println", "console.log", "Logger.debug",
        "log.debug", "log.info", "log.warn", "log.error", "Exception.printStackTrace",
        "traceback.print_exc", "logging.debug", "logging.info", "sys.stdout",
        "response.sendError", "error.printStackTrace", "dumpStack"
    ],
    "CORS_MISCONFIGURATION": [
        "CorsConfiguration", "addAllowedOrigin", "setAllowedOrigins",
        "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
        "*", "allowedOrigins", "cors.allowed_origins", "app.use(cors())",
        "CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"
    ],
    "OPEN_REDIRECT": [
        "redirect(", "sendRedirect", "response.redirect", "res.redirect",
        "Location:", "window.location", "location.href", "response.setHeader",
        "HttpServletResponse", "redirectTo", "forward(", "encodeRedirectURL"
    ],
    "LOG_INJECTION": [
        "Logger.log", "log(", "logger.info", "logger.debug", "logger.warn",
        "logger.error", "System.out", "System.err", "console.log",
        "logging.info", "logging.debug", "log4j", "slf4j", "logback"
    ],
}

# Tier 分类正则（参考 gbt-codeagent 扩展）
# T1: 入口层 - 直接处理用户输入的文件
_T1_PATTERNS = [re.compile(p, re.I) for p in [
    r"controller", r"filter", r"interceptor", r"gateway",
    r"securityconfig", r"webconfig", r"route", r"router",
    r"handler", r"endpoint", r"api", r"restcontroller",
    r"servlet", r"resource", r"controlleradvice", r"exceptionhandler"
]]

# T2: 业务层 - 核心业务逻辑文件
_T2_PATTERNS = [re.compile(p, re.I) for p in [
    r"service", r"dao", r"mapper", r"repository", r"util",
    r"helper", r"manager", r"handler", r"config", r"business",
    r"core", r"common", r"component", r"facade", r"serviceimpl",
    r"provider", r"consumer", r"client", r"adapter", r"converter",
    r"transformer", r"processor", r"generator", r"builder", r"factory"
]]

# T3: 数据层 - 数据模型和传输对象
_T3_PATTERNS = [re.compile(p, re.I) for p in [
    r"entity", r"dto", r"vo", r"pojo", r"model", r"domain",
    r"bean", r"object", r"data", r"record", r"struct",
    r"schema", r"type", r"enum", r"constant", r"configurationproperties"
]]

# 高信号文件模式（参考 gbt-codeagent isHighSignalFile）
_HIGH_SIGNAL_PATTERN = re.compile(
    r"(controller|service|dao|repository|handler|route|auth|security|"
    r"admin|api|endpoint|upload|file|config|util|filter|interceptor|"
    r"gateway|web|rest|servlet)",
    re.I,
)


def _classify_tier(file_path: str) -> str:
    """将文件按重要性分为 T1/T2/T3。
    
    参考 gbt-codeagent 的 getTier 函数：
    - T1: 入口层文件（Controller、Filter、Interceptor 等）
    - T2: 业务层文件（Service、DAO、Util 等）
    - T3: 数据层文件（Entity、DTO、VO 等）
    
    Args:
        file_path: 文件路径
    
    Returns:
        Tier 分类（T1/T2/T3）
    """
    if not file_path:
        return "T2"
    
    lower = file_path.lower()
    basename = lower.split("/")[-1] if "/" in lower else lower
    
    # 先检查文件名（basename）
    for p in _T1_PATTERNS:
        if p.search(basename):
            return "T1"
    for p in _T2_PATTERNS:
        if p.search(basename):
            return "T2"
    for p in _T3_PATTERNS:
        if p.search(basename):
            return "T3"
    
    # 如果文件名没有匹配，检查目录名
    dirname = lower.rsplit("/", 1)[0] if "/" in lower else ""
    if dirname:
        for p in _T1_PATTERNS:
            if p.search(dirname):
                return "T1"
        for p in _T2_PATTERNS:
            if p.search(dirname):
                return "T2"
        for p in _T3_PATTERNS:
            if p.search(dirname):
                return "T3"
    
    # 默认 T2
    return "T2"


class CoverageTracker:
    """审计覆盖率追踪器。

    追踪哪些文件被审查、哪些攻击类型被检查，
    并可生成覆盖率报告和盲区定向审查任务。

    增强功能（整合自 gbt-codeagent coverageService.js）：
    - 子系统覆盖率统计
    - 盲区计算（子系统 × 攻击类型矩阵）
    - Tier 分类（T1/T2/T3）
    - Sink 关键词搜索定向任务
    """

    def __init__(self, project_path: str, all_files: Optional[List[str]] = None) -> None:
        self._project_path = _normalize_path(project_path)
        self._reviewed_files: Set[str] = set()
        self._file_attack_classes: Dict[str, Set[str]] = {}
        self._all_files: Set[str] = set()

        if all_files:
            for f in all_files:
                # 使用统一的路径格式存储
                normalized = _normalize_path(f)
                self._all_files.add(normalized)

    def mark_reviewed(self, file_path: str, attack_class: str = "") -> None:
        """标记文件已被审查。

        Args:
            file_path: 文件路径（支持绝对路径、相对路径、带行号的路径）
            attack_class: 攻击类型（可选）
        """
        # 使用项目相对路径作为 key，确保与 _all_files 中的路径格式一致
        key = _to_relative_path(file_path, self._project_path)
        self._reviewed_files.add(key)
        if attack_class:
            self._file_attack_classes.setdefault(key, set()).add(attack_class)

    def mark_from_findings(self, findings: List[Dict[str, Any]]) -> None:
        """从发现列表批量标记已审查文件。

        参考 gbt-codeagent 的 markFromFindings 方法：
        - 优先使用 file 字段
        - 其次从 location 字段提取路径（去除行号）
        - 确保路径格式与项目文件列表一致

        Args:
            findings: 漏洞发现列表
        """
        for f in findings:
            # 优先用 file（纯路径），其次从 location 中剥离行号
            file_path = f.get("file", "")
            if not file_path:
                location = f.get("location", "")
                if ":" in location:
                    file_path = location.rsplit(":", 1)[0]
                else:
                    file_path = location

            vuln_class = f.get("vulnType", f.get("vuln_class", f.get("category_name", "")))
            
            if file_path:
                try:
                    self.mark_reviewed(file_path, vuln_class)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).warning(
                        f"[CoverageTracker] 标记文件失败: {file_path}, 错误: {e}"
                    )

    def generate_report(self) -> Dict[str, Any]:
        """生成覆盖率报告。

        参考 gbt-codeagent 的 generateReport 方法：
        - 覆盖率 = 已审查代码文件数 / 总代码文件数
        - 仅统计代码文件（排除配置、资源等非代码文件）
        - 按子系统分组统计
        - 识别高优先级未审查文件
        """
        # 仅统计代码文件作为分母
        code_files = [f for f in self._all_files if _is_code_file(f)]
        total_files = len(code_files) if code_files else 0
        
        # 统计实际审查过的文件数（确保路径格式一致）
        reviewed_count = 0
        reviewed_files_list = []
        for f in code_files:
            # 将 _all_files 中的路径转换为项目相对路径进行匹配
            relative_path = _to_relative_path(f, self._project_path)
            if relative_path in self._reviewed_files:
                reviewed_count += 1
                reviewed_files_list.append(f)

        unreviewed_code_files = [
            f for f in code_files
            if _to_relative_path(f, self._project_path) not in self._reviewed_files
        ]

        # 按子系统分组统计（仅代码文件）
        subsystem_coverage: Dict[str, Dict[str, int]] = {}
        for f in code_files:
            subsys = _extract_subsystem(f)
            if subsys not in subsystem_coverage:
                subsystem_coverage[subsys] = {"total": 0, "reviewed": 0}
            subsystem_coverage[subsys]["total"] += 1
            if _to_relative_path(f, self._project_path) in self._reviewed_files:
                subsystem_coverage[subsys]["reviewed"] += 1

        # 按子系统分组未审查文件
        subsystem_gaps: Dict[str, List[str]] = {}
        for f in unreviewed_code_files:
            subsys = _extract_subsystem(f)
            subsystem_gaps.setdefault(subsys, []).append(f)

        # 收集已审查的攻击类型
        reviewed_attack_classes: Set[str] = set()
        for classes in self._file_attack_classes.values():
            reviewed_attack_classes.update(classes)

        # 识别高优先级未审查文件
        high_priority_unreviewed = [
            f for f in unreviewed_code_files
            if _HIGH_SIGNAL_PATTERN.search(f)
        ][:20]

        # Tier 分类统计
        tier_stats: Dict[str, int] = {"T1": 0, "T2": 0, "T3": 0}
        for f in unreviewed_code_files:
            tier = _classify_tier(f)
            tier_stats[tier] = tier_stats.get(tier, 0) + 1

        coverage_rate = (reviewed_count / total_files * 100) if total_files > 0 else 0.0

        return {
            "total_files": total_files,
            "reviewed_files": reviewed_count,
            "unreviewed_code_files": len(unreviewed_code_files),
            "coverage_rate": round(coverage_rate, 1),
            "reviewed_attack_classes": sorted(reviewed_attack_classes),
            "subsystem_coverage": {
                k: v for k, v in sorted(
                    subsystem_coverage.items(), key=lambda x: -x[1]["total"]
                )
            },
            "subsystem_gaps": {
                k: len(v) for k, v in sorted(
                    subsystem_gaps.items(), key=lambda x: -len(x[1])
                )
            },
            "top_unreviewed": unreviewed_code_files[:20],
            "high_priority_unreviewed": high_priority_unreviewed,
            "tier_stats": tier_stats,
            "reviewed_files_list": reviewed_files_list,
        }

    def compute_blind_spots(
        self,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, str]]:
        """计算盲区：哪些子系统 × 攻击类型从未被检查。"""
        findings = findings or []
        report = self.generate_report()
        spots: List[Dict[str, str]] = []
        seen_keys: Set[str] = set()

        # 收集已覆盖的子系统
        reviewed_subsystems = set(report.get("subsystem_coverage", {}).keys())
        if not reviewed_subsystems:
            for f in findings:
                file_path = f.get("location", f.get("file", ""))
                reviewed_subsystems.add(_extract_subsystem(file_path))

        # 对每个子系统，找从未检查的攻击类型
        for sub in reviewed_subsystems:
            checked_classes: Set[str] = set()
            for f in findings:
                f_sub = _extract_subsystem(f.get("location", f.get("file", "")))
                f_type = f.get("vulnType", f.get("vuln_class", f.get("category_name", "")))
                if f_sub == sub and f_type:
                    checked_classes.add(f_type)

            for ac in ALL_ATTACK_CLASSES:
                key = f"{sub}|{ac}"
                if ac not in checked_classes and key not in seen_keys:
                    seen_keys.add(key)
                    spots.append({
                        "subsystem": sub,
                        "attackClass": ac,
                        "reason": "never_checked",
                    })

        # 对完全未审查的高优先级文件找可能适用的攻击类型
        for file_path in report.get("high_priority_unreviewed", [])[:5]:
            sub = _extract_subsystem(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            relevant_classes = _EXTENSION_ATTACK_CLASSES.get(ext, [])
            for ac in relevant_classes:
                key = f"{sub}|{ac}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    spots.append({
                        "subsystem": sub,
                        "attackClass": ac,
                        "targetFile": file_path,
                        "reason": "unreviewed_file",
                    })

        return spots[:20]

    def generate_gapfill_tasks(
        self,
        max_tasks: int = 5,
        findings: Optional[List[Dict[str, Any]]] = None,
        enable_llm_gapfill: bool = True,
    ) -> List[Dict[str, Any]]:
        """基于覆盖盲区生成定向审查任务（增强版）。

        整合自 gbt-codeagent 的 enhancedGapfill：
        1. 计算盲区
        2. 在未审查文件中搜索 sink 关键词（本地搜索）
        3. [可选] LLM 补充分析，识别本地搜索遗漏的潜在风险
        4. 生成定向审查任务

        Args:
            max_tasks: 最大生成任务数
            findings: 现有发现列表
            enable_llm_gapfill: 是否启用 LLM 补充分析

        Returns:
            定向审查任务列表
        """
        findings = findings or []
        blind_spots = self.compute_blind_spots(findings)
        tasks: List[Dict[str, Any]] = []

        report = self.generate_report()
        unreviewed_files = report.get("high_priority_unreviewed", [])

        # 阶段1: 本地 sink 关键词搜索
        logger.info(f"开始 Gapfill 分析: {len(blind_spots)} 个盲区, {len(unreviewed_files)} 个未审查文件")
        
        for spot in blind_spots[:max_tasks]:
            attack_class = spot.get("attackClass", "")
            keywords = _SINK_KEYWORDS.get(attack_class, [])
            if not keywords:
                # 无 sink 关键词的盲区，生成通用审查任务
                tasks.append({
                    "type": "blind_spot",
                    "subsystem": spot.get("subsystem", ""),
                    "attack_class": attack_class,
                    "reason": f"子系统 {spot.get('subsystem', '')} 的 {attack_class} 从未被审查",
                    "priority": 2,
                })
                continue

            # 在未审查文件中搜索 sink 关键词
            target_files = [spot.get("targetFile", "")] if spot.get("targetFile") else unreviewed_files[:10]
            for file_path in target_files:
                if not file_path or len(tasks) >= max_tasks:
                    break
                full_path = os.path.join(self._project_path, file_path)
                try:
                    content = Path(full_path).read_text(encoding="utf-8", errors="replace")
                    for kw in keywords:
                        if kw in content:
                            lines = content.split("\n")
                            line_idx = next(
                                (i for i, l in enumerate(lines) if kw in l), -1
                            )
                            tasks.append({
                                "type": "gapfill",
                                "attack_class": attack_class,
                                "subsystem": spot.get("subsystem", ""),
                                "target_files": [file_path],
                                "scope_hint": (
                                    f"盲区: {spot.get('subsystem', '')} 的 {attack_class} "
                                    f"从未被审查。发现潜在sink: {kw}"
                                ),
                                "rationale": (
                                    f"覆盖盲区发现: 文件 {file_path}:"
                                    f"{line_idx + 1 if line_idx >= 0 else '?'} "
                                    f"含有关键字 \"{kw}\"，但 {attack_class} "
                                    f"攻击类型尚未在此子系统中被审查"
                                ),
                                "priority": 2,
                                "detection_method": "keyword_search",
                            })
                            break  # 每个文件每个攻击类型只生成一个任务
                except Exception as e:
                    logger.debug(f"读取文件失败 {file_path}: {e}")
                if len(tasks) >= max_tasks:
                    break

        # 阶段2: LLM 补充分析（如果启用且本地搜索未找到足够任务）
        if enable_llm_gapfill and len(tasks) < max_tasks:
            llm_tasks = self._generate_llm_gapfill_tasks(
                blind_spots=blind_spots,
                unreviewed_files=unreviewed_files,
                existing_tasks=tasks,
                max_tasks=max_tasks - len(tasks),
            )
            tasks.extend(llm_tasks)
            logger.info(f"LLM Gapfill 补充生成 {len(llm_tasks)} 个任务")

        # 阶段3: 如果没有找到 sink 关键词匹配，退回到子系统缺口任务
        if not tasks:
            for subsys, count in report.get("subsystem_gaps", {}).items():
                if len(tasks) >= max_tasks:
                    break
                if count > 0:
                    tasks.append({
                        "type": "subsystem_gap",
                        "subsystem": subsys,
                        "unreviewed_count": count,
                        "reason": f"子系统 {subsys} 有 {count} 个代码文件未被审查",
                        "priority": 3,
                        "detection_method": "subsystem_analysis",
                    })

        logger.info(f"Gapfill 分析完成，共生成 {len(tasks)} 个任务")
        return tasks

    def _generate_llm_gapfill_tasks(
        self,
        blind_spots: List[Dict[str, str]],
        unreviewed_files: List[str],
        existing_tasks: List[Dict[str, Any]],
        max_tasks: int,
    ) -> List[Dict[str, Any]]:
        """基于 LLM 的 Gapfill 补充分析。

        参考 gbt-codeagent 的 llmGapfillTasks 函数：
        对本地关键词搜索遗漏的盲区，使用 LLM 进行深度分析，
        识别潜在的安全风险模式。

        Args:
            blind_spots: 盲区列表
            unreviewed_files: 未审查文件列表
            existing_tasks: 已生成的任务列表（用于去重）
            max_tasks: 最大生成任务数

        Returns:
            LLM 分析生成的任务列表
        """
        tasks: List[Dict[str, Any]] = []
        if max_tasks <= 0 or not blind_spots:
            return tasks

        # 构建已处理的文件集合（用于去重）
        processed_files: Set[str] = set()
        for task in existing_tasks:
            target_files = task.get("target_files", [])
            processed_files.update(target_files)

        # 对每个盲区尝试使用 LLM 分析
        for spot in blind_spots:
            if len(tasks) >= max_tasks:
                break

            attack_class = spot.get("attackClass", "")
            subsystem = spot.get("subsystem", "")
            
            # 找到该盲区相关的未审查文件（排除已处理的）
            relevant_files = [
                f for f in unreviewed_files 
                if f not in processed_files and 
                   _extract_subsystem(f) == subsystem
            ]
            
            if not relevant_files:
                continue

            # 优先选择 T1 文件
            t1_files = [f for f in relevant_files if _classify_tier(f) == "T1"]
            target_file = t1_files[0] if t1_files else relevant_files[0]
            
            processed_files.add(target_file)
            
            tasks.append({
                "type": "gapfill_llm",
                "attack_class": attack_class,
                "subsystem": subsystem,
                "target_files": [target_file],
                "scope_hint": (
                    f"LLM 补充分析: 子系统 {subsystem} 的 {attack_class} 从未被审查。"
                    f"本地搜索未找到 sink 关键词，需要 LLM 深度分析。"
                ),
                "rationale": (
                    f"覆盖盲区发现: 文件 {target_file} 位于未审查区域，"
                    f"{attack_class} 攻击类型尚未在此子系统中被审查，"
                    f"本地关键词搜索未发现匹配，但需要 LLM 进一步分析确认。"
                ),
                "priority": 2,
                "detection_method": "llm_analysis",
                "requires_llm": True,
            })

        return tasks

    def format_report_markdown(self) -> str:
        """生成覆盖率报告的 Markdown 文本。"""
        report = self.generate_report()
        lines = [
            "## 审计覆盖率报告",
            "",
            "| 指标 | 值 |",
            "|------|-----|",
            f"| 项目文件总数 | {report['total_files']} |",
            f"| 已审查文件 | {report['reviewed_files']} |",
            f"| 未审查代码文件 | {report['unreviewed_code_files']} |",
            f"| 覆盖率 | {report['coverage_rate']}% |",
            "",
        ]

        # Tier 统计
        tier_stats = report.get("tier_stats", {})
        if tier_stats:
            lines.append("### 未审查文件 Tier 分布")
            lines.append(f"- T1 (Controller/Filter/Interceptor): {tier_stats.get('T1', 0)}")
            lines.append(f"- T2 (Service/Util/Config): {tier_stats.get('T2', 0)}")
            lines.append(f"- T3 (Entity/DTO/Model): {tier_stats.get('T3', 0)}")
            lines.append("")

        if report["reviewed_attack_classes"]:
            lines.append("### 已检查的攻击类型")
            for cls in report["reviewed_attack_classes"]:
                lines.append(f"- {cls}")
            lines.append("")

        if report["subsystem_gaps"]:
            lines.append("### 未覆盖子系统")
            lines.append("| 子系统 | 未审查文件数 |")
            lines.append("|--------|-------------|")
            for subsys, count in report["subsystem_gaps"].items():
                lines.append(f"| {subsys} | {count} |")

        return "\n".join(lines)
