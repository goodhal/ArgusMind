#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM 文件级安全审计 —— 不依赖 SinkFinder，直接按文件分批次送 LLM 审查。

对标 gbt-codeagent 的 DefensiveLlmReviewer，但适配 ArgusMind 的架构：
- 收集项目源文件
- 按 Token 预算分批
- 每批文件发给主 LLM 做安全审计
- 产出 findings 入库，source="file_review"

性能优化特性：
- 结果缓存（基于文件 hash）
- 增量审计（只审计变更文件）
- Token 预算控制
- 文件优先级排序
- 并发请求限制
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 单批最大文件数
_MAX_FILES_PER_BATCH = 5
# 单批最大字符数（粗略估算，中文约 1.5 token/字符）
_MAX_CHARS_PER_BATCH = 12000
# 最大并发请求数
_MAX_CONCURRENT_REQUESTS = 3
# 扩展名白名单（仅审计源文件）
_SOURCE_EXTS = frozenset({
    ".py", ".java", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".rb", ".php", ".kt", ".swift",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".scala",
})

# 文件级审计提示词模板（参考 gbt-codeagent 优化版）
_FILE_AUDIT_SYSTEM_PROMPT = """你是一个资深代码安全审计专家。审查以下代码文件，输出结构化的 JSON 发现。

== 审查规则优先级分层 - 必须严格遵守 ==

🔴 安全问题（优先级最高）- 必须检测：
- SQL注入：用户输入直接拼接SQL语句
- 命令注入：执行系统命令时使用用户可控数据
- XSS漏洞：用户输入未经过滤直接输出到页面
- 敏感信息硬编码：密码、密钥、API密钥明文存储
- 不安全的反序列化：使用不可信数据进行反序列化
- 认证绕过：身份验证逻辑缺陷
- 权限控制缺失：水平越权、垂直越权
- SSRF：服务器端请求伪造
- 路径遍历：文件路径包含用户可控输入
- 文件上传漏洞：文件类型验证不足
- CSRF：缺少CSRF令牌校验的写操作端点
- 日志注入：用户输入未过滤写入日志
- 开放重定向：重定向目标来自用户可控参数
- XXE：XML解析未禁用外部实体
- CORS配置缺陷：反射Origin且允许凭据
- 不安全组件：使用已知有漏洞的第三方组件(如Fastjson Log4j Shiro)

🟠 性能问题（优先级次之）- 重点检测：
- 循环中的数据库查询：N+1查询问题
- 大对象的频繁创建：内存占用过高
- 未关闭的资源：数据库连接、文件流泄漏
- 重复计算：相同计算多次执行
- 低效算法：时间复杂度较高的实现

🟡 代码规范（优先级较低）- 参考检测：
- 命名规范：变量、函数命名不规范
- 注释缺失：关键逻辑缺少注释说明
- 方法过长：单方法超过50行
- 复杂度过高：圈复杂度超过15
- 魔法数字：未定义常量的硬编码数值

== 核心安全分析原则 ==
1. 深度分析优于广度扫描：深入分析少数真实漏洞比报告大量误报更有价值
2. 数据流追踪：从用户输入（Source）到危险函数（Sink）
3. 上下文感知分析：理解函数调用链和模块依赖
4. 质量优先：高置信度发现优于低置信度猜测
5. 自检原则：每报一个critical或high，先问自己："我能描述这个漏洞会导致的精确用户事故吗？"

== 严重级别判定标准 - 必须严格区分 ==

🔴 critical（严重）- 仅以下情况：
- 可直接通过网络远程利用，无需认证
- 可导致远程代码执行(RCE)、系统完全控制
- 可导致任意文件读取/写入
- 可绕过身份认证直接访问核心功能
- 明确的命令注入、SQL注入且用户输入未经任何过滤直接到达危险函数
- 硬编码的生产环境密钥/凭证
- ⚠️ critical 只能用于最严重的问题，不能滥用

🟠 high（高危）- 以下情况：
- 需要普通用户认证后可利用
- 可导致重要数据泄露（用户密码、个人信息）
- CSRF 可导致关键操作（修改密码、转账）
- 反序列化漏洞（有实际风险）
- SSRF 可访问内网
- 权限控制缺失导致越权
- 会话固定、敏感信息在日志中泄露

🟡 medium（中危）- 以下情况：
- 需要特定条件才能利用（如需要管理员权限）
- 信息泄露但影响范围有限（如版本号、路径泄露）
- 配置不当但不直接导致安全漏洞
- 弱加密算法但仍需要其他条件才能利用
- 输入验证不足但已有部分防护
- 仅测试/开发环境风险
- 竞争条件但利用难度大

🟢 low（低危）- 以下情况：
- 几乎无法实际利用
- 仅理论风险，缺乏实际攻击路径
- 代码风格问题不直接导致安全漏洞
- 已废弃但未删除的调试代码（不影响生产）
- 框架已默认防护的潜在风险
- low 用于信息性发现，置信度应设为 0.3-0.5

⚠️ 判定原则：
- 不确定时应降级而非升级：有疑问时选较低级别
- 需要认证或特定条件才能利用的，不应评为 critical
- 仅理论风险无实际攻击路径的，评为 low
- 如果所有发现都是同一级别，说明判定标准有问题

== 统计预期（校准用）==
- 一个正常项目的审计结果中，critical 应为 0-2 个，high 应为 0-5 个
- 如果 critical 超过 5 个或 high 超过 15 个，说明严重度判定过于宽松
- 如果所有发现都是 medium，说明可能漏掉了真正的严重问题

== 明确不算漏洞的情况（必须遵守）==
- JS/TS 渲染中访问可能为 undefined 的属性（框架渲染空值，不会崩溃）
- 纯理论风险，缺少真实输入能触发的路径
- 仅代码风格 / 命名 / 重复代码问题（这些不是安全漏洞）
- 测试代码 / 演示代码 / 示例代码 / mock 文件中的"漏洞"
- 已被框架默认防护的潜在风险（如 Spring Security CSRF、框架自带的 XSS 过滤）
- CSS 工具类的数值、hex 颜色、CSS 单位
- 仅 import 语句但无实际调用的情况
- 非安全相关的代码规范建议

== 运行时环境感知 ==

服务端（Node.js/Python/Go/Java）：
- 未处理异常 → 可能导致进程崩溃 → critical
- 资源泄漏 → 累积耗尽 → critical

浏览器端（React/Vue/Angular）：
- 未处理异常 → ErrorBoundary/全局 handler 兜底 → 最多 medium
- 渲染 undefined → 框架渲染空，不崩溃 → 不算漏洞

后端 API 端点：
- 缺少认证 → 数据泄露 → critical
- 缺少授权检查 → 越权访问 → critical

前端管理页面：
- 缺少前端路由守卫 → 但后端已有全局拦截 → 最多 medium
- loading/error 状态缺失 → 体验问题 → low

== Source→Sink 速查表 ==
| 漏洞 | Source（输入源） | Sink（危险API） | Safety（安全信号） |
|------|----------------|-----------------|-------------------|
| SQL注入 | request.getParameter, @RequestParam, @PathVariable | Statement拼接, MyBatis ${}, HQL拼接 | PreparedStatement, MyBatis #{}, JPA :param |
| 命令注入 | 同上 | Runtime.exec(), ProcessBuilder 拼接 | 固定命令+数组参数 |
| 路径遍历 | 同上 + MultipartFile文件名 | File(用户可控路径) | Paths.get()+normalize(), 白名单目录 |
| SSRF | 同上 + @RequestBody | HttpURLConnection, RestTemplate(用户可控URL) | 域名白名单, 内网过滤 |
| 反序列化 | @RequestBody, 文件读取 | ObjectInputStream, Fastjson parseObject | 类型白名单, 禁用autoType |
| 代码注入 | @RequestBody, @RequestParam | ScriptEngine.eval(), GroovyShell | 表达式沙箱 |
| XXE | @RequestBody(XML) | DocumentBuilder(未禁用外部实体) | setFeature(DISALLOW_DOCTYPE) |
| XSS | @RequestParam | response.getWriter().write(用户输入) | HTML实体编码, JSON响应 |
| 文件上传 | MultipartFile | transferTo(用户可控文件名) | UUID重命名, 白名单扩展名 |
| CORS | — | Access-Control-Allow-Origin反射Origin+allowCredentials | 固定白名单 |
| 认证缺失 | — | @GetMapping/@PostMapping 无 @PreAuthorize | SecurityContextHolder, @PreAuthorize |
| 硬编码凭据 | — | password/secret/apiKey/token = "字面量" | System.getenv(), @Value("${}") |
| 会话固定 | — | request.getSession(false) 不复用 | session.invalidate(), changeSessionId() |
| 竞态条件 | — | check-then-act, 余额检查后扣减 | @Version, @Lock, synchronized |

== 输出格式 ==
```json
[
  {
    "file": "相对文件路径",
    "line": 行号,
    "vuln_type": "漏洞类型",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "title": "简洁的漏洞标题（20字以内）",
    "evidence": "具体代码行或代码片段作为证据",
    "impact": "实际安全影响（可描述攻击场景）",
    "remediation": "具体可操作的修复方案",
    "cwe": "CWE编号",
    "confidence": 0.0-1.0,
    "evidencePoints": ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION"]
  }
]
```
如果零发现，返回 `[]`。

== 证据点参考 ==
| 漏洞类型 | 必须证据点 |
|---------|-----------|
| SQL注入 | EVID_SQL_EXEC_POINT, EVID_SQL_STRING_CONSTRUCTION, EVID_SQL_USER_PARAM_MAPPING |
| 命令注入 | EVID_CMD_EXEC_POINT, EVID_CMD_STRING_CONSTRUCTION, EVID_CMD_USER_PARAM_MAPPING |
| 文件操作 | EVID_FILE_READ_SINK, EVID_FILE_PATH_CONSTRUCTION, EVID_FILE_USER_PARAM_MAPPING |
| SSRF | EVID_SSRF_URL_CONSTRUCTION, EVID_SSRF_USER_PARAM_MAPPING |
| XXE | EVID_XXE_PARSER_CALL, EVID_XXE_INPUT_SOURCE |
| 反序列化 | EVID_DESER_CALLSITE, EVID_DESER_INPUT_SOURCE |
| XSS | EVID_XSS_OUTPUT_POINT, EVID_XSS_USER_INPUT_INTO_OUTPUT |
| 认证绕过 | EVID_AUTH_CHECK_BYPASS, EVID_AUTH_PERMISSION_CHECK_EXEC |

== 去重规则 ==
✅ 应该合并：同一文件、同一函数、同一行号、同一漏洞类型 → 合并为一条
❌ 不应该合并：不同端点/不同文件/不同利用前提的同类漏洞 → 分别报告

⚠️ 宁可漏报，不可误报。质量优于数量。"""

_FILE_AUDIT_USER_PROMPT = """请审计以下 {language} 源代码文件，发现安全漏洞。

{file_list}

=== 文件内容 ===
{file_contents}

=== 额外安全上下文 ===
{security_context}
"""


def _estimate_tokens(text: str) -> int:
    """粗略估算 Token 数（中文 1.5x，英文 1x）。"""
    chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    ascii_chars = len(text) - chinese_chars
    return int(chinese_chars * 1.5 + ascii_chars * 1.0)


def _is_source_file(filepath: str) -> bool:
    """判断是否为源文件。"""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in _SOURCE_EXTS


def _find_source_files(project_path: str) -> List[str]:
    """查找项目中的所有源文件。"""
    result = []
    for root, _, files in os.walk(project_path):
        for f in files:
            if _is_source_file(f):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, project_path)
                # 跳过测试文件和依赖目录
                if any(p in rel_path.lower() for p in ('test', 'tests', 'node_modules', '__pycache__', '.git')):
                    continue
                result.append(rel_path)
    return sorted(result)


def _read_file_safe(filepath: str) -> Optional[str]:
    """安全读取文件内容。"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        logger.error(f"读取文件失败 {filepath}: {e}")
        return None


def _batch_files(project_path: str, files: List[str]) -> List[List[str]]:
    """按 Token 预算分批文件。"""
    batches = []
    current_batch = []
    current_chars = 0

    for filepath in files:
        full_path = os.path.join(project_path, filepath)
        content = _read_file_safe(full_path)
        if content is None:
            continue
        
        file_chars = len(content)
        
        # 检查是否需要新建批次
        if (len(current_batch) >= _MAX_FILES_PER_BATCH or 
            current_chars + file_chars > _MAX_CHARS_PER_BATCH):
            if current_batch:
                batches.append(current_batch)
            current_batch = []
            current_chars = 0
        
        current_batch.append(filepath)
        current_chars += file_chars
    
    if current_batch:
        batches.append(current_batch)
    
    return batches


@dataclass
class FileReviewResult:
    """文件审查结果。"""
    file_path: str
    findings: List[Dict[str, Any]]
    prompt_tokens: int = 0
    completion_tokens: int = 0


def _parse_llm_response(response_text: str) -> List[Dict[str, Any]]:
    """解析 LLM 响应。"""
    try:
        # 提取 JSON 代码块
        match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text)
        if match:
            json_str = match.group(1)
            return json.loads(json_str)
        # 如果没有代码块，尝试直接解析
        return json.loads(response_text)
    except Exception as e:
        logger.error(f"解析 LLM 响应失败: {e}")
        return []


class LLMFileReviewer:
    """LLM 文件级审计器 - 集成性能优化、漏洞链分析和知识库检索"""
    
    def __init__(self, llm_client, project_path: str):
        self._llm_client = llm_client
        self._project_path = project_path
        # 延迟导入避免循环依赖
        from .llm_optimizer import get_optimizer, AsyncLimiter
        self._limiter = AsyncLimiter(_MAX_CONCURRENT_REQUESTS)
        self._optimizer = get_optimizer()
        self._optimizer.load_cache()
        # 初始化漏洞链分析器
        from .exploit_chain_analyzer import ExploitChainAnalyzer
        self._chain_analyzer = ExploitChainAnalyzer()
        # 初始化知识库服务
        from .rag_service import get_rag_service
        self._rag_service = get_rag_service()
    
    async def review_files(self, files: Optional[List[str]] = None, heuristic_findings: List[dict] = None) -> dict:
        """审计指定文件或整个项目（带缓存优化）"""
        if files is None:
            files = _find_source_files(self._project_path)
        
        if not files:
            logger.info("未找到源文件")
            return {
                'status': 'completed',
                'called': False,
                'summary': '未找到源文件',
                'findings': [],
                'warnings': [],
                'results': []
            }
        
        logger.info(f"开始审计 {len(files)} 个文件")
        
        # 构建文件信息列表
        file_infos = []
        for filepath in files:
            full_path = os.path.join(self._project_path, filepath)
            content = _read_file_safe(full_path)
            if content:
                file_infos.append({
                    'relative_path': filepath,
                    'content': content
                })
        
        # 智能文件过滤：跳过低风险文件
        from .llm_optimizer import FileInfo
        file_info_objs = [FileInfo(f['relative_path'], f['content']) for f in file_infos]
        filtered = self._optimizer.filter_low_risk_files(file_info_objs)
        original_count = len(file_info_objs)
        file_info_objs = filtered
        file_infos = [{'relative_path': f.relative_path, 'content': f.content} for f in file_info_objs]
        logger.info(f"[LLM优化] 智能文件过滤: {original_count} -> {len(file_infos)} 个文件")
        
        # 计算项目 hash 并检查缓存
        project_hash = self._optimizer.compute_project_hash(file_info_objs)
        
        cached_result = self._optimizer.get_cached_results(project_hash, file_info_objs)
        if cached_result and cached_result['is_cache_hit']:
            logger.info(f"[LLM优化] 缓存命中，返回 {len(cached_result['cached_findings'])} 条缓存结果")
            return {
                'status': 'completed',
                'called': True,
                'summary': f'使用缓存结果（{len(cached_result["cached_findings"])}条）',
                'findings': [f for f in cached_result['cached_findings']],
                'warnings': [],
                'cached': True,
                'results': []
            }
        
        # 增量审计：只审计变更文件
        if cached_result and cached_result['changed_files']:
            logger.info(f"[LLM优化] 检测到 {len(cached_result['changed_files'])} 个变更文件，进行增量审计")
            changed_set = set(cached_result['changed_files'])
            file_infos = [f for f in file_infos if f['relative_path'] in changed_set]
        
        # 文件优先级排序（结合分层审计）
        file_info_objs = [FileInfo(f['relative_path'], f['content']) for f in file_infos]
        if heuristic_findings:
            logger.info("[LLM优化] 根据启发式发现调整文件优先级")
            prioritized = self._optimizer.prioritize_files(file_info_objs, heuristic_findings)
        else:
            prioritized = self._optimizer.prioritize_files(file_info_objs)
        
        # 按层级优先级重新排序
        tier_prioritized = self._optimizer.prioritize_by_tier(prioritized)
        file_infos = [{'relative_path': f.relative_path, 'content': f.content, 'tier': self._optimizer.get_file_tier(f.relative_path)} for f in tier_prioritized]
        logger.info("[LLM优化] 文件已按层级优先级排序")
        
        # Token 预算计算
        file_info_objs = [FileInfo(f['relative_path'], f['content']) for f in file_infos]
        budget = self._optimizer.calculate_token_budget(file_info_objs)
        logger.info(f"[LLM优化] Token预算: 预估{budget['total_estimated']}, 剩余{budget['remaining_budget']}, 需要压缩:{budget['needs_compression']}")
        
        # 分层预算报告
        tier_budget = self._optimizer.calculate_tier_budget(file_info_objs)
        logger.info(f"[LLM优化] 分层预算: T1={tier_budget['tier_files']['T1']}个文件, T2={tier_budget['tier_files']['T2']}个文件, T3={tier_budget['tier_files']['T3']}个文件")
        
        if budget['needs_compression']:
            # 如果需要压缩，先裁剪大文件
            logger.info(f"[LLM优化] Token预算不足，先裁剪大文件")
            trimmed = self._optimizer.trim_files_content(file_info_objs, max_chars=8000)
            file_infos = [{'relative_path': f.relative_path, 'content': f.content} for f in trimmed]
            logger.info(f"[LLM优化] 文件裁剪完成")
            
            # 重新计算预算
            file_info_objs = [FileInfo(f['relative_path'], f['content']) for f in file_infos]
            budget = self._optimizer.calculate_token_budget(file_info_objs)
            
            if budget['needs_compression']:
                # 仍然不足，按比例压缩文件数量
                logger.info(f"[LLM优化] 仍需按{budget['compression_ratio']:.1%}比例压缩文件数量")
                keep_count = max(1, int(len(file_infos) * budget['compression_ratio']))
                file_infos = file_infos[:keep_count]
                logger.info(f"[LLM优化] 保留前 {keep_count} 个高优先级文件")
        
        # 分批处理
        file_paths = [f['relative_path'] for f in file_infos]
        batches = _batch_files(self._project_path, file_paths)
        logger.info(f"分成 {len(batches)} 批处理")
        
        results = []
        all_findings = []
        total_prompt_tokens = 0
        total_completion_tokens = 0
        total_cached_tokens = 0
        
        # 并行处理批次（带并发限制）
        import asyncio
        async def process_batch(batch_idx, batch):
            nonlocal total_prompt_tokens, total_completion_tokens, total_cached_tokens
            
            logger.info(f"处理批次 {batch_idx+1}/{len(batches)}: {batch}")
            
            # 构建批处理内容
            file_contents = []
            file_list = []
            file_info_map = {f['relative_path']: f['content'] for f in file_infos}
            
            for filepath in batch:
                content = file_info_map.get(filepath)
                if content:
                    file_contents.append(f"--- {filepath} ---\n{content}")
                    file_list.append(filepath)
            
            if not file_contents:
                return []
            
            # 构建提示词
            user_prompt = _FILE_AUDIT_USER_PROMPT.format(
                language="混合语言",
                file_list="\n".join(f"- {f}" for f in file_list),
                file_contents="\n\n".join(file_contents),
                security_context=""
            )
            
            # 调用 LLM（带并发限制）
            # LLMClient.call 是同步方法，用 asyncio.to_thread 包装为异步
            response = await self._limiter(
                asyncio.to_thread,
                self._llm_client.call,
                messages=[
                    {"role": "system", "content": _FILE_AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=8000
            )
            
            # 提取 token 统计（LLMResponse 是 dataclass，用属性访问）
            prompt_tokens = response.prompt_tokens
            completion_tokens = response.completion_tokens
            cached_tokens = response.cached_tokens
            total_prompt_tokens += prompt_tokens
            total_completion_tokens += completion_tokens
            total_cached_tokens += cached_tokens
            
            # 更新优化器的 token 使用量
            self._optimizer.update_token_usage(prompt_tokens + completion_tokens)
            
            # 解析结果（LLMResponse.content 直接取文本）
            findings = _parse_llm_response(response.content)
            
            # 去重和误报过滤
            filtered_findings = []
            for finding in findings:
                context = {
                    'filePath': finding.get('file', ''),
                    'code': finding.get('evidence', '')
                }
                if not self._optimizer.is_false_positive(finding, context):
                    finding['source'] = 'file_review'
                    filtered_findings.append(finding)
            
            logger.info(f"批次 {batch_idx+1} 完成，发现 {len(filtered_findings)} 个问题")
            return filtered_findings
        
        # 并发执行所有批次
        tasks = [process_batch(i, batch) for i, batch in enumerate(batches)]
        batch_results = await asyncio.gather(*tasks)
        
        # 合并结果
        for batch_findings in batch_results:
            all_findings.extend(batch_findings)
            for finding in batch_findings:
                file_path = finding.get('file', '')
                results.append(FileReviewResult(
                    file_path=file_path,
                    findings=[finding],
                    prompt_tokens=0,
                    completion_tokens=0
                ))
        
        # 合并缓存结果（增量审计时）
        if cached_result and cached_result['cached_findings']:
            all_findings.extend(cached_result['cached_findings'])
        
        # 缓存本次审计结果
        self._optimizer.cache_results(project_hash, file_info_objs, all_findings)
        
        # 重置 token 计数
        self._optimizer.reset_token_usage()
        
        # 漏洞链分析
        chains = []
        critical_chains = []
        if all_findings:
            chains = self._chain_analyzer.analyze_findings(all_findings)
            critical_chains = self._chain_analyzer.find_critical_chains(chains)
            logger.info(f"漏洞链分析完成，发现 {len(chains)} 条攻击链，其中 {len(critical_chains)} 条高危")
        
        # 为每个漏洞关联知识库信息
        enriched_findings = []
        for finding in all_findings:
            vuln_type = finding.get('vuln_type', '')
            cwe = finding.get('cwe', '')
            
            # 搜索知识库
            knowledge_results = []
            if vuln_type:
                knowledge_results.extend(self._rag_service.search(vuln_type, top_k=2))
            if cwe:
                knowledge_results.extend(self._rag_service.get_by_cwe(cwe))
            
            # 去重
            seen_ids = set()
            unique_knowledge = []
            for kr in knowledge_results:
                if kr['id'] not in seen_ids:
                    seen_ids.add(kr['id'])
                    unique_knowledge.append(kr)
            
            enriched_finding = finding.copy()
            enriched_finding['knowledge'] = unique_knowledge[:3]
            enriched_findings.append(enriched_finding)
        
        logger.info(f"审计完成，共发现 {len(enriched_findings)} 个问题")
        return {
            'status': 'completed',
            'called': True,
            'summary': f'完成审计 {len(file_infos)} 个文件，发现 {len(enriched_findings)} 个问题',
            'findings': enriched_findings,
            'warnings': [],
            'cached': False,
            'results': results,
            'token_usage': {
                'prompt_tokens': total_prompt_tokens,
                'completion_tokens': total_completion_tokens,
                'total_tokens': total_prompt_tokens + total_completion_tokens,
                'cached_tokens': total_cached_tokens,
            },
            'chains': [
                {
                    'risk_score': chain.risk_score,
                    'severity': chain.severity,
                    'description': chain.description,
                    'exploitability': chain.exploitability,
                    'path': chain.get_chain_path()
                }
                for chain in chains
            ],
            'critical_chains_count': len(critical_chains)
        }


def run_file_review(
    task_id: str,
    project_id: str,
    project_path: str,
    project_info: str,
    llm,
    max_workers: int = 3,
) -> int:
    """文件级审计入口函数（同步版本，供 orchestrator 调用）"""
    import asyncio
    
    async def _run_async():
        reviewer = LLMFileReviewer(llm, project_path)
        result = await reviewer.review_files()
        
        # 上报 token 用量到 token_ledger
        token_usage = result.get('token_usage', {})
        if token_usage and task_id:
            try:
                from src.services.token_service import report_token_usage
                report_token_usage(
                    task_id=task_id,
                    llm_input=token_usage.get('prompt_tokens', 0),
                    llm_output=token_usage.get('completion_tokens', 0),
                    note="file_review",
                )
                # 上报 LLM prompt cache 命中统计
                cached = token_usage.get('cached_tokens', 0)
                total_prompt = token_usage.get('prompt_tokens', 0)
                if total_prompt > 0:
                    report_token_usage(
                        task_id=task_id,
                        llm_input=cached,
                        llm_output=total_prompt - cached,
                        note="cache_stats:file_review",
                    )
            except Exception:
                pass
        
        # 处理审计结果：写入 PostgreSQL vulnerability 表
        findings = result.get('findings', [])
        if findings:
            from src.infrastructure.db.models.vulnerability import Vulnerability, VulnerabilityDetail
            from src.infrastructure.db.session import session_scope
            from uuid import uuid4
            
            with session_scope() as session:
                for finding in findings:
                    file_path = finding.get('file', '')
                    line = finding.get('line', 0)
                    entry_points = f"{file_path}:{line}" if file_path else ''
                    
                    vul = Vulnerability(
                        id=str(uuid4()),
                        project_id=project_id,
                        task_id=task_id,
                        vul_name=str(finding.get('title', finding.get('vuln_type', 'unknown')))[:255],
                        category_name=str(finding.get('vuln_type', 'unknown')),
                        level=str(finding.get('severity', 'MEDIUM')),
                        verdict=str(finding.get('verdict', '')),
                        confidence=str(finding.get('confidence', 'LOW')),
                        source='file_review',
                        neo4j_element_id='',
                    )
                    session.add(vul)
                    session.flush()
                    
                    detail = VulnerabilityDetail(vulnerability_id=vul.id)
                    session.add(detail)
                    detail.evidence = str(finding.get('evidence', ''))
                    detail.detail = str(finding.get('impact', finding.get('reason', '')))
                    detail.entry_points = entry_points
                    detail.remediation = str(finding.get('remediation', ''))
                    detail.cwe = str(finding.get('cwe', ''))
                    detail.code_snippet = str(finding.get('evidence', ''))
                    detail.language = str(finding.get('language', ''))
                    detail.impact = str(finding.get('impact', ''))
                
                session.commit()
        
        return len(findings)
    
    # 运行异步函数
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_async())
    finally:
        loop.close()
