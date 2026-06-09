#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM 审计优化模块 - 参考 gbt-codeagent

优化内容：
1. 结果缓存 - 基于文件hash避免重复审计
2. 增量审计 - 只审计变更文件
3. Token预算控制 - 智能上下文管理
4. 文件优先级排序 - 优先审计高风险文件
5. 并发控制 - 限制并行请求数量
6. 智能文件过滤 - 跳过低风险文件
7. 代码裁剪策略 - 对超大文件进行智能裁剪
8. 分层审计策略 - 基于文件类型分层审计
9. 上下文压缩 - 轮间对话历史压缩
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 低风险文件扩展名（跳过审计）
LOW_RISK_EXTENSIONS = frozenset({
    '.md', '.txt', '.json', '.yaml', '.yml', '.xml',
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico',
    '.css', '.scss', '.less', '.sass',
    '.lock', '.gitignore', '.dockerignore',
    '.md5', '.sha256', '.log', '.tmp', '.bak',
    '.csv', '.tsv', '.dat', '.ini', '.properties'
})

# 高风险文件扩展名（必须审计）
HIGH_RISK_EXTENSIONS = frozenset({
    '.java', '.py', '.js', '.ts', '.tsx', '.jsx',
    '.php', '.go', '.rs', '.rb',
    '.cpp', '.c', '.cxx', '.h', '.hpp',
    '.cs', '.vb', '.asp', '.aspx',
    '.sql', '.pl', '.pm', '.tpl',
    '.kt', '.swift', '.scala', '.groovy'
})

# 高风险文件模式
HIGH_RISK_PATTERNS = [
    re.compile(r'controller', re.IGNORECASE),
    re.compile(r'service', re.IGNORECASE),
    re.compile(r'handler', re.IGNORECASE),
    re.compile(r'api', re.IGNORECASE),
    re.compile(r'auth', re.IGNORECASE),
    re.compile(r'security', re.IGNORECASE),
    re.compile(r'login', re.IGNORECASE),
    re.compile(r'admin', re.IGNORECASE),
    re.compile(r'payment', re.IGNORECASE),
    re.compile(r'encrypt', re.IGNORECASE),
    re.compile(r'decrypt', re.IGNORECASE),
    re.compile(r'config', re.IGNORECASE),
    re.compile(r'secret', re.IGNORECASE),
    re.compile(r'token', re.IGNORECASE),
    re.compile(r'session', re.IGNORECASE),
    re.compile(r'jdbc', re.IGNORECASE),
    re.compile(r'orm', re.IGNORECASE),
    re.compile(r'dto', re.IGNORECASE),
    re.compile(r'entity', re.IGNORECASE),
    re.compile(r'model', re.IGNORECASE),
    re.compile(r'repository', re.IGNORECASE),
    re.compile(r'dao', re.IGNORECASE),
    re.compile(r'mapper', re.IGNORECASE)
]

# 低风险文件模式
LOW_RISK_PATTERNS = [
    re.compile(r'test', re.IGNORECASE),
    re.compile(r'spec', re.IGNORECASE),
    re.compile(r'mock', re.IGNORECASE),
    re.compile(r'fixture', re.IGNORECASE),
    re.compile(r'sample', re.IGNORECASE),
    re.compile(r'example', re.IGNORECASE),
    re.compile(r'demo', re.IGNORECASE),
    re.compile(r'doc', re.IGNORECASE),
    re.compile(r'docs', re.IGNORECASE),
    re.compile(r'readme', re.IGNORECASE),
    re.compile(r'changelog', re.IGNORECASE),
    re.compile(r'license', re.IGNORECASE)
]

# 分层审计权重
TIER_WEIGHTS = {
    'T1': 1.0,   # 控制器/过滤器/网关 - 最高优先级
    'T2': 0.7,   # 服务/数据访问层/配置 - 中优先级
    'T3': 0.4    # 实体/DTO/模型 - 低优先级
}

# 分层模式
TIER_PATTERNS = {
    'T1': [
        re.compile(r'controller', re.IGNORECASE),
        re.compile(r'filter', re.IGNORECASE),
        re.compile(r'interceptor', re.IGNORECASE),
        re.compile(r'gateway', re.IGNORECASE),
        re.compile(r'securityconfig', re.IGNORECASE),
        re.compile(r'webconfig', re.IGNORECASE),
        re.compile(r'route', re.IGNORECASE),
        re.compile(r'router', re.IGNORECASE),
        re.compile(r'dispatch', re.IGNORECASE),
        re.compile(r'authfilter', re.IGNORECASE),
        re.compile(r'corsfilter', re.IGNORECASE),
        re.compile(r'ratelimit', re.IGNORECASE)
    ],
    'T2': [
        re.compile(r'service', re.IGNORECASE),
        re.compile(r'dao', re.IGNORECASE),
        re.compile(r'mapper', re.IGNORECASE),
        re.compile(r'repository', re.IGNORECASE),
        re.compile(r'util', re.IGNORECASE),
        re.compile(r'helper', re.IGNORECASE),
        re.compile(r'manager', re.IGNORECASE),
        re.compile(r'handler', re.IGNORECASE),
        re.compile(r'config', re.IGNORECASE),
        re.compile(r'properties', re.IGNORECASE),
        re.compile(r'application', re.IGNORECASE),
        re.compile(r'business', re.IGNORECASE),
        re.compile(r'core', re.IGNORECASE),
        re.compile(r'common', re.IGNORECASE)
    ],
    'T3': [
        re.compile(r'entity', re.IGNORECASE),
        re.compile(r'dto', re.IGNORECASE),
        re.compile(r'vo', re.IGNORECASE),
        re.compile(r'pojo', re.IGNORECASE),
        re.compile(r'model', re.IGNORECASE),
        re.compile(r'domain', re.IGNORECASE),
        re.compile(r'bean', re.IGNORECASE),
        re.compile(r'object', re.IGNORECASE),
        re.compile(r'request', re.IGNORECASE),
        re.compile(r'response', re.IGNORECASE),
        re.compile(r'param', re.IGNORECASE)
    ]
}

@dataclass
class FileInfo:
    """文件信息"""
    relative_path: str
    content: str
    score: int = 0


class LLMOptimizer:
    """LLM 审计优化器"""
    
    def __init__(self, cache_dir: Optional[str] = None, max_tokens: int = 120000):
        self.cache_dir = cache_dir or os.path.join(os.getcwd(), 'data', 'llm_cache')
        self.cache: Dict[str, CacheEntry] = {}
        self.audit_history: Dict[str, List[dict]] = {}
        self.token_budget = {
            'max_tokens': max_tokens,
            'used_tokens': 0,
            'warning_threshold': 0.8
        }
        self.false_positive_patterns = self._init_false_positive_patterns()
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """确保缓存目录存在"""
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _init_false_positive_patterns(self):
        """初始化误报模式"""
        import re
        return {
            'test_patterns': [
                re.compile(r'test', re.IGNORECASE),
                re.compile(r'spec', re.IGNORECASE),
                re.compile(r'mock', re.IGNORECASE),
                re.compile(r'fixture', re.IGNORECASE),
                re.compile(r'example', re.IGNORECASE),
                re.compile(r'demo', re.IGNORECASE),
                re.compile(r'stub', re.IGNORECASE),
                re.compile(r'placeholder', re.IGNORECASE),
                re.compile(r'dummy', re.IGNORECASE),
                re.compile(r'__tests__'),
                re.compile(r'\.test\.'),
                re.compile(r'\.spec\.'),
                re.compile(r'_test\.js'),
                re.compile(r'_spec\.js'),
            ],
            'framework_patterns': [
                'node_modules', 'vendor', '.git', 'dist', 'build',
                'coverage', '.next', '.nuxt', '__pycache__'
            ],
            'safe_patterns': [
                re.compile(r'logger\.(error|warn|info|debug)'),
                re.compile(r'console\.(log|debug|info)'),
                re.compile(r'throw new Error.*test', re.IGNORECASE),
                re.compile(r'skip', re.IGNORECASE),
                re.compile(r'todo', re.IGNORECASE),
                re.compile(r' FIXME ', re.IGNORECASE),
                re.compile(r' XXX ', re.IGNORECASE),
            ]
        }
    
    def compute_file_hash(self, content: str) -> str:
        """计算文件内容的 hash"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def compute_project_hash(self, files: List[FileInfo]) -> str:
        """计算项目级 hash（所有文件内容的组合哈希）"""
        file_hashes = sorted([
            f"{f.relative_path}:{self.compute_file_hash(f.content)}"
            for f in files
        ])
        combined = '|'.join(file_hashes)
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()[:32]
    
    def load_cache(self):
        """加载缓存"""
        try:
            cache_file = os.path.join(self.cache_dir, 'audit_cache.json')
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 转换为 CacheEntry 对象
                    for key, entry in data.get('entries', {}).items():
                        self.cache[key] = CacheEntry(
                            project_hash=entry['project_hash'],
                            file_hashes=entry['file_hashes'],
                            findings=entry['findings'],
                            cached_at=entry['cached_at'],
                            version=entry.get('version', '1.0')
                        )
                    self.audit_history = data.get('history', {})
                logger.info(f'[LLM优化] 缓存加载完成，已缓存 {len(self.cache)} 条记录')
            else:
                logger.info('[LLM优化] 缓存文件不存在，新建缓存')
        except Exception as e:
            logger.warn(f'[LLM优化] 缓存加载失败: {e}')
            self.cache = {}
            self.audit_history = {}
    
    def save_cache(self):
        """保存缓存"""
        try:
            cache_file = os.path.join(self.cache_dir, 'audit_cache.json')
            data = {
                'entries': {k: v.__dict__ for k, v in self.cache.items()},
                'history': self.audit_history,
                'saved_at': datetime.now().isoformat()
            }
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warn(f'[LLM优化] 缓存保存失败: {e}')
    
    def get_cached_results(self, project_hash: str, files: List[FileInfo]) -> Optional[dict]:
        """获取缓存结果"""
        cached = self.cache.get(project_hash)
        if not cached:
            return None
        
        cached_file_hashes = set(cached.file_hashes)
        current_file_hashes = [
            {'path': f.relative_path, 'hash': self.compute_file_hash(f.content)}
            for f in files
        ]
        
        unchanged_files = [
            f for f in current_file_hashes 
            if f"{f['path']}:{f['hash']}" in cached_file_hashes
        ]
        changed_files = [
            f['path'] for f in current_file_hashes 
            if f"{f['path']}:{f['hash']}" not in cached_file_hashes
        ]
        
        return {
            'cached_findings': cached.findings,
            'unchanged_count': len(unchanged_files),
            'changed_files': changed_files,
            'is_cache_hit': len(changed_files) == 0
        }
    
    def cache_results(self, project_hash: str, files: List[FileInfo], findings: List[dict]):
        """缓存审计结果"""
        file_hashes = [
            f"{f.relative_path}:{self.compute_file_hash(f.content)}"
            for f in files
        ]
        entry = CacheEntry(
            project_hash=project_hash,
            file_hashes=file_hashes,
            findings=findings,
            cached_at=datetime.now().isoformat(),
            version='1.0'
        )
        self.cache[project_hash] = entry
        self.save_cache()
    
    def filter_unchanged_files(self, files: List[FileInfo], changed_files: List[str]) -> List[FileInfo]:
        """过滤掉未变更的文件"""
        if not changed_files:
            return files
        changed_set = set(changed_files)
        return [f for f in files if f.relative_path in changed_set]
    
    def calculate_token_budget(self, files: List[FileInfo], priority_files: List[str] = None) -> dict:
        """计算 Token 预算"""
        priority_files = priority_files or []
        
        # 估算总 Token 数（中文约 2 token/字符，英文约 1.3 token/单词）
        total_chars = sum(len(f.content) for f in files)
        estimated_tokens = self._estimate_tokens_from_chars(total_chars)
        
        # 计算优先级文件的 Token 数
        priority_set = set(priority_files)
        priority_chars = sum(
            len(f.content) for f in files 
            if f.relative_path in priority_set
        )
        priority_tokens = self._estimate_tokens_from_chars(priority_chars)
        
        # 计算剩余预算
        remaining_budget = self.token_budget['max_tokens'] - self.token_budget['used_tokens']
        safe_budget = int(remaining_budget * 0.9)  # 90% 安全边际
        
        return {
            'total_estimated': estimated_tokens,
            'priority_tokens': priority_tokens,
            'remaining_budget': remaining_budget,
            'safe_budget': safe_budget,
            'needs_compression': estimated_tokens > safe_budget,
            'compression_ratio': safe_budget / max(estimated_tokens, 1)
        }
    
    def _estimate_tokens_from_chars(self, chars: int) -> int:
        """从字符数估算 Token 数"""
        # 假设混合内容：中文约占 50%
        return int(chars * 1.5)  # 平均约 1.5 token/字符
    
    def prioritize_files(self, files: List[FileInfo], heuristic_findings: List[dict] = None) -> List[FileInfo]:
        """文件优先级排序 - 优先审计高风险文件"""
        heuristic_findings = heuristic_findings or []
        
        scored = []
        for file in files:
            score = 0
            file_name = file.relative_path.lower()
            
            # 安全相关文件加分
            if any(keyword in file_name for keyword in ['auth', 'login', 'user', 'permission', 'role', 'admin', 'security']):
                score += 10
            if any(keyword in file_name for keyword in ['api', 'controller', 'handler', 'service']):
                score += 8
            if any(keyword in file_name for keyword in ['config', 'settings', 'env']):
                score += 6
            if file_name.endswith(('.java', '.py', '.js', '.ts', '.go', '.rs')):
                score += 5
            
            # 测试文件减分
            if any(keyword in file_name for keyword in ['test', 'spec', 'mock']):
                score -= 20
            if any(keyword in file_name for keyword in ['node_modules', 'vendor']):
                score -= 30
            
            # 基于启发式发现调整优先级
            related_findings = [
                f for f in heuristic_findings 
                if f.get('location') and file.relative_path in f['location']
            ]
            score += len(related_findings) * 3
            
            # 文件大小适中加分（太小可能没内容，太大可能是自动生成的）
            content_len = len(file.content)
            if 1000 < content_len < 50000:
                score += 3
            
            scored.append(FileInfo(
                relative_path=file.relative_path,
                content=file.content,
                score=score
            ))
        
        # 按分数降序排列
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored
    
    def is_false_positive(self, finding: dict, context: dict = None) -> bool:
        """判断是否为误报"""
        context = context or {}
        file_path = context.get('filePath', '')
        code = context.get('code', '')
        
        # 检查测试文件模式
        for pattern in self.false_positive_patterns['test_patterns']:
            if pattern.search(file_path):
                return True
        
        # 检查框架目录模式
        for pattern in self.false_positive_patterns['framework_patterns']:
            if pattern in file_path:
                return True
        
        # 检查安全代码模式
        for pattern in self.false_positive_patterns['safe_patterns']:
            if pattern.search(code):
                return True
        
        return False
    
    def update_token_usage(self, tokens: int):
        """更新 Token 使用量"""
        self.token_budget['used_tokens'] += tokens
        usage_ratio = self.token_budget['used_tokens'] / self.token_budget['max_tokens']
        
        if usage_ratio >= self.token_budget['warning_threshold']:
            logger.warning(
                f'[LLM优化] Token 使用量达到警告阈值: {usage_ratio:.1%}'
            )
    
    def reset_token_usage(self):
        """重置 Token 使用量"""
        self.token_budget['used_tokens'] = 0
    
    def is_high_risk_file(self, file_path: str) -> bool:
        """判断是否为高风险文件"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in HIGH_RISK_EXTENSIONS:
            return True
        if ext in LOW_RISK_EXTENSIONS:
            return False
        
        # 检查文件路径模式
        file_name = file_path.lower()
        for pattern in HIGH_RISK_PATTERNS:
            if pattern.search(file_name):
                return True
        
        # 默认认为源文件是高风险的
        return ext.startswith('.') is False
    
    def filter_low_risk_files(self, files: List[FileInfo]) -> List[FileInfo]:
        """过滤低风险文件"""
        filtered = []
        skipped = []
        
        for file in files:
            if self.is_high_risk_file(file.relative_path):
                filtered.append(file)
            else:
                skipped.append(file.relative_path)
        
        if skipped:
            logger.info(f'[LLM优化] 跳过 {len(skipped)} 个低风险文件')
        
        return filtered
    
    def trim_large_file(self, content: str, max_chars: int = 8000) -> str:
        """
        智能裁剪大文件内容
        
        保留：
        - 函数/方法定义
        - 类定义
        - 注释（包含 TODO、FIXME 等）
        - import/require 语句
        - 关键安全相关代码
        """
        if len(content) <= max_chars:
            return content
        
        lines = content.split('\n')
        important_lines = []
        in_function = False
        function_buffer = []
        
        for line in lines:
            # 保留函数/方法定义
            if re.match(r'^\s*(def |class |function |public |private |protected )', line):
                in_function = True
                function_buffer = [line]
                continue
            
            # 保留 import/require 语句
            if re.match(r'^\s*(import |from |require\()', line):
                important_lines.append(line)
                continue
            
            # 保留注释（安全相关）
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                # 特别关注安全相关注释
                if any(keyword in line.lower() for keyword in ['todo', 'fixme', 'security', 'vulnerability', 'bug', 'warning']):
                    important_lines.append(line)
                continue
            
            # 保留关键安全相关代码
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'token', 'api_key', 'encrypt', 'decrypt']):
                important_lines.append(line)
                continue
            
            # 函数内容缓冲（保留前几行）
            if in_function:
                function_buffer.append(line)
                if len(function_buffer) <= 10:  # 每个函数保留前10行
                    important_lines.extend(function_buffer)
                in_function = False
                function_buffer = []
        
        # 如果裁剪后内容太少，保留一些中间内容
        if len(important_lines) < 20 and len(lines) > 50:
            # 保留开头和结尾各20行
            important_lines = lines[:20] + ['... (truncated) ...'] + lines[-20:]
        
        result = '\n'.join(important_lines)
        
        # 确保不超过最大字符数
        if len(result) > max_chars:
            result = result[:max_chars] + '\n... (truncated at max chars)'
        
        logger.debug(f'[LLM优化] 文件裁剪: {len(content)} chars -> {len(result)} chars')
        return result
    
    def trim_files_content(self, files: List[FileInfo], max_chars: int = 8000) -> List[FileInfo]:
        """批量裁剪文件内容"""
        trimmed = []
        for file in files:
            trimmed_content = self.trim_large_file(file.content, max_chars)
            trimmed.append(FileInfo(
                relative_path=file.relative_path,
                content=trimmed_content,
                score=file.score
            ))
        return trimmed
    
    def get_file_tier(self, file_path: str) -> str:
        """获取文件层级"""
        file_name = file_path.lower()
        
        # 按优先级检查层级
        for tier, patterns in TIER_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(file_name):
                    return tier
        
        # 默认 T3
        return 'T3'
    
    def calculate_tier_budget(self, files: List[FileInfo]) -> dict:
        """计算分层预算"""
        tier_files = {'T1': [], 'T2': [], 'T3': []}
        
        for file in files:
            tier = self.get_file_tier(file.relative_path)
            tier_files[tier].append(file)
        
        # 计算每层的 token 预估
        tier_tokens = {}
        total_tokens = 0
        for tier, tier_file_list in tier_files.items():
            chars = sum(len(f.content) for f in tier_file_list)
            tokens = self._estimate_tokens_from_chars(chars)
            tier_tokens[tier] = tokens
            total_tokens += tokens
        
        return {
            'tier_files': {k: len(v) for k, v in tier_files.items()},
            'tier_tokens': tier_tokens,
            'total_tokens': total_tokens
        }
    
    def prioritize_by_tier(self, files: List[FileInfo]) -> List[FileInfo]:
        """按层级优先级排序"""
        scored = []
        for file in files:
            tier = self.get_file_tier(file.relative_path)
            tier_weight = TIER_WEIGHTS.get(tier, 0.4)
            
            # 基础分数 + 层级权重
            base_score = file.score if hasattr(file, 'score') else 0
            total_score = base_score + tier_weight * 100
            
            scored.append({
                'file': file,
                'score': total_score,
                'tier': tier
            })
        
        scored.sort(key=lambda x: x['score'], reverse=True)
        return [s['file'] for s in scored]


@dataclass
class CacheEntry:
    """缓存条目"""
    project_hash: str
    file_hashes: List[str]
    findings: List[dict]
    cached_at: str
    version: str = '1.0'


class AsyncLimiter:
    """异步并发限制器 - 参考 p-limit"""
    
    def __init__(self, max_concurrent: int = 3):
        self._max_concurrent = max_concurrent
        self._current = 0
        self._queue = []
    
    async def __call__(self, func, *args, **kwargs):
        """限制并发调用"""
        if self._current >= self._max_concurrent:
            # 等待队列中有空闲位置
            await self._wait_for_slot()
        
        self._current += 1
        try:
            return await func(*args, **kwargs)
        finally:
            self._current -= 1
            self._notify_waiters()
    
    async def _wait_for_slot(self):
        """等待空闲槽位"""
        import asyncio
        future = asyncio.get_event_loop().create_future()
        self._queue.append(future)
        await future
    
    def _notify_waiters(self):
        """通知等待者"""
        if self._queue and self._current < self._max_concurrent:
            future = self._queue.pop(0)
            future.set_result(None)


class Limiter:
    """同步并发限制器 - 用于同步代码环境"""
    
    def __init__(self, max_concurrent: int = 3):
        self._max_concurrent = max_concurrent
        self._current = 0
        self._queue = []
    
    def __call__(self, func, *args, **kwargs):
        """限制并发调用"""
        if self._current >= self._max_concurrent:
            # 等待队列中有空闲位置
            self._wait_for_slot()
        
        self._current += 1
        try:
            return func(*args, **kwargs)
        finally:
            self._current -= 1
            self._notify_waiters()
    
    def _wait_for_slot(self):
        """等待空闲槽位"""
        import threading
        event = threading.Event()
        self._queue.append(event)
        event.wait()
    
    def _notify_waiters(self):
        """通知等待者"""
        if self._queue and self._current < self._max_concurrent:
            event = self._queue.pop(0)
            event.set()


# 全局优化器实例
_global_optimizer = LLMOptimizer()


def get_optimizer() -> LLMOptimizer:
    """获取全局优化器实例"""
    return _global_optimizer
