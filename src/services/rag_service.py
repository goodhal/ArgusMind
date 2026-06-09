#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""知识库检索服务 - 参考 gbt-codeagent

基于关键词检索安全知识库，增强审计能力：
1. 漏洞类型文档
2. CWE 定义
3. 攻击模式
4. 修复方案
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeDocument:
    """知识库文档"""
    id: str
    title: str
    content: str
    tags: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    severity: str = 'medium'
    category: str = 'general'


class SimpleRetriever:
    """简单检索器"""
    
    def __init__(self, documents: List[KnowledgeDocument]):
        self.documents = documents
        self._index = self._build_index()
    
    def _build_index(self) -> Dict[str, List[KnowledgeDocument]]:
        """构建倒排索引"""
        index = {}
        for doc in self.documents:
            for tag in doc.tags:
                tag_lower = tag.lower()
                if tag_lower not in index:
                    index[tag_lower] = []
                index[tag_lower].append(doc)
            
            for cwe in doc.cwe_ids:
                cwe_lower = cwe.lower()
                if cwe_lower not in index:
                    index[cwe_lower] = []
                index[cwe_lower].append(doc)
        
        return index
    
    def search(self, query: str, top_k: int = 5) -> List[Tuple[KnowledgeDocument, float]]:
        """搜索知识库"""
        lower_query = query.lower()
        scores: List[Tuple[KnowledgeDocument, float]] = []
        seen = set()
        
        for doc in self.documents:
            if doc.id in seen:
                continue
            
            score = 0.0
            
            # 标题匹配（最高权重）
            if lower_query in doc.title.lower():
                score += 10.0
            
            # 标签匹配
            if any(lower_query in tag.lower() for tag in doc.tags):
                score += 5.0
            
            # CWE 匹配
            if any(lower_query in cwe.lower() for cwe in doc.cwe_ids):
                score += 8.0
            
            # 内容匹配
            content_lower = doc.content.lower()
            query_words = [w for w in lower_query.split() if len(w) > 2]
            for word in query_words:
                if word in content_lower:
                    score += 1.0
            
            if score > 0:
                scores.append((doc, score))
                seen.add(doc.id)
        
        # 按评分排序
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


class RAGService:
    """知识库检索服务"""
    
    def __init__(self, knowledge_dir: Optional[str] = None):
        self.knowledge_dir = knowledge_dir or os.path.join(os.getcwd(), 'data', 'knowledge')
        self.retriever = SimpleRetriever(self._load_documents())
    
    def _load_documents(self) -> List[KnowledgeDocument]:
        """加载知识库文档"""
        documents = []
        
        # 加载内置漏洞知识库
        documents.extend(self._load_builtin_knowledge())
        
        # 尝试加载外部知识库文件
        try:
            documents.extend(self._load_external_knowledge())
        except Exception as e:
            logger.warning(f"加载外部知识库失败: {e}")
        
        logger.info(f"知识库加载完成，共 {len(documents)} 条记录")
        return documents
    
    def _load_builtin_knowledge(self) -> List[KnowledgeDocument]:
        """加载内置知识库"""
        return [
            # SQL 注入
            KnowledgeDocument(
                id='sql_injection',
                title='SQL 注入攻击',
                content='SQL注入是一种代码注入技术，攻击者通过在输入字段中插入SQL语句来欺骗数据库执行非授权的查询。常见场景包括：登录表单、搜索框、URL参数等。防护措施：使用参数化查询（PreparedStatement）、使用ORM框架、输入验证、最小权限原则。',
                tags=['sql', 'injection', 'database', 'query'],
                cwe_ids=['CWE-89'],
                severity='high',
                category='injection'
            ),
            # XSS 攻击
            KnowledgeDocument(
                id='xss',
                title='跨站脚本攻击(XSS)',
                content='XSS攻击允许攻击者在受害者浏览器中执行恶意脚本。分为存储型、反射型和DOM型。防护措施：输入过滤、输出编码、使用安全的模板引擎、设置CSP策略。',
                tags=['xss', 'cross-site', 'script', 'web'],
                cwe_ids=['CWE-79'],
                severity='high',
                category='web'
            ),
            # CSRF 攻击
            KnowledgeDocument(
                id='csrf',
                title='跨站请求伪造(CSRF)',
                content='CSRF攻击诱导受害者执行非预期的操作。防护措施：使用CSRF令牌、验证Referer头、使用SameSite Cookie属性、双重提交Cookie。',
                tags=['csrf', 'cross-site', 'request', 'forgery'],
                cwe_ids=['CWE-352'],
                severity='medium',
                category='web'
            ),
            # SSRF 攻击
            KnowledgeDocument(
                id='ssrf',
                title='服务器端请求伪造(SSRF)',
                content='SSRF攻击允许攻击者诱使服务器发起请求到内部资源。防护措施：白名单验证、禁止内网IP、使用URL解析库、禁用危险协议。',
                tags=['ssrf', 'server', 'request', 'forgery'],
                cwe_ids=['CWE-918'],
                severity='high',
                category='web'
            ),
            # 命令注入
            KnowledgeDocument(
                id='command_injection',
                title='命令注入攻击',
                content='命令注入允许攻击者执行任意系统命令。常见于使用shell_exec、exec、system等函数的场景。防护措施：避免使用系统命令、使用白名单、参数化命令执行。',
                tags=['command', 'injection', 'shell', 'system'],
                cwe_ids=['CWE-78'],
                severity='critical',
                category='injection'
            ),
            # 反序列化漏洞
            KnowledgeDocument(
                id='deserialization',
                title='不安全的反序列化',
                content='反序列化漏洞允许攻击者通过构造恶意序列化数据来执行任意代码。常见于Java的Serializable、Python的pickle等。防护措施：使用安全的序列化格式、验证输入、使用白名单类。',
                tags=['deserialization', 'serialization', 'pickle', 'java'],
                cwe_ids=['CWE-502'],
                severity='critical',
                category='code'
            ),
            # 路径遍历
            KnowledgeDocument(
                id='path_traversal',
                title='路径遍历攻击',
                content='路径遍历攻击允许攻击者访问文件系统中的任意文件。常见于文件上传、文件下载功能。防护措施：输入验证、规范化路径、使用白名单目录。',
                tags=['path', 'traversal', 'file', 'directory'],
                cwe_ids=['CWE-22'],
                severity='high',
                category='file'
            ),
            # 硬编码凭据
            KnowledgeDocument(
                id='hardcoded_credentials',
                title='硬编码凭据',
                content='将密码、API密钥、数据库连接字符串等敏感信息硬编码在源代码中是严重的安全问题。防护措施：使用环境变量、配置文件、密钥管理服务。',
                tags=['hardcoded', 'credentials', 'password', 'secret'],
                cwe_ids=['CWE-798'],
                severity='critical',
                category='secrets'
            ),
            # 认证绕过
            KnowledgeDocument(
                id='auth_bypass',
                title='认证绕过',
                content='攻击者通过各种手段绕过身份验证机制。常见方式包括：弱密码策略、会话固定、未验证的重定向、逻辑缺陷。防护措施：强密码策略、多因素认证、会话管理、输入验证。',
                tags=['authentication', 'bypass', 'login', 'session'],
                cwe_ids=['CWE-287'],
                severity='critical',
                category='auth'
            ),
            # 权限提升
            KnowledgeDocument(
                id='privilege_escalation',
                title='权限提升',
                content='权限提升攻击允许攻击者获得比正常权限更高的访问级别。分为垂直提升和水平提升。防护措施：最小权限原则、权限验证、审计日志。',
                tags=['privilege', 'escalation', 'permission', 'role'],
                cwe_ids=['CWE-269'],
                severity='high',
                category='auth'
            ),
            # 文件上传漏洞
            KnowledgeDocument(
                id='file_upload',
                title='文件上传漏洞',
                content='文件上传漏洞允许攻击者上传恶意文件到服务器。防护措施：文件类型验证、文件重命名、存储目录隔离、禁用脚本执行。',
                tags=['file', 'upload', 'malicious', 'webshell'],
                cwe_ids=['CWE-434'],
                severity='high',
                category='file'
            ),
            # 日志注入
            KnowledgeDocument(
                id='log_injection',
                title='日志注入',
                content='日志注入攻击允许攻击者通过构造恶意输入来伪造日志条目或执行命令。防护措施：输入验证、日志内容转义、避免将用户输入直接写入日志。',
                tags=['log', 'injection', 'logging', 'forging'],
                cwe_ids=['CWE-117'],
                severity='medium',
                category='code'
            ),
            # 开放重定向
            KnowledgeDocument(
                id='open_redirect',
                title='开放重定向',
                content='开放重定向漏洞允许攻击者将用户重定向到恶意网站。常见于登录成功后的重定向、密码重置链接。防护措施：验证重定向URL、使用白名单、避免使用用户可控参数。',
                tags=['redirect', 'open', 'url', 'phishing'],
                cwe_ids=['CWE-601'],
                severity='medium',
                category='web'
            ),
            # CORS 配置缺陷
            KnowledgeDocument(
                id='cors_misconfig',
                title='CORS配置缺陷',
                content='CORS配置不当可能导致跨域请求被滥用。防护措施：使用白名单域名、不要使用通配符、正确配置Credentials。',
                tags=['cors', 'cross-origin', 'config', 'web'],
                cwe_ids=['CWE-942'],
                severity='medium',
                category='web'
            ),
            # XXE 攻击
            KnowledgeDocument(
                id='xxe',
                title='XML外部实体注入(XXE)',
                content='XXE攻击允许攻击者通过XML实体引用读取文件或发起请求。防护措施：禁用外部实体、使用安全的XML解析器、验证输入。',
                tags=['xxe', 'xml', 'entity', 'external'],
                cwe_ids=['CWE-611'],
                severity='high',
                category='injection'
            ),
            # 弱加密
            KnowledgeDocument(
                id='weak_crypto',
                title='弱加密算法',
                content='使用不安全的加密算法可能导致数据泄露。常见问题：使用MD5、SHA-1、DES、3DES等已被破解的算法。防护措施：使用AES-256、SHA-256、RSA-2048+等强算法。',
                tags=['crypto', 'encryption', 'hash', 'algorithm'],
                cwe_ids=['CWE-327'],
                severity='medium',
                category='cryptography'
            ),
            # 敏感信息泄露
            KnowledgeDocument(
                id='info_leak',
                title='敏感信息泄露',
                content='敏感信息泄露包括：错误信息泄露、版本信息泄露、调试信息泄露、配置文件泄露等。防护措施：禁用详细错误信息、移除调试代码、安全处理配置文件。',
                tags=['information', 'leak', 'exposure', 'debug'],
                cwe_ids=['CWE-200'],
                severity='medium',
                category='secrets'
            ),
            # 竞争条件
            KnowledgeDocument(
                id='race_condition',
                title='竞争条件',
                content='竞争条件发生在多个线程或进程同时访问共享资源时。常见于：检查-然后-执行、资源分配、计数器操作。防护措施：使用同步机制、原子操作、锁。',
                tags=['race', 'condition', 'thread', 'concurrency'],
                cwe_ids=['CWE-362'],
                severity='high',
                category='code'
            )
        ]
    
    def _load_external_knowledge(self) -> List[KnowledgeDocument]:
        """加载外部知识库文件"""
        documents = []
        
        if not os.path.exists(self.knowledge_dir):
            return documents
        
        for filename in os.listdir(self.knowledge_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.knowledge_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                doc = KnowledgeDocument(
                                    id=item.get('id', ''),
                                    title=item.get('title', ''),
                                    content=item.get('content', ''),
                                    tags=item.get('tags', []),
                                    cwe_ids=item.get('cwe_ids', []),
                                    severity=item.get('severity', 'medium'),
                                    category=item.get('category', 'general')
                                )
                                documents.append(doc)
                except Exception as e:
                    logger.warning(f"加载知识库文件 {filename} 失败: {e}")
        
        return documents
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """搜索知识库"""
        results = self.retriever.search(query, top_k)
        return [
            {
                'id': doc.id,
                'title': doc.title,
                'content': doc.content,
                'tags': doc.tags,
                'cwe_ids': doc.cwe_ids,
                'severity': doc.severity,
                'category': doc.category,
                'score': score
            }
            for doc, score in results
        ]
    
    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按类别获取文档"""
        docs = [doc for doc in self.retriever.documents if doc.category == category]
        return [
            {
                'id': doc.id,
                'title': doc.title,
                'content': doc.content,
                'tags': doc.tags,
                'cwe_ids': doc.cwe_ids,
                'severity': doc.severity,
                'category': doc.category
            }
            for doc in docs
        ]
    
    def get_by_cwe(self, cwe_id: str) -> List[Dict[str, Any]]:
        """按 CWE ID 获取文档"""
        docs = [doc for doc in self.retriever.documents if cwe_id.lower() in [c.lower() for c in doc.cwe_ids]]
        return [
            {
                'id': doc.id,
                'title': doc.title,
                'content': doc.content,
                'tags': doc.tags,
                'cwe_ids': doc.cwe_ids,
                'severity': doc.severity,
                'category': doc.category
            }
            for doc in docs
        ]


# 全局服务实例
_global_rag_service = RAGService()


def get_rag_service() -> RAGService:
    """获取全局知识库服务实例"""
    return _global_rag_service
