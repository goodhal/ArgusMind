# -*- coding: utf-8 -*-
"""Orchestrator —— 审计流水编排核心。

相比最初版本的变化：
1. `run()` 接收 `ExecutionContext`：task_id / project_id / project_name / project_path / llm_config / opencode_config
   全部由上游 `audit_service.run_task` 从 DB 读取传入，不再硬编码
2. 根节点为 Neo4j `Task`；`Information Collection / make a plan` 等 `AuditStage` 统一用 `merge_node` / `HAS_STAGE` 幂等挂载
3. 所有运行日志通过 `LogEvent` 发布到事件总线 → 落入 logs 表
4. 任务状态流转通过 `TaskStatusEvent` 发布
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------- 动态线程池大小计算 ----------
def _get_optimal_workers(base: int = 2, max_limit: int = 8) -> int:
    """根据 CPU 核心数动态计算合适的线程池大小。
    
    对于 I/O 密集型任务（如文件扫描），可以设置更高的并发。
    """
    cpu_count = os.cpu_count() or 4
    # I/O 密集型：CPU * 2，最多不超过 max_limit
    optimal = min(cpu_count * 2, max_limit)
    return max(base, optimal)


import src.storage.manager as db_manager
from src.core.enums import ActionType
from src.agents.brain import Brain
from src.agents.chain_analyzer import ChainAnalyzer
from src.agents.context import BrainContext
from src.agents.plan import Plan
from src.agents.project_info import ProjectInfo
from src.agents.sink_finder import SinkFinder
from src.core.event_bus import get_event_bus
from src.core.event_span import start_event_span
from src.core.events import LogEvent, TaskStatusEvent, EventStart
from src.core.context import ExecutionContext
from src.core.task_control import TaskPausedError, ensure_task_running, get_task_control
from src.core.code_agent_run_registry import abort_code_agent_for_task
from src.llm import LLMError
from src.core.audit_state import AuditState, AgentStatus
from src.core.circuit_breaker import get_circuit_breaker_registry, CircuitOpenError, CircuitBreakerConfig
from src.core.retry import with_retry, RetryConfig
from src.core.policies import OrchestratorPolicy
from src.services.smart_file_filter import SmartFileFilter
from src.services.project_service import get_project
from src.services.chain_analysis_service import (
    ensure_knowledge_element_id_for_risk_category,
    fetch_non_completed_analysis_results_for_vul,
    reset_non_completed_analysis_results_to_pending_for_vul,
)
from src.services.plan_service import (
    fetch_all_pending_risk_categories,
    fetch_all_pending_risk_categories_global,
    fetch_next_pending_language_for_plan,
    find_completed_plan_stage_node_id_for_task,
    mark_language_status,
    mark_risk_category_status,
    mark_risk_category_sink_finder_completed,
    persist_plan,
    reset_running_audit_nodes_to_pending_for_task,
    check_language_all_categories_completed,
)
from src.services.event_service import fail_running_non_information_events_for_task, complete_running_events_for_task
from src.services.sink_flow_service import (
    SINK_FLOW_LEAF_STATUS_RUNNING,
    fetch_next_pending_sink_chain_path,
    mark_sink_flow_leaf_status,
    reset_running_sink_and_chain_nodes_to_pending_for_task,
)
from src.utils.ids import generate_id
from src.knowledge.audit_config import AUDIT_SCHEDULING, AUDIT_PROFILES
from src.services.quick_scan_service import QuickScanService
from src.services.pattern_analyzer import PatternAnalyzer
from src.services.coverage_tracker import CoverageTracker
from src.services.quick_scan_filter import QuickScanFilter
from src.services.quick_scan_verifier import QuickScanVerifier
from src.services.llm_optimizer import LLMOptimizer
from src.services.component_vuln_service import (
    scan_project_dependencies,
    ScanResult as ComponentScanResult,
)
from src.analyzers.ast_enricher import get_global_ast_enricher, ASTEnricherService


class Orchestrator:
    """ReAct 风格的审计流程编排器"""
    MODULE_NAME = "Orchestrator"

    def __init__(self) -> None:
        self._bus = get_event_bus()

    # ---------- 日志辅助 ----------
    def _log(self, task_id: str, level: str, message: str) -> None:
        self._bus.publish_async(
            LogEvent(level=level, module=self.MODULE_NAME, message=message, task_id=task_id)
        )

    # ---------- 超时看门狗 ----------
    def _timeout_watchdog(self, task_id: str, started_at: float, timeout_seconds: int) -> None:
        """后台守护线程：每 30 秒检查任务是否超时，超时则自动取消。"""
        check_interval = 30
        while True:
            time.sleep(check_interval)
            ctrl = get_task_control()
            if ctrl.is_stopped(task_id) or ctrl.is_paused(task_id):
                return  # 任务已被手动停止/暂停，看门狗退出

            elapsed = time.time() - started_at
            if elapsed >= timeout_seconds:
                self._cancel_on_timeout(task_id, elapsed)
                return

    def _cancel_on_timeout(self, task_id: str, elapsed_seconds: float) -> None:
        """超时自动取消任务：停止信号 + 中断外部工具 + 更新 DB + 发布事件。"""
        elapsed_minutes = elapsed_seconds / 60.0
        try:
            ctrl = get_task_control()
            ctrl.set_stopped(task_id)
            abort_code_agent_for_task(task_id, reason="timeout")

            self._bus.publish(LogEvent(
                level="WARNING",
                module=self.MODULE_NAME,
                message=f"任务执行超时（{elapsed_minutes:.1f} 分钟），自动取消",
                task_id=task_id,
            ))
            self._bus.publish(EventStart(
                task_id=task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason=f"任务超时自动取消（{elapsed_minutes:.1f} 分钟）",
                status="failed",
            ))
            self._bus.publish(TaskStatusEvent(
                task_id=task_id,
                status="cancelled",
                message=f"任务执行超时，已自动取消（{elapsed_minutes:.1f} 分钟）",
            ))

            # 更新 DB 状态
            from src.services.task_service import update_task
            from src.schemas.task import TaskUpdate
            update_task(task_id, TaskUpdate(
                status="cancelled",
                error=f"任务执行超时（{elapsed_minutes:.1f} 分钟），已自动取消",
            ))
        except Exception:
            self._log(task_id, "WARNING", f"任务超时处理异常: {elapsed_minutes:.1f} 分钟")

    # ---------- Neo4j 幂等封装 ----------
    def _ensure_task_node(self, ctx: ExecutionContext) -> str:
        """按 task_id 幂等创建 Neo4j Task 根节点（承载项目名/路径等展示字段）。返回 node_id。"""
        match_props = {"task_id": ctx.task_id}
        existed = db_manager.neo4j_repository.find_node("Task", match_props)
        if existed:
            self._log(
                ctx.task_id,
                "INFO",
                f"Neo4j Task 根节点已存在，复用 elementId={existed.get('elementId')}",
            )
            return existed.get("node_id") or existed.get("elementId")

        node_id = generate_id()
        db_manager.neo4j_repository.merge_node(
            "Task",
            match_properties=match_props,
            extra_properties={
                "created_at": datetime.now().isoformat(),
                "node_id": node_id,
                "project_id": ctx.project_id,
                "name": ctx.project_name,
                "task_id": ctx.task_id,
                "path": str(ctx.project_path),
            },
        )
        return node_id

    def _mark_stage_completed(self, task_id: str, stage_name: str) -> None:
        """将指定 AuditStage 节点及其子节点标记为 completed（前端链路图实时更新）。"""
        try:
            # 更新父节点
            db_manager.neo4j_repository.update_node(
                {"label": "AuditStage", "name": stage_name, "task_id": task_id},
                {"status": "completed", "end_time": datetime.now().isoformat()},
            )
            # 更新子节点（通过 HAS_STAGE 关系）
            query = """
            MATCH (parent:AuditStage {name: $stage_name, task_id: $task_id})-[:HAS_STAGE]->(child)
            SET child.status = 'completed', child.end_time = $end_time
            RETURN count(child) as updated_count
            """
            result = db_manager.neo4j_repository.client.execute_write(
                query,
                {
                    "stage_name": stage_name,
                    "task_id": task_id,
                    "end_time": datetime.now().isoformat(),
                },
            )
            if result and result[0]["updated_count"] > 0:
                self._log(
                    task_id,
                    "INFO",
                    f"标记阶段完成（{stage_name}）: 同时更新 {result[0]['updated_count']} 个子节点",
                )
        except Exception as e:
            self._log(task_id, "WARNING", f"标记阶段完成失败（{stage_name}）: {e}")

    def _ensure_stage_node(
        self,
        ctx: ExecutionContext,
        parent_node_id: str,
        stage_name: str,
        *,
        parent_label: str = "Task",
    ) -> str:
        """按 (task_id, name) 幂等创建 AuditStage，并与父节点建 HAS_STAGE。

        ``parent_label`` 须与 ``parent_node_id`` 所指节点标签一致：首阶段挂在 ``Task`` 上，
        后续阶段（如 ``make a plan``）挂在上一 ``AuditStage`` 上。若误用 ``Task``，
        ``create_relationship`` 会 MERGE 出错误的 ``Task {node_id: <AuditStage的 id>}``。
        """
        match_props = {"name": stage_name, "task_id": ctx.task_id}
        existed = db_manager.neo4j_repository.find_node("AuditStage", match_props)
        if existed:
            self._log(
                ctx.task_id,
                "INFO",
                f"Neo4j 阶段节点已存在（{stage_name}），复用 node_id={existed.get('node_id')}",
            )
            return existed.get("node_id") or existed.get("elementId")

        node_id = generate_id()
        db_manager.neo4j_repository.create_relationship(
            from_node={"label": parent_label, "node_id": parent_node_id},
            to_node={
                "label": "AuditStage",
                "name": stage_name,
                "status": "running",
                "task_id": ctx.task_id,
                "created_at": datetime.now().isoformat(),
                "node_id": node_id,
            },
            relationship_type="HAS_STAGE",
        )
        return node_id

    # 统一文件收集常量
    _SKIP_DIRS = frozenset({
        "node_modules", ".git", "__pycache__", ".idea", ".vscode",
        "target", "build", "dist", ".next", ".nuxt", "vendor",
        ".gradle", ".mvn", "venv", ".env", "env",
    })
    _SKIP_EXTS = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot",
        ".mp3", ".mp4", ".zip", ".tar", ".gz",
        ".lock", ".md5", ".sha256", ".log", ".tmp", ".bak",
    })

    def _collect_project_files(self, project_path: str) -> List[str]:
        """一次性遍历项目目录，返回相对路径文件列表。

        后续 SmartFileFilter / QuickScanService / CoverageTracker 等均复用此列表，
        避免各自重复 os.walk。
        """
        files: List[str] = []
        for root, dirs, filenames in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in self._SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                _, ext = os.path.splitext(fname)
                if ext.lower() in self._SKIP_EXTS:
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, project_path).replace("\\", "/")
                files.append(rel_path)
        return files

    def _collect_or_reuse_project_info(
        self,
        ctx: ExecutionContext,
        shared_brain: Brain,
        information_collection_id: str,
        project_file_list: list,
    ) -> bool:
        _code_exts = {
            ".py", ".java", ".js", ".ts", ".php", ".rb", ".go", ".rs",
            ".cs", ".cpp", ".c", ".h", ".kt", ".swift", ".scala",
            ".jsx", ".tsx", ".vue", ".svelte", ".dart", ".lua", ".r",
        }
        has_code_files = any(
            os.path.splitext(f)[1].lower() in _code_exts for f in project_file_list
        )
        try:
            project = get_project(ctx.project_id)
            db_description = (getattr(project, "description", "") or "").strip()
            db_description_compact = (getattr(project, "description_compact", "") or "").strip()
            db_project_session_id = getattr(project, "session_id", "").strip()
            if db_description and db_description_compact:
                if not has_code_files:
                    self._log(ctx.task_id, "WARNING",
                              f"项目目录无源代码文件（共 {len(project_file_list)} 个文件），"
                              "清除旧缓存描述，重新收集信息")
                    try:
                        project.description = ""
                        project.description_compact = ""
                        from src.infrastructure.db import session_scope as _ss
                        with _ss() as _s:
                            _s.merge(project)
                            _s.commit()
                    except Exception:
                        pass
                else:
                    shared_brain.project_info = db_description
                    shared_brain.project_info_compact = db_description_compact
                    shared_brain.set_project_info_session_id(db_project_session_id)
                    self._log(ctx.task_id, "INFO", "复用项目描述信息，跳过信息收集")
                    db_manager.neo4j_repository.update_node(
                        {"label": "AuditStage", "node_id": information_collection_id},
                        {"status": "completed", "end_time": datetime.now().isoformat()},
                    )
                    return True
        except Exception:
            pass

        # 使用 EventSpan 自动管理 start/finish，避免 running 事件泄漏
        info_span = start_event_span(
            task_id=ctx.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.INFORMATION,
            reason="开始信息收集",
        )
        try:
            project_info = ProjectInfo(brain=shared_brain)
            project_info.run()
            if not shared_brain.project_info:
                # OpenCode 不可用或返回空：用 Tokei + 文件列表生成基础 project_info
                self._log(ctx.task_id, "WARNING", "OpenCode 信息收集为空，使用 LLM 兜底")
                shared_brain.project_info = self._build_llm_fallback_project_info(ctx, project_file_list, shared_brain)
                shared_brain.project_info_compact = shared_brain.project_info
                if not shared_brain.project_info:
                    self._log(ctx.task_id, "ERROR", "兜底信息收集也为空")
                    info_span.mark_failed("信息收集结果为空")
                    self._bus.publish(
                        TaskStatusEvent(task_id=ctx.task_id, status="failed", message="信息收集结果为空")
                    )
                    return False
            db_manager.neo4j_repository.update_node(
                {"label": "AuditStage", "node_id": information_collection_id},
                {"status": "completed", "end_time": datetime.now().isoformat()},
            )
            # 智能文件过滤：基于风险评分筛选高优先级文件
            try:
                file_filter = SmartFileFilter(project_path=str(ctx.project_path))
                risk_files = file_filter.get_high_risk_files(file_list=project_file_list)
                if risk_files:
                    shared_brain.risk_files = risk_files
                    # 基于 EALOC 动态调整批次大小
                    total_ealoc = sum(e.get("ealoc", 0) for e in risk_files)
                    avg_ealoc = total_ealoc / len(risk_files) if risk_files else 0
                    suggested_batch = max(3, min(15, int(500 / avg_ealoc))) if avg_ealoc > 0 else 6
                    self._log(
                        ctx.task_id,
                        "INFO",
                        f"SmartFileFilter 识别到 {len(risk_files)} 个高风险文件，"
                        f"EALOC={total_ealoc}，建议批次大小={suggested_batch}",
                    )
                    # 将建议批次大小写入 shared_brain 供后续调度使用
                    shared_brain.suggested_batch_size = suggested_batch
            except Exception as filter_ex:
                self._log(
                    ctx.task_id,
                    "WARNING",
                    f"SmartFileFilter 执行失败（不影响主流程）: {filter_ex}",
                )
            info_span.finish()
            return True
        except Exception as ex:
            info_span.mark_failed(str(ex))
            self._log(ctx.task_id, "ERROR", str(ex))
            raise

    def _build_offline_project_info(self, ctx: ExecutionContext, project_file_list: list) -> str:
        """脱机模式专用：纯 Tokei + 文件统计生成 project_info，零 LLM 调用。"""
        try:
            project_path = str(ctx.project_path)
            tokei_stats = self._run_tokei(project_path)

            fallback = [f"# 项目信息（自动推断，脱机模式）\n"]
            fallback.append(f"项目名称: {ctx.project_name}")
            fallback.append(f"文件总数: {len(project_file_list)}")
            if tokei_stats:
                fallback.append(tokei_stats)
            else:
                from collections import Counter
                ext_counter = Counter()
                for f in project_file_list:
                    _, ext = os.path.splitext(f)
                    if ext:
                        ext_counter[ext.lower()] += 1
                if ext_counter:
                    fallback.append("\n## 文件类型分布")
                    for ext, count in ext_counter.most_common(10):
                        fallback.append(f"- {ext}: {count} 文件")
                fallback.append(f"\n总计: {len(project_file_list)} 文件")
            fallback.append("\n## 基于文件列表和语言统计的自动推断，可能不完整。")
            return "\n".join(fallback)
        except Exception as e:
            self._log(ctx.task_id, "WARNING", f"脱机信息收集失败: {e}")
            return ""

    def _build_llm_fallback_project_info(self, ctx: ExecutionContext, project_file_list: list, shared_brain: Brain) -> str:
        """联机模式兜底：OpenCode 不可用时，收集关键文件，交由 LLM 分析生成 project_info。"""
        try:
            project_path = str(ctx.project_path)
            # 1) 收集关键文件
            snippets = self._collect_key_file_snippets(project_path, project_file_list)
            tokei_stats = self._run_tokei(project_path)

            # 2) 调用 LLM 分析
            prompt = f"""你是一个软件项目分析专家。请根据以下信息，生成一份简洁的项目技术栈分析报告。

**项目名称**: {ctx.project_name}
**文件总数**: {len(project_file_list)}
{tokei_stats}

**关键文件内容**:
{chr(10).join(snippets) if snippets else '(无关键文件)'}

请用中文输出以下格式的项目信息：

## 项目概述
[1-2句话概括项目类型、用途]

## 技术栈
- 后端: [语言+框架]
- 前端: [框架/库]
- 数据库: [类型]
- 其他: [构建工具、中间件等]

## 安全关注点
基于技术栈，列出需要重点审计的漏洞类型（如SQL注入、命令注入、XSS、反序列化等）

请直接输出分析报告，不要输出其他内容。"""
            try:
                response = shared_brain.llm.call(
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1000,
                    temperature=0.3,
                )
                text = response.content or ""
                # 上报 token 用量
                if ctx.task_id and (response.prompt_tokens or response.completion_tokens):
                    try:
                        from src.services.token_service import report_token_usage
                        report_token_usage(
                            task_id=ctx.task_id,
                            llm_input=response.prompt_tokens,
                            llm_output=response.completion_tokens,
                            note="project_info",
                        )
                        # 上报 LLM prompt cache 命中统计
                        if response.cached_tokens and response.prompt_tokens:
                            report_token_usage(
                                task_id=ctx.task_id,
                                llm_input=response.cached_tokens,
                                llm_output=response.prompt_tokens - response.cached_tokens,
                                note="cache_stats:project_info",
                            )
                    except Exception:
                        pass
                if text and text.strip():
                    return text.strip()
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"LLM 分析项目信息失败: {e}")

            # 3) LLM 失败：降级为纯统计兜底（等同于脱机模式）
            self._log(ctx.task_id, "INFO", "LLM 兜底收集失败，降级使用纯统计兜底")
            return self._build_offline_project_info(ctx, project_file_list)
        except Exception as e:
            self._log(ctx.task_id, "WARNING", f"联机兜底信息收集失败: {e}")
            return ""

    def _collect_key_file_snippets(self, project_path: str, project_file_list: list) -> list:
        """收集关键文件（构建文件/入口/README）的内容片段。"""
        key_patterns = [
            "pom.xml", "build.gradle", "package.json", "requirements.txt",
            "Cargo.toml", "go.mod", "Makefile", "CMakeLists.txt", "setup.py",
            "composer.json", "Gemfile", "yarn.lock", "pnpm-lock.yaml",
            "main.py", "app.py", "index.js", "app.js", "server.js",
            "main.go", "main.rs", "Program.cs", "index.ts",
            "README.md", "readme.md", "README", "README.txt",
            "application.yml", "application.properties", ".env.example",
        ]
        key_files = []
        for f in project_file_list[:500]:
            basename = os.path.basename(f).lower()
            if basename in [p.lower() for p in key_patterns]:
                key_files.append(f)

        key_files = key_files[:15]
        snippets = []
        for rel_path in key_files:
            abs_path = os.path.join(project_path, rel_path)
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                if len(content) > 4000:
                    content = content[:4000] + f"\n... (截断，原文 {len(content)} 字符)"
                snippets.append(f"### {rel_path}\n```\n{content}\n```")
            except Exception as read_ex:
                snippets.append(f"### {rel_path}\n(无法读取: {read_ex})")
        return snippets

    def _run_tokei(self, project_path: str) -> str:
        """运行 Tokei 获取语言统计，返回 Markdown 格式字符串。"""
        try:
            from src.tools import TokeiTool
            tokei = TokeiTool()
            result = tokei.run(project_path)
            if result.success and result.data:
                langs = result.data.get("languages", {})
                total = result.data.get("total", {})
                stats = "\n## 语言分布 (Tokei)\n"
                for lang, s in sorted(langs.items(), key=lambda x: -x[1].get("code", 0)):
                    stats += f"- **{lang}**: {s.get('files', 0)} 文件, {s.get('code', 0)} 行代码\n"
                stats += f"\n总计: {total.get('code', 0)} 行代码, {total.get('files', 0)} 文件\n"
                return stats
        except Exception:
            pass
        return ""

    # ---------- 主流程 ----------
    def run(self, ctx: ExecutionContext) -> None:
        ensure_task_running(ctx.task_id)
        failed_count = fail_running_non_information_events_for_task(ctx.task_id)
        if failed_count:
            self._log(
                ctx.task_id,
                "INFO",
                f"已将 {failed_count} 条遗留 running 事件（非 information）标为 failed",
            )
        self._bus.publish(TaskStatusEvent(task_id=ctx.task_id, status="running"))
        self._log(ctx.task_id, "INFO", f"开始编排任务 {ctx.task_id}")

        # 初始化审计状态管理器
        audit_state = AuditState()
        audit_state.start()
        audit_state.update_progress(0, 4, "初始化")

        # 启动超时看门狗
        policy = OrchestratorPolicy()
        task_started_at = time.time()
        if policy.task_timeout_minutes > 0:
            timeout_seconds = policy.task_timeout_minutes * 60
            watchdog = threading.Thread(
                target=self._timeout_watchdog,
                args=(ctx.task_id, task_started_at, timeout_seconds),
                daemon=True,
            )
            watchdog.start()
            self._log(
                ctx.task_id, "INFO",
                f"超时看门狗已启动：超时={policy.task_timeout_minutes}分钟 "
                f"（环境变量 ARGUSMIND_TASK_TIMEOUT_MINUTES={os.environ.get('ARGUSMIND_TASK_TIMEOUT_MINUTES', '120')}）"
            )

        # 记录审计配置
        mode_label = "脱机（仅规则引擎）" if ctx.offline_mode else "完整（LLM + 规则引擎）"
        self._log(
            ctx.task_id,
            "INFO",
            f"审计模式：{mode_label}，"
            f"策略={list(AUDIT_PROFILES.keys())}，"
            f"批次={AUDIT_SCHEDULING.get('maxFilesPerBatch', 6)}文件/批，"
            f"并行={AUDIT_SCHEDULING.get('maxParallelRequests', 5)}请求",
        )

        try:
            brain_ctx = BrainContext(
                project_id=ctx.project_id,
                project_name=ctx.project_name,
                project_path=str(ctx.project_path),
                task_id=ctx.task_id,
                llm_config=ctx.llm_config,
                offline_mode=ctx.offline_mode,
            )
            # 创建【开始初始化项目】事件
            shared_brain = Brain(brain_ctx)

            # 读取选择性重跑的阶段列表
            stages_to_rerun = None
            from src.infrastructure.db import session_scope as _session_scope
            from src.repositories.task_repository import TaskRepository as _TaskRepo
            try:
                with _session_scope() as _s:
                    _task = _TaskRepo(_s).get(ctx.task_id)
                    if _task and getattr(_task, "stages_to_rerun", None):
                        stages_to_rerun = set(_task.stages_to_rerun)
                        self._log(ctx.task_id, "INFO", f"选择性重跑阶段: {stages_to_rerun}")
            except Exception:
                pass

            # 0) 统一文件收集（避免后续各服务重复 os.walk）
            project_file_list = self._collect_project_files(str(ctx.project_path))
            self._log(ctx.task_id, "INFO", f"项目文件收集完成: {len(project_file_list)} 个文件")

            # 0) Task 根节点（幂等，替代原 Project 根）
            task_root_node_id = self._ensure_task_node(ctx)

            # 1) 信息收集阶段
            audit_state.update_progress(1, 4, "信息收集")

            # 选择性重跑：跳过信息收集阶段
            if stages_to_rerun and "information_collection" not in stages_to_rerun:
                self._log(ctx.task_id, "INFO", "选择性重跑：跳过信息收集阶段，复用已有数据")
            else:
                information_collection_id = self._ensure_stage_node(
                    ctx, task_root_node_id, "Information Collection"
                )
                self._log(ctx.task_id, "INFO", f"信息收集阶段 node_id={information_collection_id}")

                # 脱机模式：跳过 LLM 信息收集，用 Tokei 生成基础 project_info
                if ctx.offline_mode:
                    self._log(ctx.task_id, "INFO", "脱机模式：使用 Tokei 推断项目信息")
                    shared_brain.project_info = self._build_offline_project_info(
                        ctx, project_file_list
                    )
                    shared_brain.project_info_compact = shared_brain.project_info
                else:
                    # 信息收集（必须先完成，Plan 和 QuickScan 都依赖 project_info）
                    if not self._collect_or_reuse_project_info(ctx, shared_brain, information_collection_id, project_file_list):
                        return
                self._mark_stage_completed(ctx.task_id, "信息收集")

            # 1.2) ProjectManifest 预扫描：为每个审计阶段生成热点文件清单
            try:
                from src.services.project_manifest import ensure_project_manifest
                project_manifest = ensure_project_manifest(
                    project_path=str(ctx.project_path),
                    task_id=ctx.task_id,
                    file_list=project_file_list,
                )
                shared_brain.project_manifest = project_manifest
                manifest_summary = project_manifest.to_dict()
                self._log(
                    ctx.task_id, "INFO",
                    f"ProjectManifest 预扫描完成: "
                    f"路由候选={manifest_summary.get('route_candidate_count', 0)}, "
                    f"阶段热点={manifest_summary.get('stage_hotspot_counts', {})}",
                )
                self._bus.publish(EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=f"ProjectManifest: {manifest_summary.get('route_candidate_count', 0)} 路由候选",
                    status="completed",
                    result=json.dumps(manifest_summary, ensure_ascii=False),
                ))
            except Exception as manifest_ex:
                self._log(ctx.task_id, "WARNING", f"ProjectManifest 预扫描失败（不影响主流程）: {manifest_ex}")

            # 1.5) 信息收集完成后，Plan 和 QuickScan 并行执行
            # Plan 只依赖 project_info，不依赖 QuickScan 结果
            # QuickScan 只依赖文件列表，不依赖 Plan
            # 两者在 Sink/Chain 开始前汇合即可
            # 脱机模式：跳过 Plan（LLM），仅执行 QuickScan
            # 选择性重跑：如果不需要重跑 planning，也跳过
            _skip_planning = stages_to_rerun and "planning" not in stages_to_rerun

            plan_result = None
            plan_id = None
            reused_plan_id = None
            quick_scan_findings = []
            scan_stats = None

            def _run_plan():
                """生成审计计划（LLM 调用 + 人工审批）"""
                nonlocal plan_result, plan_id, reused_plan_id
                try:
                    reused_plan_id = find_completed_plan_stage_node_id_for_task(ctx.task_id)
                    if reused_plan_id:
                        plan_id = reused_plan_id
                        self._log(ctx.task_id, "INFO", f"复用已有审计计划 plan_id={plan_id}")
                        return True

                    plan_id = self._ensure_stage_node(
                        ctx,
                        information_collection_id,
                        "make a plan",
                        parent_label="AuditStage",
                    )
                    self._log(ctx.task_id, "INFO", f"生成审计计划 plan_id={plan_id}")

                    plan_agent = Plan(brain=shared_brain)
                    plan_result = plan_agent.run()

                    if plan_result:
                        # 进行人机交互 确认审计计划 或者新增审计计划
                        interaction_id = uuid.uuid4().hex
                        plan_span = start_event_span(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.HUMAN_APPROVAL,
                            reason=interaction_id,
                        )
                        approval_result = shared_brain.wait_for_human_approval(
                            message=json.dumps(plan_result),
                            timeout_seconds=120,
                            auto_approve_on_timeout=True,
                            interaction_id=interaction_id,
                            interaction_type="plan"
                        )
                        plan_result = json.loads(approval_result.get("message", plan_result))
                        persist_plan(plan_id, plan_result, ctx.task_id)

                        db_manager.neo4j_repository.update_node(
                            {"label": "AuditStage", "node_id": plan_id},
                            {"status": "completed", "end_time": datetime.now().isoformat()},
                        )
                        plan_span.finish()
                    return bool(plan_result)
                except Exception as plan_ex:
                    self._log(ctx.task_id, "ERROR", f"[Checkpoint] _run_plan 异常: {plan_ex}")
                    raise

            def _run_quick_scan_pipeline():
                """快速扫描 + 后处理（LLMOptimizer + QuickScanFilter）"""
                nonlocal quick_scan_findings, scan_stats
                # 快速扫描
                try:
                    quick_scanner = QuickScanService()
                    scan_result = quick_scanner.scan_project(str(ctx.project_path), file_list=project_file_list)
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"快速扫描执行失败: {e}")
                    return

                if not scan_result:
                    return

                quick_scan_findings = scan_result.get("findings", [])
                scan_stats = scan_result.get("stats", {})
                # 设置来源模式（从项目的 source_type 推导）
                try:
                    from src.services.project_service import get_project as _get_proj
                    _proj = _get_proj(ctx.project_id)
                    _st = getattr(_proj, "source_type", "") or ""
                    _source_mode_map = {
                        "zip": "ZIP 代码包上传",
                        "git": "Git 仓库克隆",
                        "url": "URL 导入",
                        "local": "本地代码导入",
                        "github": "GitHub 候选发现",
                        "gitee": "Gitee 候选发现",
                    }
                    scan_stats["source_mode"] = _source_mode_map.get(_st.lower(), _st or "未知")
                except Exception:
                    scan_stats.setdefault("source_mode", "未知")
                if quick_scan_findings:
                    self._log(ctx.task_id, "INFO",
                              f"快速扫描完成: 发现 {len(quick_scan_findings)} 个潜在问题 "
                              f"(代码={scan_stats.get('code_findings', 0)}, "
                              f"组件={scan_stats.get('component_findings', 0)})")
                else:
                    self._log(ctx.task_id, "INFO", "快速扫描完成: 未发现明显问题")

                # QuickScan 子阶段：规则扫描完成
                self._ensure_stage_node(ctx, _quick_scan_stage_id, "规则扫描", parent_label="AuditStage")

                # ── PatternAnalyzer：独立模式匹配（不依赖 sink，直接产出发现并入库）──
                self._ensure_stage_node(ctx, _quick_scan_stage_id, "模式匹配", parent_label="AuditStage")
                try:
                    pattern_analyzer = PatternAnalyzer()
                    # 复用 QuickScanService 已读入的文件缓存，避免重复 I/O
                    pattern_analyzer.set_file_content_cache(
                        quick_scanner.get_file_content_cache()
                    )
                    pa_result = pattern_analyzer.analyze_files(
                        file_paths=[
                            str(ctx.project_path / f) for f in project_file_list
                            if os.path.splitext(f)[1].lower() in (
                                ".py", ".java", ".js", ".ts", ".php", ".rb",
                                ".go", ".rs", ".cs", ".cpp", ".c", ".h",
                                ".kt", ".swift", ".scala", ".jsx", ".tsx",
                            )
                        ],
                        max_workers=8,
                    )
                    # 缓存到 shared_brain，避免 SinkFinder 每个 category 重复 os.walk + PatternAnalyzer
                    shared_brain.pattern_analyzer_results = pa_result
                    pa_findings = []
                    project_root = str(ctx.project_path)
                    for r in pa_result.get("results", []):
                        abs_path = r.get("file_path", "")
                        rel_path = os.path.relpath(abs_path, project_root).replace("\\", "/") if abs_path else ""
                        for f in r.get("findings", []):
                            original_evidence = f.get("evidence", "").strip()
                            pa_findings.append({
                                "source": "pattern_analyzer",
                                "vuln_id": "",
                                "title": f"[模式匹配] {f.get('vuln_type', '')}",
                                "severity": f.get("severity", "MEDIUM"),
                                "confidence": 0.5 if f.get("has_safe_pattern") else 0.8,
                                "file": rel_path,
                                "line": f.get("line", 1),
                                "vuln_type": f.get("vuln_type", ""),
                                "cwe": f.get("cwe", ""),
                                "evidence": original_evidence or f"在 {rel_path}:{f.get('line', 1)} 检测到 {f.get('vuln_type', '')} 相关危险模式",
                                "impact_description": f"代码中存在 {f.get('vuln_type', '')} 相关危险模式，需人工确认是否构成实际漏洞",
                                "remediation": f.get("remediation", ""),
                                "location": f"{rel_path}:{f.get('line', 1)}",
                                "code_snippet": original_evidence,
                                "status": "待验证",
                            })
                    if pa_findings:
                        pa_count = len(pa_findings)
                        self._log(ctx.task_id, "INFO",
                                  f"PatternAnalyzer 完成: 发现 {pa_count} 个危险模式 "
                                  f"(summary={pa_result.get('aggregate_summary', {})})")
                        quick_scan_findings = (quick_scan_findings or []) + pa_findings
                        self._log(ctx.task_id, "INFO",
                                  f"[QuickScan] PatternAnalyzer 已合并, 当前总数: {len(quick_scan_findings)}")
                        self._bus.publish(EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"PatternAnalyzer: {pa_count} 个危险模式（纯代码零 Token）",
                            status="completed",
                            result=str(pa_result.get("aggregate_summary", {})),
                        ))
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"PatternAnalyzer 失败（不阻断主流程）: {e}")

            # 创建 QuickScan 阶段节点（供子步骤挂靠）
            _quick_scan_stage_id = self._ensure_stage_node(ctx, task_root_node_id, "Quick Scan")
            self._bus.publish(EventStart(
                task_id=ctx.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason="QuickScan 流水线启动: 规则扫描 + 模式匹配 + 组件分析",
                status="running",
            ))

            # Java 路由映射提取
            try:
                from src.analyzers.route_mapper import extract_routes_from_project, format_routes_for_prompt
                java_files = [f for f in project_file_list if f.endswith(".java")][:200]
                if java_files:
                    routes = extract_routes_from_project(str(ctx.project_path), java_files)
                    if routes:
                        route_hint = format_routes_for_prompt(routes)
                        self._log(ctx.task_id, "INFO", f"提取到 {len(routes)} 条 Java 路由映射")
                        self._bus.publish(EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"Java 路由映射: {len(routes)} 条",
                            status="completed",
                            result=route_hint,
                        ))
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"Java 路由映射提取失败: {e}")

            # 组件漏洞扫描：扫描 pom.xml / build.gradle 中的第三方依赖 CVE
            self._ensure_stage_node(ctx, _quick_scan_stage_id, "组件扫描", parent_label="AuditStage")
            try:
                import asyncio as _asyncio
                comp_scan_result: ComponentScanResult = _asyncio.run(
                    scan_project_dependencies(str(ctx.project_path))
                )
                comp_findings = comp_scan_result.findings
                comp_stats = comp_scan_result.stats
                if comp_findings:
                    self._log(
                        ctx.task_id, "INFO",
                        f"组件漏洞扫描完成: 扫描 {comp_stats.get('files_scanned', 0)} 个依赖文件, "
                        f"{comp_stats.get('total_dependencies', 0)} 个依赖, "
                        f"发现 {len(comp_findings)} 个 CVE 漏洞 "
                        f"(严重={comp_stats.get('critical', 0)}, "
                        f"高危={comp_stats.get('high', 0)}, "
                        f"中危={comp_stats.get('medium', 0)})",
                    )
                    # 合并组件扫描结果到快速扫描 findings
                    quick_scan_findings = (quick_scan_findings or []) + comp_findings
                    self._bus.publish(EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"组件漏洞扫描: {len(comp_findings)} 个 CVE",
                        status="completed",
                        result=f"组件漏洞扫描发现 {len(comp_findings)} 个已知 CVE 漏洞",
                    ))
                else:
                    self._log(ctx.task_id, "INFO",
                              f"组件漏洞扫描完成: 扫描 {comp_stats.get('files_scanned', 0)} 个文件, "
                              f"未发现已知 CVE 漏洞")
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"组件漏洞扫描失败（不阻断主流程）: {e}")

            # ── 先执行 QuickScan 流水线（QuickScan + PatternAnalyzer + 组件扫描），再 persist ──
            _plan_future = None
            _plan_executor = None

            if ctx.offline_mode:
                self._log(ctx.task_id, "INFO", "脱机模式：跳过审计计划生成，仅执行快速扫描")
                _run_quick_scan_pipeline()
                self._mark_stage_completed(ctx.task_id, "Quick Scan")
            elif _skip_planning:
                self._log(ctx.task_id, "INFO", "选择性重跑：跳过审计计划生成，仅执行快速扫描")
                _run_quick_scan_pipeline()
                self._mark_stage_completed(ctx.task_id, "Quick Scan")
            elif ctx.extra.get("enable_sink_finder", False):
                self._log(ctx.task_id, "INFO", "[Checkpoint] 开始并行执行 Plan + QuickScan")
                try:
                    _plan_executor = ThreadPoolExecutor(max_workers=2)
                    _plan_future = _plan_executor.submit(_run_plan)
                    scan_future = _plan_executor.submit(_run_quick_scan_pipeline)
                    scan_future.result()
                    self._log(ctx.task_id, "INFO", "[Checkpoint] QuickScan 线程完成")
                    self._mark_stage_completed(ctx.task_id, "Quick Scan")
                except Exception as exec_ex:
                    self._log(ctx.task_id, "ERROR", f"[Checkpoint] ThreadPoolExecutor 异常退出: {exec_ex}")
                    raise
            else:
                self._log(ctx.task_id, "INFO", "Sinker 关闭，跳过审计计划生成，仅执行快速扫描")
                _run_quick_scan_pipeline()
                self._mark_stage_completed(ctx.task_id, "Quick Scan")

            # 保存过滤前的原始结果，供 LLM 审计参考
            quick_scan_findings_raw = list(quick_scan_findings)
            self._log(ctx.task_id, "INFO",
                      f"[QuickScan] 合并后共 {len(quick_scan_findings_raw)} 条发现准备入库/过滤")

            # 发布统一的快速扫描汇总事件（含 QuickScan + PatternAnalyzer + 组件扫描）
            self._bus.publish(EventStart(
                task_id=ctx.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason=f"快速扫描: {len(quick_scan_findings_raw)} 个潜在问题",
                status="completed",
                result=f"快速扫描发现 {len(quick_scan_findings_raw)} 个潜在安全线索 "
                       f"(代码扫描 + 模式匹配 + 组件分析)",
            ))

            if ctx.offline_mode:
                # 脱机模式：无 LLM，仅靠规则过滤
                self._ensure_stage_node(ctx, _quick_scan_stage_id, "过滤筛选", parent_label="AuditStage")
                if quick_scan_findings:
                    try:
                        # 步骤1: 全部原始结果先入库
                        raw_findings = list(quick_scan_findings)
                        from src.services.vulnerability_service import persist_quick_scan_findings
                        qs_persisted = persist_quick_scan_findings(
                            ctx.project_id, ctx.task_id, raw_findings
                        )
                        self._log(ctx.task_id, "INFO",
                                  f"快速扫描发现 {qs_persisted} 条已全部入库 (含待过滤项)")

                        # 步骤2: 规则过滤
                        qs_filter = QuickScanFilter(
                            project_root=str(ctx.project_path),
                            candidate_threshold=5,
                            confidence_threshold=0.3,
                        )
                        quick_scan_findings = qs_filter.filter(raw_findings)
                        filter_stats = qs_filter.get_stats()
                        self._log(ctx.task_id, "INFO",
                                  f"QuickScanFilter (脱机): "
                                  f"输入={filter_stats['total']} → "
                                  f"通过={filter_stats['passed']} "
                                  f"过滤={filter_stats['filtered']}")

                        # 步骤3: 标记被过滤的记录
                        filtered = qs_filter.get_filtered()
                        if filtered:
                            from src.services.vulnerability_service import update_quick_scan_filtered_findings
                            marked = update_quick_scan_filtered_findings(ctx.task_id, filtered)
                            self._log(ctx.task_id, "INFO",
                                      f"已将 {marked} 条被过滤的发现标记为 false_positive")
                    except Exception as e:
                        self._log(ctx.task_id, "WARNING", f"QuickScanFilter 过滤失败（使用原始结果）: {e}")
                        # 降级：尝试入库原始结果
                        try:
                            from src.services.vulnerability_service import persist_quick_scan_findings
                            persist_quick_scan_findings(ctx.project_id, ctx.task_id, quick_scan_findings)
                        except Exception as persist_ex:
                            self._log(ctx.task_id, "WARNING", f"快速扫描结果持久化失败: {persist_ex}")
            else:
                # 联机模式：规则过滤 → 去重入库（零 Token），LLM 验证推迟到 Phase 3 与 SinkFinder 并行
                self._ensure_stage_node(ctx, _quick_scan_stage_id, "过滤筛选", parent_label="AuditStage")
                if quick_scan_findings:
                    try:
                        # ---- 步骤1: 规则过滤 ----
                        qs_filter = QuickScanFilter(
                            project_root=str(ctx.project_path),
                            candidate_threshold=5,
                            confidence_threshold=0.3,
                        )
                        pre_filtered = qs_filter.filter(quick_scan_findings)
                        filter_stats = qs_filter.get_stats()
                        self._log(ctx.task_id, "INFO",
                                  f"QuickScanFilter (联机预过滤): "
                                  f"输入={filter_stats['total']} → "
                                  f"通过={filter_stats['passed']} "
                                  f"过滤={filter_stats['filtered']}")

                        # 标记被规则过滤的记录
                        filtered = qs_filter.get_filtered()
                        if filtered:
                            try:
                                from src.services.vulnerability_service import update_quick_scan_filtered_findings
                                marked = update_quick_scan_filtered_findings(ctx.task_id, filtered)
                                self._log(ctx.task_id, "INFO",
                                          f"规则预过滤: 已将 {marked} 条标记为 false_positive")
                            except Exception as mark_ex:
                                self._log(ctx.task_id, "WARNING",
                                          f"规则预过滤标记失败: {mark_ex}")

                        # ---- 步骤2: 去重入库（不去重版本全量入库，由 persist 层去重）----
                        qs_persisted = 0
                        if not pre_filtered:
                            self._log(ctx.task_id, "INFO",
                                      "规则预过滤后无剩余发现")
                            quick_scan_findings = []
                        else:
                            # 直接入库，persist_quick_scan_findings 内部会做跨源去重
                            try:
                                from src.services.vulnerability_service import persist_quick_scan_findings
                                qs_persisted = persist_quick_scan_findings(
                                    ctx.project_id, ctx.task_id, pre_filtered
                                )
                                self._log(ctx.task_id, "INFO",
                                          f"快速扫描发现 {qs_persisted} 条已入库 "
                                          f"（去重前={len(pre_filtered)} 条）")
                            except Exception as persist_ex:
                                self._log(ctx.task_id, "WARNING",
                                          f"快速扫描入库失败: {persist_ex}")
                            quick_scan_findings = pre_filtered

                            # 发布汇总事件（不含 LLM 验证统计，后续在 Phase 3B 补充）
                            self._bus.publish(EventStart(
                                task_id=ctx.task_id,
                                module=self.MODULE_NAME,
                                action_type=ActionType.INFORMATION,
                                reason=f"Phase2 脱机流程完成: 规则过滤 {filter_stats['filtered']} 条, "
                                       f"去重入库 {qs_persisted} 条",
                                status="completed",
                            ))
                    except Exception as e:
                        self._log(ctx.task_id, "WARNING", f"联机快速扫描处理失败（使用原始结果）: {e}")

                # 将过滤前的完整结果注入 shared_brain 供 SinkFinder 参考
                if not ctx.offline_mode:
                    shared_brain.quick_scan_findings = quick_scan_findings_raw if quick_scan_findings_raw else quick_scan_findings

            # 修正 planning 事件状态（Plan agent 的 event_span.finish() 可能未正确更新）
            try:
                from src.infrastructure.db import session_scope
                from sqlalchemy import text as _text
                with session_scope() as _s:
                    _s.execute(
                        _text("UPDATE events SET status='completed', finished_at=now() WHERE task_id=:tid AND action_type='planning' AND status='running'"),
                        {"tid": ctx.task_id},
                    )
            except Exception as mark_ex:
                self._log(ctx.task_id, "WARNING", f"标记 planning 事件完成失败: {mark_ex}")

            # 3) Phase 3: LLM 验证 + 文件级审计（脱机模式跳过）
            #     Phase 3A: SinkFinder + ChainAnalyzer 仅在 enable_sink_finder=True 时执行
            _skip_sink_chain = stages_to_rerun and "sink_discovery" not in stages_to_rerun and "chain_analysis" not in stages_to_rerun
            if ctx.offline_mode:
                self._log(ctx.task_id, "INFO", "脱机模式：跳过 LLM 审计阶段")
            elif _skip_sink_chain:
                self._log(ctx.task_id, "INFO", "选择性重跑：跳过 Sink/Chain 分析阶段")
            else:
                audit_state.update_progress(3, 4, "Sink发现与链路分析")
                sink_chain_error = None
                verify_error = None
                file_review_error = None
                task_paused = False

                # 等待 Plan 完成（LLM Verification + File Review 不依赖 Plan）
                plan_success = True
                if _plan_future is not None:
                    try:
                        plan_success = _plan_future.result()
                        self._log(ctx.task_id, "INFO", f"[Checkpoint] Plan 线程完成, plan_success={plan_success}")
                    except Exception as plan_ex:
                        self._log(ctx.task_id, "ERROR", f"Plan 执行异常: {plan_ex}")
                        plan_success = False
                    finally:
                        if _plan_executor:
                            _plan_executor.shutdown(wait=False)
                if not plan_success:
                    self._log(ctx.task_id, "WARNING", "审计计划缺失，跳过 Sink/Chain 分析")

                # 构建 Phase 3 并行任务
                phase3_futures = []

                # Phase 3A: SinkFinder + ChainAnalyzer（仅启用时执行且 Plan 成功时）
                if ctx.extra.get("enable_sink_finder", False) and plan_success:
                    self._log(ctx.task_id, "INFO",
                              "[Checkpoint] 进入 SinkFinder + ChainAnalyzer 阶段")
                    sink_finder = SinkFinder(brain=shared_brain)
                    chain_analyzer = ChainAnalyzer(brain=shared_brain)
                    reset_running_audit_nodes_to_pending_for_task(ctx.task_id)
                    reset_running_sink_and_chain_nodes_to_pending_for_task(ctx.task_id)

                    def _run_sink_and_chain():
                        nonlocal sink_chain_error, task_paused
                        try:
                            self._drive_sink_and_chain(ctx, plan_id, sink_finder, chain_analyzer,
                                                       stages_to_rerun=stages_to_rerun)
                        except TaskPausedError:
                            task_paused = True
                            self._log(ctx.task_id, "INFO", "任务已暂停，编排协作式退出")
                            return
                        except Exception as e:
                            sink_chain_error = e
                            self._log(ctx.task_id, "ERROR", f"Sink/Chain 分析过程错误 {e}")
                            self._bus.publish(EventStart(
                                task_id=ctx.task_id, module=self.MODULE_NAME,
                                action_type=ActionType.CHAIN_ANALYSIS,
                                reason=f"分析过程错误: {e}", status="failed",
                            ))

                # Phase 3B: LLM 验证已入库记录（始终执行）
                def _run_llm_verify():
                    nonlocal verify_error
                    try:
                        from src.infrastructure.db import session_scope
                        from src.infrastructure.db.models import Vulnerability
                        from src.services.quick_scan_verifier import QuickScanVerifier
                        from src.services.vulnerability_service import update_quick_scan_verification

                        # 从 DB 读取已去重的非误报记录
                        all_deduped = []
                        with session_scope() as _s:
                            rows = _s.query(Vulnerability).filter(
                                Vulnerability.task_id == ctx.task_id,
                                Vulnerability.status != "false_positive",
                            ).all()
                            for row in rows:
                                ep = str(getattr(row.detail, "entry_points", "")) if row.detail else ""
                                all_deduped.append({
                                    "id": row.id,
                                    "source": row.source or "quick_scan",
                                    "file": ep.split(":")[0] if ep else "",
                                    "line": int(ep.split(":")[1]) if ":" in ep else 1,
                                    "location": ep,
                                    "vuln_type": row.category_name,
                                    "title": row.vul_name,
                                    "severity": row.level,
                                    "confidence": row.confidence,
                                    "evidence": str(getattr(row.detail, "evidence", "")) if row.detail else "",
                                })

                        if not all_deduped:
                            self._log(ctx.task_id, "INFO", "LLM 验证: 无去重记录需验证")
                            return

                        self._log(ctx.task_id, "INFO",
                                  f"开始 LLM 验证: {len(all_deduped)} 条去重后记录")

                        # 发布 Phase 3B 开始事件
                        _verify_span = EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"Phase3B LLM验证: 验证 {len(all_deduped)} 条去重后记录",
                            status="running",
                        )
                        self._bus.publish(_verify_span)

                        verifier = QuickScanVerifier(
                            llm=shared_brain.llm,
                            project_path=str(ctx.project_path),
                            task_id=ctx.task_id,
                        )
                        verified = verifier.verify_findings(
                            all_deduped,
                            project_info=str(shared_brain.project_info or ""),
                            max_workers=3,
                        )
                        v_stats = verifier.get_stats()
                        self._log(ctx.task_id, "INFO",
                                  f"LLM 验证完成: "
                                  f"confirmed={v_stats['confirmed']} "
                                  f"false_positive={v_stats['false_positive']} "
                                  f"need_review={v_stats['need_review']} "
                                  f"error={v_stats['error']}")

                        # 先回写 DB（含全部验证结果，让 false_positive 也能标记入库）
                        update_quick_scan_verification(ctx.task_id, verified)
                        # 再过滤内存中的误报，供下游报告使用
                        before_count = len(verified)
                        verified = QuickScanVerifier.filter_verified(verified)
                        filtered_count = before_count - len(verified)
                        if filtered_count > 0:
                            self._log(ctx.task_id, "INFO",
                                      f"LLM 验证过滤 {filtered_count} 条误报（标记为 false_positive），"
                                      f"保留 {len(verified)} 条")

                        self._bus.publish(EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"Phase3B LLM验证完成: {v_stats['confirmed']} 确认, "
                                   f"{v_stats['false_positive']} 误报, "
                                   f"{v_stats['need_review']} 待审"
                                   + (f"（过滤 {filtered_count} 条误报）" if filtered_count > 0 else ""),
                            status="completed",
                        ))
                        self._mark_stage_completed(ctx.task_id, "LLM Verification")
                    except Exception as e:
                        verify_error = e
                        self._log(ctx.task_id, "WARNING", f"LLM 验证失败（不阻断主流程）: {e}")

                # 创建 LLM 验证阶段节点（与 Plan 平级，作为 Task 的直接子节点）
                _llm_verify_stage_id = self._ensure_stage_node(
                    ctx,
                    task_root_node_id,
                    "LLM Verification",
                    parent_label="Task",
                )

                def _run_file_review():
                    """Phase 3C: 文件级 LLM 安全审计（不依赖 SinkFinder，直接审源码）。"""
                    nonlocal file_review_error
                    try:
                        from src.services.llm_file_reviewer import run_file_review

                        self._bus.publish(EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason="Phase3C 文件级审计启动: 按文件分批送 LLM 审查",
                            status="running",
                        ))
                        self._log(ctx.task_id, "INFO",
                                  "Phase3C 文件级审计启动: 按文件分批送 LLM 审查")
                        reviewed = run_file_review(
                            task_id=ctx.task_id,
                            project_id=ctx.project_id,
                            project_path=str(ctx.project_path),
                            project_info=str(shared_brain.project_info_compact or ""),
                            llm=shared_brain.llm,
                            max_workers=3,
                        )
                        self._log(ctx.task_id, "INFO",
                                  f"Phase3C 文件级审计完成: 发现 {reviewed} 条")
                        self._bus.publish(EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"Phase3C 文件级审计完成: 发现 {reviewed} 个潜在问题",
                            status="completed",
                        ))
                        self._mark_stage_completed(ctx.task_id, "File Review")
                    except Exception as e:
                        file_review_error = e
                        self._log(ctx.task_id, "WARNING", f"Phase3C 文件级审计失败（不阻断主流程）: {e}")

                # 审计完成前去重：优先保留 LLM 审计结果
                try:
                    self._deduplicate_findings(ctx.task_id)
                    self._log(ctx.task_id, "INFO", "审计结果去重完成")
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"去重失败（不阻断）: {e}")

                # 创建文件级审计阶段节点（与 Plan 平级，作为 Task 的直接子节点）
                _file_review_stage_id = self._ensure_stage_node(
                    ctx,
                    task_root_node_id,
                    "File Review",
                    parent_label="Task",
                )

                # LLM Verification + File Review 不依赖 Plan，与 Sink/Chain 并行
                with ThreadPoolExecutor(max_workers=3) as parallel_executor:
                    verify_future = parallel_executor.submit(_run_llm_verify)
                    file_review_future = parallel_executor.submit(_run_file_review)
                    if ctx.extra.get("enable_sink_finder", False):
                        sink_future = parallel_executor.submit(_run_sink_and_chain)
                    verify_future.result()
                    file_review_future.result()
                    if ctx.extra.get("enable_sink_finder", False):
                        sink_future.result()

                # 处理 sink/chain 的错误（LLM 验证错误不阻断）
                if task_paused:
                    self._log(ctx.task_id, "INFO", "任务已暂停，跳过后续处理")
                    return
                if sink_chain_error:
                    self._bus.publish(TaskStatusEvent(
                        task_id=ctx.task_id, status="failed",
                        message="分析过程错误"
                    ))
                    return

            ensure_task_running(ctx.task_id)
            audit_state.update_progress(4, 4, "完成")

            # 安全检查：确认所有 RiskCategory 都已完成，防止提前生成报告
            try:
                remaining = fetch_all_pending_risk_categories_global(plan_id)
                if remaining:
                    self._log(ctx.task_id, "WARNING",
                              f"报告生成前发现 {len(remaining)} 个未完成的漏洞类型，"
                              f"强制标记为 completed")
                    for cat in remaining:
                        mark_risk_category_status(cat["node_id"], "completed")
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"安全检查失败（不阻断）: {e}")

            # 4) 后处理阶段：CoverageTracker 初始化 与 Neo4j 查询互不依赖，并行执行
            coverage_tracker = None
            all_findings_for_report = []

            def _init_coverage_tracker():
                """初始化覆盖率追踪器（纯本地操作，不依赖 Neo4j）"""
                nonlocal coverage_tracker
                try:
                    ct = CoverageTracker(str(ctx.project_path), project_file_list)
                    # QuickScan 扫描了所有代码文件，全部标记为已审查
                    for f in project_file_list:
                        ct.mark_reviewed(f, "quick_scan")
                    # 标记有 findings 的文件的具体漏洞类型
                    for f in quick_scan_findings:
                        file_path = f.get("file", "")
                        vuln_type = f.get("vuln_type", "")
                        if file_path:
                            ct.mark_reviewed(file_path, vuln_type)
                    self._log(ctx.task_id, "INFO",
                              f"覆盖率追踪器初始化完成: {len(project_file_list)} 个文件")
                    return ct
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"覆盖率追踪器初始化失败: {e}")
                    return None

            def _collect_and_dedup_findings():
                """从 PostgreSQL 收集 findings（与 regenerate 端点共用 collect_enriched_findings）"""
                nonlocal all_findings_for_report
                try:
                    from src.services.vulnerability_service import collect_enriched_findings
                    findings = collect_enriched_findings(ctx.task_id, str(ctx.project_path))
                    self._log(ctx.task_id, "INFO", f"收集到 {len(findings)} 条 findings")
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"PostgreSQL 查询 findings 失败，降级使用内存数据: {e}")
                    findings = []

                # PostgreSQL 查询成功则直接使用；降级时仍用快扫内存数据
                return findings if findings else quick_scan_findings

            with ThreadPoolExecutor(max_workers=2) as post_executor:
                ct_future = post_executor.submit(_init_coverage_tracker)
                findings_future = post_executor.submit(_collect_and_dedup_findings)
                coverage_tracker = ct_future.result()
                all_findings_for_report = findings_future.result()

            # Quick Scan 发现已在 _run_quick_scan_pipeline 结束时实时入库
            # all_findings_for_report 直接读取 PostgreSQL（与 report API 同源），不再查 Neo4j

            # 4.5) AST 增强分析：对 findings 进行上下文感知的深度分析（置信度提升 + 证据丰富化）
            if all_findings_for_report:
                try:
                    ast_enricher = get_global_ast_enricher()
                    enriched = ast_enricher.enhance_findings(
                        all_findings_for_report,
                        str(ctx.project_path),
                    )
                    enriched_count = sum(1 for f in enriched if f.get("ast_context"))
                    all_findings_for_report = enriched
                    if enriched_count > 0:
                        self._log(
                            ctx.task_id, "INFO",
                            f"AST 增强分析完成: {enriched_count}/{len(enriched)} 条发现获得深度上下文增强",
                        )
                        # 将 ast_context 写回 DB（vulnerability_details 表）
                        try:
                            from src.services.vulnerability_service import update_ast_contexts
                            persisted = update_ast_contexts(ctx.task_id, enriched)
                            if persisted > 0:
                                self._log(ctx.task_id, "INFO",
                                          f"AST 上下文已持久化: {persisted} 条记录")
                        except Exception as db_ex:
                            self._log(ctx.task_id, "WARNING",
                                      f"AST 上下文持久化失败（不阻断主流程）: {db_ex}")
                    ast_enricher.clear_cache()
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"AST 增强分析失败（不阻断主流程）: {e}")

            # 创建报告生成阶段节点（与 Plan 平级，作为 Task 的直接子节点）
            _report_stage_id = self._ensure_stage_node(
                ctx,
                task_root_node_id,
                "Report Generation",
                parent_label="Task",
            )
            self._bus.publish(EventStart(
                task_id=ctx.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason="报告生成阶段启动: 审计评分 + 覆盖率报告 + HTML报告",
                status="running",
            ))

            # 5) 审计评分、覆盖率报告 互不依赖，并行执行
            audit_score_result = None
            coverage_report = None

            def _calc_audit_score():
                """计算审计评分"""
                nonlocal audit_score_result
                self._ensure_stage_node(ctx, _report_stage_id, "审计评分", parent_label="AuditStage")
                self._bus.publish(EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason="计算审计评分",
                    status="running",
                ))
                if not all_findings_for_report:
                    return
                try:
                    from src.knowledge.audit_scoring import calculate_audit_score, generate_audit_report
                    audit_score_result = calculate_audit_score(all_findings_for_report)
                    report_md = generate_audit_report(all_findings_for_report)
                    self._log(ctx.task_id, "INFO",
                              f"审计评分: {audit_score_result['score']}/100 评级={audit_score_result['grade']} "
                              f"门禁={audit_score_result['gate']}")
                    self._bus.publish(EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason="审计评分报告",
                        status="completed",
                        result=report_md,
                    ))
                    self._mark_stage_completed(ctx.task_id, "审计评分")
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"生成审计评分报告失败: {e}")

            def _calc_coverage_report():
                """生成覆盖率报告"""
                nonlocal coverage_report
                self._ensure_stage_node(ctx, _report_stage_id, "覆盖率报告", parent_label="AuditStage")
                self._bus.publish(EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason="生成覆盖率报告",
                    status="running",
                ))
                if not coverage_tracker:
                    return
                try:
                    if all_findings_for_report:
                        coverage_tracker.mark_from_findings(all_findings_for_report)
                    coverage_report = coverage_tracker.generate_report()
                    coverage_md = coverage_tracker.format_report_markdown()
                    self._log(ctx.task_id, "INFO",
                              f"审计覆盖率: {coverage_report['coverage_rate']}% "
                              f"({coverage_report['reviewed_files']}/{coverage_report['total_files']} 文件)")
                    self._bus.publish(EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"审计覆盖率报告: {coverage_report['coverage_rate']}% "
                               f"({coverage_report['reviewed_files']}/{coverage_report['total_files']} 文件)",
                        status="completed",
                        result=coverage_md,
                    ))
                    self._mark_stage_completed(ctx.task_id, "覆盖率报告")
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"生成覆盖率报告失败: {e}")

            with ThreadPoolExecutor(max_workers=2) as report_executor:
                score_future = report_executor.submit(_calc_audit_score)
                coverage_future = report_executor.submit(_calc_coverage_report)
                score_future.result()
                coverage_future.result()

            # 6) 防漏报兜底：依赖覆盖率报告和 findings
            self._ensure_stage_node(ctx, _report_stage_id, "覆盖盲区分析", parent_label="AuditStage")
            gapfill_findings = []
            try:
                if coverage_tracker:
                    gapfill_tasks = coverage_tracker.generate_gapfill_tasks(
                        max_tasks=5, findings=all_findings_for_report
                    )
                    if gapfill_tasks:
                        self._log(ctx.task_id, "INFO",
                                  f"防漏报兜底: 发现 {len(gapfill_tasks)} 个覆盖盲区，"
                                  f"启动补充审计")
                        # 将盲区任务发布为事件
                        import re as _re
                        real_gapfill_findings = []  # 仅真实漏洞线索（type=gapfill）
                        for task in gapfill_tasks:
                            target_file = task.get("targetFile", "") or (task.get("target_files", [None])[0] or "")
                            attack_class = task.get("attackClass", task.get("attack_class", ""))
                            reason = task.get("reason", task.get("scope_hint", ""))
                            task_type = task.get("type", "")
                            # 从 rationale 提取行号（格式: "文件 path:行号"）
                            line = 1
                            rationale = task.get("rationale", "")
                            if rationale:
                                m = _re.search(r":(\d+)", rationale.split("文件 ")[-1] if "文件 " in rationale else "")
                                if m:
                                    line = int(m.group(1))
                            self._bus.publish(EventStart(
                                task_id=ctx.task_id,
                                module=self.MODULE_NAME,
                                action_type=ActionType.INFORMATION,
                                reason=f"覆盖盲区: {target_file or task.get('subsystem', '')} "
                                       f"缺少 {attack_class} 检查 ({reason})",
                                status="completed",
                                result=f"建议补充审查: {target_file} 的 {attack_class} 相关安全问题",
                            ))

                            # 仅在文件中找到了 sink 关键字（type=gapfill）时才视为真实漏洞线索
                            if task_type == "gapfill":
                                gapfill_finding = {
                                    "source": "gapfill",
                                    "vuln_id": "",
                                    "title": f"[覆盖盲区] {task.get('subsystem', '')} - {attack_class}",
                                    "severity": "MEDIUM",
                                    "confidence": 0.4,
                                    "file": target_file,
                                    "line": line,
                                    "vuln_type": attack_class,
                                    "cwe": "",
                                    "evidence": rationale or f"子系统 {task.get('subsystem', '')} 的 {attack_class} 从未被审查",
                                    "impact_description": f"覆盖盲区：{task.get('subsystem', '')} 的 {attack_class} 从未被审查",
                                    "remediation": f"建议人工审查 {target_file} 中 {attack_class} 相关安全风险",
                                    "location": f"{target_file}:{line}",
                                    "status": "待验证",
                                }
                                real_gapfill_findings.append(gapfill_finding)
                                # 也加入报告中（含文件+行号的真实线索）
                                all_findings_for_report = (all_findings_for_report or []) + [gapfill_finding]

                        # 持久化真实漏洞线索（type=gapfill，追加模式不清除已有记录）
                        if real_gapfill_findings:
                            try:
                                from src.services.vulnerability_service import persist_quick_scan_findings
                                gp_persisted = persist_quick_scan_findings(
                                    ctx.project_id, ctx.task_id, real_gapfill_findings,
                                    clear_existing=False,
                                )
                                self._log(ctx.task_id, "INFO",
                                          f"gapfill 真实漏洞线索已入库: {gp_persisted} 条")
                            except Exception as gp_ex:
                                self._log(ctx.task_id, "WARNING", f"gapfill 入库失败: {gp_ex}")

                        # type=blind_spot / subsystem_gap 仅为覆盖盲区提醒，不纳入漏洞/报告
                        # 将 gapfill 任务注入 Brain 供 SinkFinder 后续轮次参考
                        shared_brain.gapfill_tasks = gapfill_tasks

                        # LLM Gapfill 补充审计：读取遗漏文件内容，送 LLM 做精准审查
                        llm_gapfill_tasks = [t for t in gapfill_tasks if t.get("type") == "gapfill" and t.get("target_files")]
                        if llm_gapfill_tasks and not ctx.offline_mode and ctx.llm_config:
                            self._log(ctx.task_id, "INFO",
                                      f"LLM Gapfill: 启动 {len(llm_gapfill_tasks)} 个遗漏文件的定向补充审计")
                            try:
                                from src.services.llm_file_reviewer import _construct_gapfill_prompt
                                gapfill_files = []
                                seen_files = set()
                                for task in llm_gapfill_tasks:
                                    for tf in task.get("target_files", []):
                                        if tf not in seen_files:
                                            seen_files.add(tf)
                                            full_path = str(ctx.project_path / tf)
                                            try:
                                                with open(full_path, "r", encoding="utf-8", errors="replace") as gf:
                                                    content = gf.read()
                                                if 50 < len(content) < 15000:
                                                    gapfill_files.append({"path": tf, "content": content})
                                            except Exception:
                                                pass
                                        if len(gapfill_files) >= 8:
                                            break
                                    if len(gapfill_files) >= 8:
                                        break

                                if gapfill_files:
                                    gf_prompt = _construct_gapfill_prompt(gapfill_files)
                                    try:
                                        gf_resp = shared_brain.llm.call(
                                            messages=[
                                                {"role": "system", "content": gf_prompt},
                                                {"role": "user", "content": "审查以上遗漏文件，仅输出JSON格式结果。"},
                                            ],
                                            temperature=0.1,
                                        )
                                        gf_raw = gf_resp.content or ""
                                        # 上报 token 用量
                                        if ctx.task_id and (gf_resp.prompt_tokens or gf_resp.completion_tokens):
                                            try:
                                                from src.services.token_service import report_token_usage
                                                report_token_usage(
                                                    task_id=ctx.task_id,
                                                    llm_input=gf_resp.prompt_tokens,
                                                    llm_output=gf_resp.completion_tokens,
                                                    note="gapfill",
                                                )
                                                # 上报 LLM prompt cache 命中统计
                                                if gf_resp.cached_tokens and gf_resp.prompt_tokens:
                                                    report_token_usage(
                                                        task_id=ctx.task_id,
                                                        llm_input=gf_resp.cached_tokens,
                                                        llm_output=gf_resp.prompt_tokens - gf_resp.cached_tokens,
                                                        note="cache_stats:gapfill",
                                                    )
                                            except Exception:
                                                pass
                                        # 提取 JSON
                                        import json as _json
                                        gf_json_start = gf_raw.find("[")
                                        gf_json_end = gf_raw.rfind("]") + 1
                                        if gf_json_start >= 0 and gf_json_end > gf_json_start:
                                            gf_parsed = _json.loads(gf_raw[gf_json_start:gf_json_end])
                                            gf_count = 0
                                            for gf in gf_parsed:
                                                if isinstance(gf, dict) and gf.get("location"):
                                                    loc = gf.get("location", "")
                                                    line = 1
                                                    if ":" in loc:
                                                        try:
                                                            line = int(loc.split(":")[1])
                                                        except ValueError:
                                                            pass
                                                    gf_finding = {
                                                        "source": "gapfill",
                                                        "title": gf.get("title", f"gapfill: {gf.get('vulnType', '')}"),
                                                        "severity": gf.get("severity", "MEDIUM"),
                                                        "confidence": 0.5,
                                                        "file": loc.split(":")[0],
                                                        "line": line,
                                                        "vuln_type": gf.get("vulnType", ""),
                                                        "evidence": "",
                                                        "impact_description": "覆盖盲区补充审计发现",
                                                        "remediation": "建议人工审查",
                                                        "location": loc,
                                                        "status": "待验证",
                                                    }
                                                    all_findings_for_report.append(gf_finding)
                                                    gf_count += 1
                                            if gf_count:
                                                self._log(ctx.task_id, "INFO",
                                                          f"LLM Gapfill 完成: {gf_count} 条新发现")
                                                # 入库
                                                try:
                                                    from src.services.vulnerability_service import persist_quick_scan_findings
                                                    persist_quick_scan_findings(
                                                        ctx.project_id, ctx.task_id,
                                                        [f for f in all_findings_for_report if f.get("source") == "gapfill"],
                                                        clear_existing=False,
                                                    )
                                                except Exception:
                                                    pass
                                    except Exception as llm_ex:
                                        self._log(ctx.task_id, "WARNING",
                                                  f"LLM Gapfill 调用失败: {llm_ex}")
                            except Exception as gapfill_ex:
                                self._log(ctx.task_id, "WARNING",
                                          f"LLM Gapfill 执行失败: {gapfill_ex}")
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"防漏报兜底执行失败: {e}")
            else:
                self._mark_stage_completed(ctx.task_id, "覆盖盲区分析")

            # 7) 生成 HTML 审计报告：依赖所有上述结果
            self._ensure_stage_node(ctx, _report_stage_id, "HTML报告", parent_label="AuditStage")
            try:
                from src.services.report_generator import write_report_to_file
                report_dir = os.path.join(str(ctx.project_path), ".argusmind", "reports")
                # 收集语言统计信息
                language_stats = None
                try:
                    from src.tools import TokeiTool
                    tokei = TokeiTool()
                    tokei_result = tokei.run(str(ctx.project_path))
                    if tokei_result.success and tokei_result.data:
                        language_stats = tokei_result.data
                except Exception:
                    pass
                report_info = write_report_to_file(
                    report_dir=report_dir,
                    task_id=ctx.task_id,
                    project_name=ctx.project_name,
                    findings=all_findings_for_report,
                    audit_score=audit_score_result,
                    coverage_report=coverage_report,
                    scan_stats=scan_stats,
                    quick_scan_findings=[f for f in all_findings_for_report if f.get("source") in ("quick_scan", "component_scan", "pattern_analyzer")],
                    llm_findings=[f for f in all_findings_for_report if f.get("source") not in ("quick_scan", "component_scan", "pattern_analyzer")],
                    exploit_chain_report=None,
                    language_stats=language_stats,
                )
                self._log(ctx.task_id, "INFO",
                          f"HTML 审计报告已生成: {report_info.get('file_path', '')}")
                self._bus.publish(EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason="HTML审计报告",
                    status="completed",
                    result=f"报告已生成: {report_info.get('download_path', '')}",
                ))
                self._mark_stage_completed(ctx.task_id, "HTML报告")
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"生成 HTML 审计报告失败: {e}")

            audit_state.complete({"task_id": ctx.task_id})

            # 统一清理：将任务下所有 running 状态的节点和事件一次性标记为 completed
            try:
                db_manager.neo4j_repository.client.execute_write(
                    """
                    MATCH (n)
                    WHERE n.task_id = $task_id
                      AND coalesce(n.status, '') = 'running'
                      AND (
                        n:AuditStage OR n:Language OR n:RiskCategory
                        OR n:SinkFlowNode OR n:ChainNode OR n:AnalysisResult
                      )
                    SET n.status = 'completed'
                    """,
                    {"task_id": ctx.task_id},
                )
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"Neo4j 清理标记完成失败: {e}")

            # 清理残留的 running 事件（防止 span 泄漏导致事件永远停留在 running）
            leftover = complete_running_events_for_task(ctx.task_id)
            if leftover:
                self._log(
                    ctx.task_id,
                    "WARNING",
                    f"任务完成时仍有 {leftover} 条 running 事件，已强制标记为 completed",
                )

            # 从数据库重新统计实际漏洞数（防止 all_findings_for_report 与 DB 不一致）
            try:
                from sqlalchemy import func as _sa_func
                from src.infrastructure.db.models.vulnerability import Vulnerability as _VulnModel
                from src.infrastructure.db import session_scope as _ss
                with _ss() as _s:
                    actual_vuln_count = _s.query(
                        _sa_func.count(_VulnModel.id)
                    ).filter(
                        _VulnModel.task_id == ctx.task_id,
                        _VulnModel.status != "false_positive",
                    ).scalar() or len(all_findings_for_report)
            except Exception:
                actual_vuln_count = len(all_findings_for_report)

            self._bus.publish(TaskStatusEvent(
                task_id=ctx.task_id, status="completed",
                vuln_count=actual_vuln_count,
            ))
            self._log(ctx.task_id, "INFO", f"任务 {ctx.task_id} 编排完成")
        except TaskPausedError:
            audit_state.pause("任务暂停")
            self._log(ctx.task_id, "INFO", "任务已暂停，编排协作式退出")
            return
        except Exception as ex:
            msg = f"编排异常终止: {ex}"
            audit_state.fail(msg)
            self._log(ctx.task_id, "ERROR", msg)

            # 统一清理：将任务下所有 running 状态节点标记为 failed
            try:
                db_manager.neo4j_repository.client.execute_write(
                    """
                    MATCH (n)
                    WHERE n.task_id = $task_id
                      AND coalesce(n.status, '') = 'running'
                      AND (
                        n:AuditStage OR n:Language OR n:RiskCategory
                        OR n:SinkFlowNode OR n:ChainNode OR n:AnalysisResult
                      )
                    SET n.status = 'failed'
                    """,
                    {"task_id": ctx.task_id},
                )
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"Neo4j 清理标记失败失败: {e}")

            # 清理残留的 running 事件
            leftover = fail_running_non_information_events_for_task(ctx.task_id)
            if leftover:
                self._log(
                    ctx.task_id,
                    "WARNING",
                    f"任务失败时仍有 {leftover} 条 running 事件，已强制标记为 failed",
                )

            self._bus.publish(
                EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=msg,
                    status="failed",
                )
            )
            self._bus.publish(TaskStatusEvent(task_id=ctx.task_id, status="failed", message=msg))
            return

    # ---------- Sink/Chain 消费循环 ----------
    # 优先级分层：L1(高危) → L2(中危) → L3(低危) → L4(信息级)
    _PRIORITY_TIERS = {
        "L1": {"max_level": 25, "label": "高危", "sink_workers": 5, "chain_workers": 2},
        "L2": {"max_level": 50, "label": "中危", "sink_workers": 4, "chain_workers": 2},
        "L3": {"max_level": 75, "label": "低危", "sink_workers": 3, "chain_workers": 1},
        "L4": {"max_level": 100, "label": "信息级", "sink_workers": 2, "chain_workers": 1},
    }
    _TIER_ORDER = ["L1", "L2", "L3", "L4"]

    # 同语言漏洞类型并行上限（控制 LLM 并发，避免限流）—— 兼容旧接口
    _MAX_PARALLEL_SINK_FINDERS = 5
    _MAX_PARALLEL_CHAIN_ANALYZERS = 2  # ChainAnalyzer LLM 轮次多，限制并发

    # ── QuickScan 已知结果跳过 SinkFinder 的映射 ──
    _QUICKSCAN_VULN_TYPE_MAP: Dict[str, set] = {
        "COMMAND_INJECTION": {"COMMAND_INJECTION", "CODE_INJECTION"},
        "SQL_INJECTION": {"SQL_INJECTION"},
        "CODE_INJECTION": {"CODE_INJECTION"},
        "SPEL_INJECTION": {"CODE_INJECTION"},
        "SSTI": {"CODE_INJECTION"},
        "JNDI_INJECTION": {"CODE_INJECTION"},
        "DESERIALIZATION": {"DESERIALIZATION", "INSECURE_DESERIALIZATION"},
        "XXE": {"XXE"},
        "SSRF": {"SSRF"},
        "PATH_TRAVERSAL": {"PATH_TRAVERSAL"},
        "XSS": {"XSS"},
        "AUTH_BYPASS": {"AUTH_BYPASS"},
        "IDOR": {"IDOR"},
        "OPEN_REDIRECT": {"OPEN_REDIRECT"},
        "WEAK_CRYPTO": {"WEAK_CRYPTO"},
        "WEAK_HASH": {"WEAK_HASH", "WEAK_CRYPTO"},
        "HARDCODED_CREDENTIALS": {"HARDCODED_CREDENTIALS", "HARD_CODE_PASSWORD"},
        "FILE_UPLOAD": {"FILE_UPLOAD"},
        "FILE_OPERATIONS": {"FILE_OPERATIONS", "FILE_UPLOAD"},
        "CSRF": {"CSRF"},
        "CORS_MISCONFIGURATION": {"CSRF", "CORS_MISCONFIGURATION"},
        "LOG_INJECTION": {"LOG_INJECTION"},
        "RACE_CONDITION": {"RACE_CONDITION"},
        "INSECURE_RANDOM": {"INSECURE_RANDOM"},
        "JWT_VULNERABILITIES": {"JWT_VULNERABILITIES"},
        "MASS_ASSIGNMENT": {"MASS_ASSIGNMENT"},
        "SESSION_FIXATION": {"SESSION_FIXATION"},
        "INFORMATION_DISCLOSURE": {"INFORMATION_DISCLOSURE"},
        "REGEX_DOS": {"REGEX_DOS"},
        "RATE_LIMITING": {"RATE_LIMITING"},
        "BUFFER_OVERFLOW": {"BUFFER_OVERFLOW"},
        "PROTOTYPE_POLLUTION": {"PROTOTYPE_POLLUTION"},
        "NOSQL_INJECTION": {"NOSQL_INJECTION"},
        "FORMAT_STRING": {"FORMAT_STRING"},
    }

    def _should_skip_sink_finder_for_category(
        self, brain: Any, category_name: str
    ) -> bool:
        """检查 QuickScan/PatternAnalyzer 是否已覆盖该漏洞类型，可跳过 SinkFinder。

        通过 brain.quick_scan_findings 检查是否已有匹配的发现。
        PatternAnalyzer 产出已随 QuickScan 入库，此处统一检查。
        """
        matched_types = self._QUICKSCAN_VULN_TYPE_MAP.get(category_name.upper())
        if not matched_types:
            return False

        findings = getattr(brain, "quick_scan_findings", None) or []
        if not findings:
            return False

        for f in findings:
            f_type = str(f.get("vuln_type", "")).upper()
            if f_type in matched_types:
                return True
        return False

    def _drive_sink_and_chain(
        self,
        ctx: ExecutionContext,
        plan_id: str,
        sink_finder: SinkFinder,
        chain_analyzer: ChainAnalyzer,
        stages_to_rerun: Optional[set] = None,
    ) -> None:
        """按优先级层级（L1-L4）流水线驱动 SinkFinder + ChainAnalyzer。

        流水线策略（改进版）：
        - 移除层级间串行屏障，所有层级类别一次性并行调度
        - 每个漏洞类型在单任务内 SinkFinder→ChainAnalyzer 串行执行
        - 不同漏洞类型在线程池内并行，实现自然的流水线交错
        - SinkFinder 完成立即触发 ChainAnalyzer，不等待同级其他类型
        - QuickScan/PatternAnalyzer 已覆盖的类型跳过 SinkFinder，直达 ChainAnalyzer
        """
        ensure_task_running(ctx.task_id)

        all_pending = fetch_all_pending_risk_categories_global(plan_id)
        if not all_pending:
            self._log(ctx.task_id, "INFO", "[SinkChain] 无待处理漏洞类型，跳过")
            return

        # 按 tier 分组（仅用于日志统计，不阻塞调度）
        tiered_categories: Dict[str, List[Dict]] = {}
        for cat in all_pending:
            level = int(cat.get("level") or 100)
            for tn in self._TIER_ORDER:
                if level <= self._PRIORITY_TIERS[tn]["max_level"]:
                    tiered_categories.setdefault(tn, []).append(cat)
                    break

        total_cats = len(all_pending)
        all_languages = set(c.get("language_name") for c in all_pending)
        for tn, cats in tiered_categories.items():
            langs = set(c.get("language_name") for c in cats)
            self._log(ctx.task_id, "INFO",
                      f"[SinkChain] {tn}({self._PRIORITY_TIERS[tn]['label']}): "
                      f"{len(cats)} 个漏洞类型, {len(langs)} 种语言")

        # 最大并行数：控制 LLM 并发，避免超载
        max_workers = min(5, total_cats)

        _run_sink_chain_pipeline = self._make_sink_chain_pipeline(
            ctx, sink_finder, chain_analyzer, stages_to_rerun=stages_to_rerun
        )

        self._log(ctx.task_id, "INFO",
                  f"[SinkChain] 全部 {total_cats} 个漏洞类型并行调度 "
                  f"（{len(all_languages)} 种语言，最多 {max_workers} 路并行）")

        # ── 一次性并行调度所有类别 ──
        _lang_running_set: set = set()

        if total_cats == 1:
            _run_sink_chain_pipeline(all_pending[0], _lang_running_set)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_run_sink_chain_pipeline, cat, _lang_running_set): cat
                    for cat in all_pending
                }
                for future in as_completed(futures):
                    cat = futures[future]
                    try:
                        future.result()
                    except (TaskPausedError, LLMError):
                        raise
                    except Exception as ex:
                        self._log(ctx.task_id, "ERROR",
                                  f"[SinkChain] 任务异常 "
                                  f"{cat.get('language_name')}/{cat.get('category_name')}: {ex}")

        # 标记已完成的语言
        self._mark_completed_languages(plan_id, _lang_running_set)
        self._log(ctx.task_id, "INFO", "[SinkChain] 所有优先级层级流水线处理完成")

    def _make_sink_chain_pipeline(
        self,
        ctx: ExecutionContext,
        sink_finder: SinkFinder,
        chain_analyzer: ChainAnalyzer,
        stages_to_rerun: Optional[set] = None,
    ):
        """创建 SinkFinder→ChainAnalyzer 流水线闭包（避免嵌套函数无法 pickle）。"""

        def _pipeline(cat_row: Dict, _lang_running_set: set) -> None:
            """流水线任务：SinkFinder → ChainAnalyzer（串行，但与其他任务并行）。"""
            vul_node_id = cat_row["node_id"]
            category_name = cat_row.get("category_name") or ""
            language_name = cat_row.get("language_name") or ""
            lang_node_id = cat_row.get("lang_node_id") or ""

            # 根据 level 推断所属 tier（仅用于日志）
            level = int(cat_row.get("level") or 100)
            tier_name = "L4"
            for tn in self._TIER_ORDER:
                if level <= self._PRIORITY_TIERS[tn]["max_level"]:
                    tier_name = tn
                    break
            tier_label = self._PRIORITY_TIERS[tier_name]["label"]

            # 标记状态
            if lang_node_id and lang_node_id not in _lang_running_set:
                mark_language_status(lang_node_id, "running")
                _lang_running_set.add(lang_node_id)
            mark_risk_category_status(vul_node_id, "running")
            ensure_knowledge_element_id_for_risk_category(vul_node_id)

            # ── 阶段 A：SinkFinder（或跳过） ──
            if cat_row.get("sink_finder_completed"):
                self._log(ctx.task_id, "INFO",
                          f"[{tier_name}] SinkFinder 已完成: {language_name}/{category_name}")
            else:
                sink_info_span = start_event_span(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=f"开始审计 [{tier_name}-{tier_label}]：\n"
                           f"语言 {language_name}\n漏洞类型:{category_name}\n"
                           f"描述：{cat_row.get('risk_description', '')}\n"
                           f"依据：{cat_row.get('reasoning_basis', '')}",
                )
                try:
                    # 复跑模式：注入 Gap Check 提示词
                    _run_kind = "initial"
                    _existing = None
                    if stages_to_rerun and "sink_discovery" in stages_to_rerun:
                        _run_kind = "gap_check"
                        # 尝试从 Neo4j 获取该漏洞类型已有的 sink 发现
                        try:
                            _existing = self._fetch_existing_sinks_for_category(
                                ctx.task_id, category_name, language_name
                            )
                        except Exception:
                            _existing = None
                        if _existing:
                            self._log(ctx.task_id, "INFO",
                                      f"[{tier_name}] Gap Check 模式: {language_name}/{category_name}, "
                                      f"已有 {len(_existing)} 条发现")
                    sink_finder.run(
                        language_name,
                        category_name,
                        vul_node_id,
                        cat_row.get("reasoning_basis", ""),
                        cat_row.get("risk_description", ""),
                        run_kind=_run_kind,
                        existing_findings=_existing,
                    )
                    self._log(ctx.task_id, "INFO",
                              f"[{tier_name}] SinkFinder 完成: {language_name}/{category_name}")
                    mark_risk_category_sink_finder_completed(vul_node_id)
                except (TaskPausedError, LLMError):
                    sink_info_span.mark_failed("任务暂停或 LLM 错误")
                    raise
                except Exception as sink_ex:
                    sink_info_span.mark_failed(str(sink_ex))
                    self._log(ctx.task_id, "ERROR",
                              f"[{tier_name}] SinkFinder 异常 {language_name}/{category_name}: {sink_ex}")
                    return  # Skip ChainAnalyzer for this category
                finally:
                    sink_info_span.finish()

            # ── 阶段 B：ChainAnalyzer ──
            try:
                self._process_chain_analysis(ctx, cat_row, chain_analyzer)
            except (TaskPausedError, LLMError):
                raise
            except Exception as ex:
                self._log(ctx.task_id, "ERROR",
                          f"[{tier_name}] ChainAnalyzer 异常 "
                          f"{language_name}/{category_name}: {ex}")

        return _pipeline

    def _fetch_existing_sinks_for_category(
        self, task_id: str, category_name: str, language_name: str
    ) -> List[Dict[str, Any]]:
        """从 Neo4j 获取指定漏洞类型已有的 SinkFlowNode 发现（用于 Gap Check 模式）。"""
        try:
            query = """
            MATCH (t:Task {task_id: $task_id})-[:HAS_STAGE]->(s:AuditStage)
                  -[:HAS_STAGE]->(rc:RiskCategory {category_name: $category_name})
                  -[:HAS_SINK]->(sf:SinkFlowNode)
            WHERE sf.status = 'completed'
            RETURN sf.file AS file, sf.line AS line, sf.function AS function,
                   sf.reason AS reason, sf.end_line AS end_line
            LIMIT 50
            """
            results = db_manager.neo4j_repository.client.execute_read(
                query,
                {"task_id": task_id, "category_name": category_name},
            )
            if not results:
                return []
            return [
                {
                    "file": r.get("file", ""),
                    "line": r.get("line", 0),
                    "function": r.get("function", ""),
                    "reason": r.get("reason", ""),
                    "end_line": r.get("end_line", 0),
                }
                for r in results
                if r.get("file")
            ]
        except Exception:
            return []

    def _mark_completed_languages(self, plan_id: str, running_set: set) -> None:
        """检查并标记所有漏洞类型已完成的语言为 completed。"""
        for lang_node_id in list(running_set):
            if check_language_all_categories_completed(lang_node_id):
                mark_language_status(lang_node_id, "completed")
                running_set.discard(lang_node_id)

    def _deduplicate_findings(self, task_id: str) -> None:
        """审计结果去重：优先保留 LLM 审计产生的结果。

        去重规则：
        1. 按 (file_path, line, category_name) 分组
        2. 每组按 source 优先级保留最高的，删除其他重复的记录
        """
        from src.infrastructure.db.models.vulnerability import Vulnerability, VulnerabilityDetail
        from src.services.vulnerability_service import _SOURCE_PRIORITY
        from src.infrastructure.db import session_scope
        
        with session_scope() as session:
            rows = (
                session.query(Vulnerability)
                .filter(Vulnerability.task_id == task_id)
                .all()
            )
        
            if not rows:
                return
            
            # 在 session 内预加载 detail 并提取所有数据（避免外部懒加载）
            detail_map: dict = {}
            detail_rows = (
                session.query(VulnerabilityDetail)
                .filter(VulnerabilityDetail.vulnerability_id.in_([r.id for r in rows]))
                .all()
            )
            for d in detail_rows:
                detail_map[d.vulnerability_id] = d
            
            # 分组去重，按 source 优先级排序（全部在 session 内完成）
            groups: dict = {}
            for v in rows:
                detail = detail_map.get(v.id)
                ep = str(detail.entry_points) if detail and detail.entry_points else ''
                file_path = ep.split(':')[0] if ep else ''
                try:
                    line = int(ep.split(':')[1]) if ':' in ep else 0
                except (ValueError, TypeError):
                    line = 0
                category = v.category_name or ''
                key = (file_path, line, category)
                
                if key not in groups:
                    groups[key] = []
                groups[key].append((v.id, _SOURCE_PRIORITY.get(v.source or '', 99)))
            
            # 每个分组内按优先级升序排序，保留第一个
            to_delete_ids = []
            for key, items in groups.items():
                if len(items) > 1:
                    items.sort(key=lambda x: x[1])
                    for vid, _ in items[1:]:
                        to_delete_ids.append(vid)
            
            # 删除重复记录
            if to_delete_ids:
                session.query(VulnerabilityDetail).filter(
                    VulnerabilityDetail.vulnerability_id.in_(to_delete_ids)
                ).delete(synchronize_session=False)
                session.query(Vulnerability).filter(
                    Vulnerability.id.in_(to_delete_ids)
                ).delete(synchronize_session=False)
            
                self._log(task_id, "INFO",
                         f"去重完成：删除 {len(to_delete_ids)} 个重复结果，保留高优先级审计结果")

    def _process_chain_analysis(
        self,
        ctx: ExecutionContext,
        cat_row: Dict,
        chain_analyzer: ChainAnalyzer,
    ) -> None:
        """处理单个漏洞类型的链路分析（补跑二次校验 + ChainAnalyzer）。

        单条链路失败不中断同类其他链路（仅跳过该条，继续分析下一条）。
        CircuitBreaker 保护防止 LLM 服务级联故障导致重试风暴。
        """
        vul_node_id = cat_row["node_id"]
        category_name = cat_row.get("category_name") or ""
        knowledge_element_id = ensure_knowledge_element_id_for_risk_category(vul_node_id)

        # 获取或创建该漏洞类型的熔断器（按 category 隔离）
        cb = get_circuit_breaker_registry().get_or_create(
            f"chain-analyzer:{vul_node_id}",
            CircuitBreakerConfig(failure_threshold=5, success_threshold=3, recovery_timeout=60.0),
        )

        reset_non_completed_analysis_results_to_pending_for_vul(vul_node_id)

        incomplete_ars = fetch_non_completed_analysis_results_for_vul(vul_node_id)
        if incomplete_ars:
            self._bus.publish(EventStart(
                task_id=ctx.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason=f"补跑二次校验：vul={category_name} 共 {len(incomplete_ars)} 条",
            ))
            for row in incomplete_ars:
                ar_nid = (
                    (row.get("ar_element_id") or row.get("node_id") or "")
                ).strip()
                if not ar_nid:
                    continue
                try:
                    cb.call(lambda: chain_analyzer.resume_secondary_confirmation_for_stored_result(
                        ar_node_id=ar_nid,
                        category_name=category_name,
                        risk_description=cat_row["risk_description"],
                        knowledge_element_id=knowledge_element_id,
                    ))
                except CircuitOpenError:
                    self._log(ctx.task_id, "WARNING",
                              f"补跑二次校验熔断器打开，跳过剩余 ar | category={category_name}")
                    break
                except (TaskPausedError, LLMError):
                    raise
                except Exception as ex:
                    self._log(ctx.task_id, "ERROR", f"补跑二次校验失败 ar={ar_nid!r}: {ex}")

        chain_count = 0
        skipped_count = 0
        failed_count = 0
        while True:
            ensure_task_running(ctx.task_id)
            chain = fetch_next_pending_sink_chain_path(vul_node_id)
            if not chain:
                break
            if not isinstance(chain, dict):
                self._log(
                    ctx.task_id,
                    "ERROR",
                    f"待分析链路格式异常（非 dict）: {type(chain).__name__}",
                )
                skipped_count += 1
                continue
            leaf_id = str(chain.get("leaf_sink_node_id") or "").strip()
            sink_nodes_chk = chain.get("sink_nodes")
            if not leaf_id or not isinstance(sink_nodes_chk, list) or not sink_nodes_chk:
                self._log(
                    ctx.task_id,
                    "ERROR",
                    "待分析链路缺少 leaf_sink_node_id 或 sink_nodes 为空/非 list，跳过本记录 "
                    f"keys={list(chain.keys())}",
                )
                skipped_count += 1
                continue
            mark_sink_flow_leaf_status(leaf_id, SINK_FLOW_LEAF_STATUS_RUNNING)
            try:
                cb.call(lambda: chain_analyzer.run(
                    chain=chain,
                    vul_description=cat_row["risk_description"],
                    category_name=category_name,
                    knowledge_element_id=knowledge_element_id,
                ))
                chain_count += 1
            except CircuitOpenError:
                self._log(ctx.task_id, "WARNING",
                          f"链路分析熔断器打开，跳过剩余链路 | category={category_name} "
                          f"已完成={chain_count} 已跳过={skipped_count}")
                break
            except (TaskPausedError, LLMError):
                self._log(ctx.task_id, "ERROR", f"链路分析致命错误 leaf={leaf_id}")
                raise
            except Exception as ex:
                self._log(ctx.task_id, "ERROR", f"链路分析异常 leaf={leaf_id}: {ex}")
                failed_count += 1
                # 单链失败不中断，继续分析下一条

        self._log(
            ctx.task_id,
            "INFO",
            f"漏洞类型 {category_name} 链路分析完成: 成功={chain_count} 跳过={skipped_count} 失败={failed_count}",
        )
        mark_risk_category_status(vul_node_id, "completed")
