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
from services.chain_analysis_service import (
    ensure_knowledge_element_id_for_risk_category,
    fetch_non_completed_analysis_results_for_vul,
    reset_non_completed_analysis_results_to_pending_for_vul,
)
from services.plan_service import (
    fetch_all_pending_risk_categories,
    fetch_next_pending_language_for_plan,
    find_completed_plan_stage_node_id_for_task,
    mark_language_status,
    mark_risk_category_status,
    persist_plan,
    reset_running_audit_nodes_to_pending_for_task,
)
from src.services.event_service import fail_running_non_information_events_for_task
from services.sink_flow_service import (
    SINK_FLOW_LEAF_STATUS_RUNNING,
    fetch_next_pending_sink_chain_path,
    mark_sink_flow_leaf_status,
    reset_running_sink_and_chain_nodes_to_pending_for_task,
)
from src.utils.ids import generate_id
from src.knowledge.audit_config import AUDIT_SCHEDULING, AUDIT_PROFILES
from src.services.quick_scan_service import QuickScanService
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
            self._log(ctx.task_id, "WARNING", f"任务超时处理异常: {elapsed_minutes:.1f} 分钟")

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
        try:
            project = get_project(ctx.project_id)
            db_description = (getattr(project, "description", "") or "").strip()
            db_description_compact = (getattr(project, "description_compact", "") or "").strip()
            db_project_session_id = getattr(project, "session_id", "").strip()
            if db_description and db_description_compact:
                shared_brain.project_info = db_description
                shared_brain.project_info_compact = db_description_compact
                shared_brain.set_project_info_session_id(db_project_session_id)
                self._log(ctx.task_id, "INFO", "复用项目描述信息，跳过信息收集")
                db_manager.neo4j_repository.update_node(
                    {"label": "AuditStage", "node_id": information_collection_id},
                    {"status": "completed", "end_time": datetime.now().isoformat()},
                )
                return True

            self._bus.publish(EventStart(
                task_id=ctx.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.INFORMATION,
                reason="开始信息收集",
            ))
            try:
                project_info = ProjectInfo(brain=shared_brain)
                project_info.run()
                if not shared_brain.project_info:
                    # OpenCode 不可用或返回空：用 Tokei + 文件列表生成基础 project_info
                    self._log(ctx.task_id, "WARNING", "OpenCode 信息收集为空，使用 Tokei 兜底")
                    shared_brain.project_info = self._build_fallback_project_info(ctx, project_file_list, shared_brain)
                    shared_brain.project_info_compact = shared_brain.project_info
                    if not shared_brain.project_info:
                        self._log(ctx.task_id, "ERROR", "兜底信息收集也为空")
                        self._bus.publish(
                            EventStart(
                                task_id=ctx.task_id,
                                module=self.MODULE_NAME,
                                action_type=ActionType.INFORMATION,
                                reason="信息收集结果为空",
                                status="failed",
                            )
                        )
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
                return True
            except Exception as e:
                raise
        except Exception as ex:
            self._log(ctx.task_id, "ERROR", str(ex))
            raise

    def _build_fallback_project_info(self, ctx: ExecutionContext, project_file_list: list, shared_brain: Brain = None) -> str:
        """当 OpenCode 不可用时，收集关键文件，让 LLM 分析生成 project_info。"""
        try:
            project_path = str(ctx.project_path)
            # 1) 收集关键文件：构建文件 + README + 入口文件
            key_patterns = [
                # 构建/依赖文件
                "pom.xml", "build.gradle", "package.json", "requirements.txt",
                "Cargo.toml", "go.mod", "Makefile", "CMakeLists.txt", "setup.py",
                "composer.json", "Gemfile", "yarn.lock", "pnpm-lock.yaml",
                # 主入口
                "main.py", "app.py", "index.js", "app.js", "server.js",
                "main.go", "main.rs", "Program.cs", "index.ts",
                # 文档
                "README.md", "readme.md", "README", "README.txt",
                # 配置
                "application.yml", "application.properties", ".env.example",
            ]
            key_files = []
            for f in project_file_list[:500]:
                basename = os.path.basename(f).lower()
                if basename in [p.lower() for p in key_patterns]:
                    key_files.append(f)

            # 限制数量避免上下文爆炸
            key_files = key_files[:15]

            # 2) 读取关键文件内容
            snippets = []
            for rel_path in key_files:
                abs_path = os.path.join(project_path, rel_path)
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    # 限制每个文件 4000 字符
                    if len(content) > 4000:
                        content = content[:4000] + f"\n... (截断，原文 {len(content)} 字符)"
                    snippets.append(f"### {rel_path}\n```\n{content}\n```")
                except Exception as read_ex:
                    snippets.append(f"### {rel_path}\n(无法读取: {read_ex})")

            # 3) Tokei 语言统计
            tokei_stats = ""
            try:
                from src.tools import TokeiTool
                tokei = TokeiTool()
                result = tokei.run(project_path)
                if result.success and result.data:
                    langs = result.data.get("languages", {})
                    total = result.data.get("total", {})
                    tokei_stats = "\n## 语言分布 (Tokei)\n"
                    for lang, stats in sorted(langs.items(), key=lambda x: -x[1].get("code", 0)):
                        tokei_stats += f"- **{lang}**: {stats.get('files', 0)} 文件, {stats.get('code', 0)} 行代码\n"
                    tokei_stats += f"\n总计: {total.get('code', 0)} 行代码, {total.get('files', 0)} 文件\n"
            except Exception as tokei_ex:
                self._log(ctx.task_id, "WARNING", f"Tokei 语言统计失败: {tokei_ex}")

            # 4) 调用 LLM 分析
            if shared_brain and shared_brain.llm:
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
                    response = shared_brain.llm.chat_completion(
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=1000,
                        temperature=0.3,
                    )
                    # 提取返回文本
                    text = response.get("choices", [{}])[0].get("message", {}).get("content", "")
                    if text and text.strip():
                        return text.strip()
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"LLM 分析项目信息失败: {e}")

            # 5) LLM 也失败：用纯 Tokei 统计兜底
            fallback = [f"# 项目信息（自动推断）\n"]
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
            self._log(ctx.task_id, "WARNING", f"兜底信息收集失败: {e}")
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

            # 0) 统一文件收集（避免后续各服务重复 os.walk）
            project_file_list = self._collect_project_files(str(ctx.project_path))
            self._log(ctx.task_id, "INFO", f"项目文件收集完成: {len(project_file_list)} 个文件")

            # 0) Task 根节点（幂等，替代原 Project 根）
            task_root_node_id = self._ensure_task_node(ctx)

            # 1) 信息收集阶段
            audit_state.update_progress(1, 4, "信息收集")
            information_collection_id = self._ensure_stage_node(
                ctx, task_root_node_id, "Information Collection"
            )
            self._log(ctx.task_id, "INFO", f"信息收集阶段 node_id={information_collection_id}")

            # 脱机模式：跳过 LLM 信息收集，用 Tokei 生成基础 project_info
            if ctx.offline_mode:
                self._log(ctx.task_id, "INFO", "脱机模式：使用 Tokei 推断项目信息")
                shared_brain.project_info = self._build_fallback_project_info(
                    ctx, project_file_list
                )
                shared_brain.project_info_compact = shared_brain.project_info
            else:
                # 信息收集（必须先完成，Plan 和 QuickScan 都依赖 project_info）
                if not self._collect_or_reuse_project_info(ctx, shared_brain, information_collection_id, project_file_list):
                    return

            # 1.5) 信息收集完成后，Plan 和 QuickScan 并行执行
            # Plan 只依赖 project_info，不依赖 QuickScan 结果
            # QuickScan 只依赖文件列表，不依赖 Plan
            # 两者在 Sink/Chain 开始前汇合即可
            # 脱机模式：跳过 Plan（LLM），仅执行 QuickScan

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
                if quick_scan_findings:
                    self._log(ctx.task_id, "INFO",
                              f"快速扫描完成: 发现 {len(quick_scan_findings)} 个潜在问题 "
                              f"(代码={scan_stats.get('code_findings', 0)}, "
                              f"组件={scan_stats.get('component_findings', 0)})")
                    self._bus.publish(EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"快速扫描: {len(quick_scan_findings)} 个潜在问题",
                        status="completed",
                        result=f"快速扫描发现 {len(quick_scan_findings)} 个潜在安全线索，"
                               f"将作为 LLM 深度审计的参考输入",
                    ))
                else:
                    self._log(ctx.task_id, "INFO", "快速扫描完成: 未发现明显问题")

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

                # 保存过滤前的原始结果，供 LLM 审计参考
                quick_scan_findings_raw = list(quick_scan_findings)

                if ctx.offline_mode:
                    # 脱机模式：无 LLM，仅靠规则过滤
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
                    # 联机模式：LLM 验证替代规则过滤
                    # LLM 验证对过滤前的完整结果做判断，避免规则过滤误伤真实漏洞
                    if quick_scan_findings:
                        try:
                            self._log(ctx.task_id, "INFO",
                                      f"开始 LLM 验证快速扫描结果: {len(quick_scan_findings)} 条")
                            verifier = QuickScanVerifier(
                                llm=shared_brain.llm,
                                project_path=str(ctx.project_path),
                            )
                            quick_scan_findings = verifier.verify_findings(
                                quick_scan_findings,
                                project_info=str(shared_brain.project_info or ""),
                            )
                            v_stats = verifier.get_stats()
                            self._log(ctx.task_id, "INFO",
                                      f"LLM 验证快速扫描完成: "
                                      f"confirmed={v_stats['confirmed']} "
                                      f"false_positive={v_stats['false_positive']} "
                                      f"need_review={v_stats['need_review']} "
                                      f"error={v_stats['error']}")

                            # 过滤掉 LLM 判定的误报
                            before_count = len(quick_scan_findings)
                            quick_scan_findings = QuickScanVerifier.filter_verified(quick_scan_findings)
                            filtered_count = before_count - len(quick_scan_findings)
                            if filtered_count > 0:
                                self._log(ctx.task_id, "INFO",
                                          f"LLM 验证过滤 {filtered_count} 条误报，"
                                          f"保留 {len(quick_scan_findings)} 条")

                            # LLMOptimizer 仅做去重和排序，不做误报检测（LLM 已验证）
                            try:
                                llm_optimizer = LLMOptimizer()
                                opt_result = llm_optimizer.optimize_findings(
                                    quick_scan_findings,
                                    project_root=str(ctx.project_path),
                                    confidence_threshold=0.1,  # LLM 已验证，降低阈值
                                )
                                quick_scan_findings = opt_result["optimized_findings"]
                                opt_stats = opt_result["stats"]
                                self._log(ctx.task_id, "INFO",
                                          f"LLMOptimizer 去重排序: "
                                          f"输入={opt_stats['total_in']} → "
                                          f"去重后={opt_stats['after_dedup']} "
                                          f"最终={opt_stats['final_count']}")
                            except Exception as e:
                                self._log(ctx.task_id, "WARNING", f"LLMOptimizer 去重失败: {e}")

                            self._bus.publish(EventStart(
                                task_id=ctx.task_id,
                                module=self.MODULE_NAME,
                                action_type=ActionType.INFORMATION,
                                reason=f"LLM 验证快速扫描: {v_stats['confirmed']} 确认, "
                                       f"{v_stats['false_positive']} 误报, "
                                       f"{v_stats['need_review']} 待审",
                                status="completed",
                            ))
                        except Exception as e:
                            self._log(ctx.task_id, "WARNING", f"LLM 验证快速扫描失败（使用原始结果）: {e}")

                # 脱机模式：已经在上方完成了全部入库+过滤标记
                # 联机模式：将过滤前的完整结果注入 shared_brain 供 SinkFinder 参考
                if not ctx.offline_mode:
                    shared_brain.quick_scan_findings = quick_scan_findings_raw if quick_scan_findings_raw else quick_scan_findings

                # 快速扫描结果立即入库（脱机模式已在规则过滤步骤中入库，跳过避免重复）
                if quick_scan_findings and not ctx.offline_mode:
                    try:
                        from src.services.vulnerability_service import persist_quick_scan_findings
                        qs_persisted = persist_quick_scan_findings(
                            ctx.project_id, ctx.task_id, quick_scan_findings
                        )
                        self._log(ctx.task_id, "INFO",
                                  f"快速扫描发现 {qs_persisted} 条已实时入库")

                        # 联机模式：更新已入库记录的 LLM 验证状态
                        try:
                            from src.services.vulnerability_service import update_quick_scan_verification
                            update_quick_scan_verification(ctx.task_id, quick_scan_findings)
                        except Exception as e:
                            self._log(ctx.task_id, "WARNING", f"更新快速扫描验证状态失败: {e}")
                    except Exception as e:
                        self._log(ctx.task_id, "WARNING", f"快速扫描入库失败: {e}")

            # 脱机模式：仅执行 QuickScan 流水线，跳过 Plan
            if ctx.offline_mode:
                self._log(ctx.task_id, "INFO", "脱机模式：跳过审计计划生成，仅执行快速扫描")
                _run_quick_scan_pipeline()
            else:
                # 并行执行 Plan 和 QuickScan 流水线
                self._log(ctx.task_id, "INFO", "[Checkpoint] 开始并行执行 Plan + QuickScan")
                try:
                    with ThreadPoolExecutor(max_workers=2) as parallel_executor:
                        plan_future = parallel_executor.submit(_run_plan)
                        scan_future = parallel_executor.submit(_run_quick_scan_pipeline)

                        plan_success = plan_future.result()
                        self._log(ctx.task_id, "INFO", f"[Checkpoint] Plan 线程完成, plan_success={plan_success}")
                        scan_future.result()  # 等待 QuickScan 完成（忽略异常，已在内部处理）
                        self._log(ctx.task_id, "INFO", "[Checkpoint] QuickScan 线程完成")
                    self._log(ctx.task_id, "INFO", "[Checkpoint] ThreadPoolExecutor 正常关闭")
                except Exception as exec_ex:
                    self._log(ctx.task_id, "ERROR", f"[Checkpoint] ThreadPoolExecutor 异常退出: {exec_ex}")
                    raise

                if not plan_success:
                    self._log(ctx.task_id, "WARNING", "审计计划缺失，流程结束")
                    self._bus.publish(EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason="审计计划缺失，流程结束",
                        status="failed",
                    ))
                    self._bus.publish(TaskStatusEvent(task_id=ctx.task_id, status="failed", message="审计计划缺失"))
                    return

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

            # 3) Sink 发现 + 链路分析（脱机模式跳过，仅使用快速扫描结果）
            if ctx.offline_mode:
                self._log(ctx.task_id, "INFO", "脱机模式：跳过 Sink/Chain 深度分析")
            else:
                self._log(ctx.task_id, "INFO", "[Checkpoint] 进入 SinkFinder + ChainAnalyzer 阶段")
                audit_state.update_progress(3, 4, "Sink发现与链路分析")
                sink_finder = SinkFinder(brain=shared_brain)
                chain_analyzer = ChainAnalyzer(brain=shared_brain)

                reset_running_audit_nodes_to_pending_for_task(ctx.task_id)
                reset_running_sink_and_chain_nodes_to_pending_for_task(ctx.task_id)
                try:
                    self._drive_sink_and_chain(ctx, plan_id, sink_finder, chain_analyzer)
                except TaskPausedError:
                    self._log(ctx.task_id, "INFO", "任务已暂停，编排协作式退出")
                    return
                except Exception as e:
                    self._log(ctx.task_id, "ERROR", f"分析过程错误 {str(e)}")
                    self._bus.publish(
                        EventStart(
                            task_id=ctx.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.CHAIN_ANALYSIS,
                            reason=f"分析过程错误: {e}",
                            status="failed",
                        )
                    )
                    self._bus.publish(TaskStatusEvent(task_id=ctx.task_id, status="failed", message="分析过程错误"))
                    return

            ensure_task_running(ctx.task_id)
            audit_state.update_progress(4, 4, "完成")

            # 4) 后处理阶段：CoverageTracker 初始化 与 Neo4j 查询互不依赖，并行执行
            coverage_tracker = None
            all_findings_for_report = []

            def _init_coverage_tracker():
                """初始化覆盖率追踪器（纯本地操作，不依赖 Neo4j）"""
                nonlocal coverage_tracker
                try:
                    ct = CoverageTracker(str(ctx.project_path), project_file_list)
                    # 标记快速扫描已覆盖的文件
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
                """从 PostgreSQL 收集 findings（与 API 报告数据源一致）+ 去重 + 验证"""
                nonlocal all_findings_for_report
                findings = []
                try:
                    from src.infrastructure.db import session_scope
                    from src.infrastructure.db.models import Vulnerability
                    with session_scope() as _s:
                        rows = _s.query(Vulnerability).filter(
                            Vulnerability.task_id == ctx.task_id,
                            Vulnerability.status != "false_positive",
                        ).all()
                        for row in rows:
                            findings.append({
                                "id": row.id,
                                "project_id": row.project_id,
                                "task_id": row.task_id,
                                "vul_name": row.vul_name,
                                "vuln_type": row.category_name,
                                "category_name": row.category_name,
                                "verdict": row.verdict,
                                "severity": row.level,
                                "level": row.level,
                                "confidence": row.confidence,
                                "source": row.source or "quick_scan",
                                "neo4j_element_id": row.neo4j_element_id,
                                "status": row.status,
                                "verification_status": row.verification_status,
                            })
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"PostgreSQL 查询 findings 失败，降级使用内存数据: {e}")

                # PostgreSQL 查询成功则直接使用；降级时仍用快扫内存数据
                merged = findings if findings else quick_scan_findings

                # 跨源去重（脱机模式跳过 LLM 去重，仅做简单合并）
                if merged:
                    try:
                        if ctx.offline_mode:
                            # 脱机模式：基于规则的简单去重（按 file+line+vuln_type）
                            seen = set()
                            deduped = []
                            for f in merged:
                                key = (f.get("file", ""), f.get("line", ""), f.get("vuln_type", ""))
                                if key not in seen:
                                    seen.add(key)
                                    deduped.append(f)
                            merged = deduped
                        else:
                            dedup_optimizer = LLMOptimizer()
                            merged = dedup_optimizer.deduplicate_findings(merged)
                            merged = dedup_optimizer.rank_findings(merged)
                    except Exception as e:
                        self._log(ctx.task_id, "WARNING", f"跨源去重失败（使用原始合并结果）: {e}")

                # ValidationService: 验证漏洞发现，检测幻觉并修正行号
                if merged:
                    try:
                        from src.services.validation_service import ValidationService
                        validator = ValidationService()
                        val_result = validator.validate_findings(merged, str(ctx.project_path))
                        if val_result.hallucinations:
                            self._log(ctx.task_id, "WARNING",
                                      f"ValidationService 检测到 {len(val_result.hallucinations)} 个疑似幻觉")
                        if val_result.corrected:
                            self._log(ctx.task_id, "INFO",
                                      f"ValidationService 修正了 {len(val_result.corrected)} 个行号")
                        merged = val_result.validated
                    except Exception as e:
                        self._log(ctx.task_id, "WARNING", f"ValidationService 验证失败（使用原始结果）: {e}")

                return merged

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

            # 5) 审计评分、覆盖率报告 互不依赖，并行执行
            audit_score_result = None
            coverage_report = None

            def _calc_audit_score():
                """计算审计评分"""
                nonlocal audit_score_result
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
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"生成审计评分报告失败: {e}")

            def _calc_coverage_report():
                """生成覆盖率报告"""
                nonlocal coverage_report
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
                except Exception as e:
                    self._log(ctx.task_id, "WARNING", f"生成覆盖率报告失败: {e}")

            with ThreadPoolExecutor(max_workers=2) as report_executor:
                score_future = report_executor.submit(_calc_audit_score)
                coverage_future = report_executor.submit(_calc_coverage_report)
                score_future.result()
                coverage_future.result()

            # 6) 防漏报兜底：依赖覆盖率报告和 findings
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
                        # 将盲区任务发布为事件，供后续审计轮次使用
                        for task in gapfill_tasks:
                            target_file = task.get("targetFile", "")
                            attack_class = task.get("attackClass", "")
                            reason = task.get("reason", "")
                            self._bus.publish(EventStart(
                                task_id=ctx.task_id,
                                module=self.MODULE_NAME,
                                action_type=ActionType.INFORMATION,
                                reason=f"覆盖盲区: {target_file or task.get('subsystem', '')} "
                                       f"缺少 {attack_class} 检查 ({reason})",
                                status="completed",
                                result=f"建议补充审查: {target_file} 的 {attack_class} 相关安全问题",
                            ))
                        # 将 gapfill 任务注入 Brain 供 SinkFinder 后续轮次参考
                        shared_brain.gapfill_tasks = gapfill_tasks
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"防漏报兜底执行失败: {e}")

            # 7) 生成 HTML 审计报告：依赖所有上述结果
            try:
                from src.services.report_generator import write_report_to_file
                report_dir = os.path.join(str(ctx.project_path), ".argusmind", "reports")
                report_info = write_report_to_file(
                    report_dir=report_dir,
                    task_id=ctx.task_id,
                    project_name=ctx.project_name,
                    findings=all_findings_for_report,
                    audit_score=audit_score_result,
                    coverage_report=coverage_report,
                    scan_stats=scan_stats,
                    quick_scan_findings=quick_scan_findings,
                    llm_findings=[f for f in all_findings_for_report if f.get("source") not in ("quick_scan", "component_scan")],
                    exploit_chain_report=None,
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
            except Exception as e:
                self._log(ctx.task_id, "WARNING", f"生成 HTML 审计报告失败: {e}")

            audit_state.complete({"task_id": ctx.task_id})

            # 确保所有 AuditStage 节点状态与任务状态一致
            db_manager.neo4j_repository.client.execute_write(
                """
                MATCH (s:AuditStage {task_id: $task_id})
                WHERE s.status = 'running'
                SET s.status = 'completed'
                """,
                {"task_id": ctx.task_id},
            )

            self._bus.publish(TaskStatusEvent(
                task_id=ctx.task_id, status="completed",
                vuln_count=len(all_findings_for_report),
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

            # 确保所有 AuditStage 节点状态与任务失败状态一致
            db_manager.neo4j_repository.client.execute_write(
                """
                MATCH (s:AuditStage {task_id: $task_id})
                WHERE s.status = 'running'
                SET s.status = 'failed'
                """,
                {"task_id": ctx.task_id},
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
    # 同语言漏洞类型并行上限（控制 LLM 并发，避免限流）
    _MAX_PARALLEL_SINK_FINDERS = 5
    _MAX_PARALLEL_CHAIN_ANALYZERS = 2  # ChainAnalyzer LLM 轮次多，限制并发

    def _drive_sink_and_chain(
        self,
        ctx: ExecutionContext,
        plan_id: str,
        sink_finder: SinkFinder,
        chain_analyzer: ChainAnalyzer,
    ) -> None:
        """按语言 → 漏洞类型驱动 SinkFinder + ChainAnalyzer。

        - 同语言下不同漏洞类型的 SinkFinder 可并行执行
        - 同语言下不同漏洞类型的 ChainAnalyzer 可并行执行
        - 单个漏洞类型内链路分析失败不中断其他类型
        - 单个链路失败不中断同类型其他链路（由 _process_chain_analysis 保证）
        """
        while True:
            ensure_task_running(ctx.task_id)
            lang_row = fetch_next_pending_language_for_plan(plan_id)
            if not lang_row:
                break
            lang_node_id = lang_row["node_id"]
            language_name = lang_row.get("language") or ""

            # 收集该语言下所有待处理的漏洞类型
            self._log(ctx.task_id, "INFO", f"[SinkChain] 批量查询 {language_name} 的待处理漏洞类型")
            pending_categories = fetch_all_pending_risk_categories(lang_node_id)
            self._log(ctx.task_id, "INFO", f"[SinkChain] {language_name} 共 {len(pending_categories)} 个漏洞类型")

            if not pending_categories:
                mark_language_status(lang_node_id, "completed")
                continue

            self._log(ctx.task_id, "INFO",
                      f"语言 {language_name} 共 {len(pending_categories)} 个漏洞类型，"
                      f"并行 SinkFinder（上限 {self._MAX_PARALLEL_SINK_FINDERS}），"
                      f"并行 ChainAnalyzer（上限 {self._MAX_PARALLEL_CHAIN_ANALYZERS}）")

            # ---- Phase 1: 并行 SinkFinder ----
            def _submit_sink_finder(cat_row: Dict) -> None:
                vul_node_id = cat_row["node_id"]
                category_name = cat_row.get("category_name") or ""
                mark_language_status(lang_node_id, "running")
                mark_risk_category_status(vul_node_id, "running")
                ensure_knowledge_element_id_for_risk_category(vul_node_id)
                if cat_row.get("sink_finder_completed"):
                    self._log(ctx.task_id, "INFO",
                              f"{language_name} {category_name} SinkFinder 已完成，跳过")
                    return
                self._log(ctx.task_id, "INFO",
                          f"SinkFinder: 语言={language_name} 类型={category_name} (vul_node_id={vul_node_id})")
                self._bus.publish(EventStart(
                    task_id=ctx.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=f"开始审计：\n语言 {language_name}\n漏洞类型:{category_name}\n"
                           f"描述：{cat_row.get('risk_description', '')}\n"
                           f"依据：{cat_row.get('reasoning_basis', '')}",
                ))
                self._log(ctx.task_id, "INFO",
                          f"SinkFinder 开始: {language_name}/{category_name}")
                sink_finder.run(
                    language_name,
                    category_name,
                    vul_node_id,
                    cat_row.get("reasoning_basis", ""),
                    cat_row.get("risk_description", ""),
                )
                self._log(ctx.task_id, "INFO",
                          f"SinkFinder 完成: {language_name}/{category_name}")
                mark_risk_category_sink_finder_completed(vul_node_id)

            if len(pending_categories) > 1:
                # SinkFinder 并行上限根据 CPU 动态调整（控制 LLM 并发，避免限流）
                max_sink_workers = _get_optimal_workers(base=2, max_limit=5)
                with ThreadPoolExecutor(max_workers=max_sink_workers) as cat_executor:
                    futures = {cat_executor.submit(_submit_sink_finder, cr): cr for cr in pending_categories}
                    for future in as_completed(futures):
                        cr = futures[future]
                        try:
                            future.result()
                        except (TaskPausedError, LLMError):
                            raise
                        except Exception as ex:
                            self._log(ctx.task_id, "ERROR",
                                      f"SinkFinder 异常 category={cr.get('category_name')}: {ex}")
            else:
                for cr in pending_categories:
                    _submit_sink_finder(cr)

            # ---- Phase 2: 并行 ChainAnalyzer（不同漏洞类型可并行） ----
            self._log(ctx.task_id, "INFO",
                      f"Phase 2 开始: ChainAnalyzer 处理 {len(pending_categories)} 个漏洞类型 (最多{self._MAX_PARALLEL_CHAIN_ANALYZERS}路并行)")
            def _submit_chain_analysis(cat_row: Dict) -> None:
                cat_name = cat_row.get("category_name") or ""
                try:
                    self._process_chain_analysis(ctx, cat_row, chain_analyzer)
                except (TaskPausedError, LLMError):
                    raise
                except Exception as ex:
                    self._log(ctx.task_id, "ERROR",
                              f"ChainAnalyzer 异常 category={cat_name}: {ex}")
                    # 不中断其他漏洞类型的分析

            if len(pending_categories) > 1:
                # ChainAnalyzer 并行上限根据 CPU 动态调整（LLM 轮次多，降低并发）
                max_chain_workers = _get_optimal_workers(base=1, max_limit=2)
                with ThreadPoolExecutor(max_workers=max_chain_workers) as chain_executor:
                    chain_futures = {chain_executor.submit(_submit_chain_analysis, cr): cr
                                     for cr in pending_categories}
                    for future in as_completed(chain_futures):
                        cr = chain_futures[future]
                        try:
                            future.result()
                        except (TaskPausedError, LLMError):
                            raise
                        except Exception as ex:
                            self._log(ctx.task_id, "ERROR",
                                      f"ChainAnalyzer 线程异常 category={cr.get('category_name')}: {ex}")
            else:
                for cr in pending_categories:
                    _submit_chain_analysis(cr)

            mark_language_status(lang_node_id, "completed")

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
