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
import uuid
from datetime import datetime

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
from src.core.task_control import TaskPausedError, ensure_task_running
from src.llm import LLMError
from src.services.project_service import get_project
from services.chain_analysis_service import (
    ensure_knowledge_element_id_for_risk_category,
    fetch_non_completed_analysis_results_for_vul,
    reset_non_completed_analysis_results_to_pending_for_vul,
)
from services.plan_service import (
    fetch_next_pending_language_for_plan,
    fetch_next_pending_risk_category_for_language,
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


class Orchestrator:
    """ReAct 风格的审计流程编排器"""
    MODULE_NAME = "Orchestrator"

    def __init__(self) -> None:
        self._bus = get_event_bus()

    # ---------- 日志辅助 ----------
    def _log(self, task_id: str, level: str, message: str) -> None:
        self._bus.publish(
            LogEvent(level=level, module=self.MODULE_NAME, message=message, task_id=task_id)
        )

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

    def _collect_or_reuse_project_info(
        self,
        ctx: ExecutionContext,
        shared_brain: Brain,
        information_collection_id: str,
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
                    self._log(ctx.task_id, "ERROR", "收集到的项目信息为空")
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
                return True
            except Exception as e:
                raise
        except Exception as ex:
            self._log(ctx.task_id, "ERROR", str(ex))
            raise

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
        try:
            brain_ctx = BrainContext(
                project_id=ctx.project_id,
                project_name=ctx.project_name,
                project_path=str(ctx.project_path),
                task_id=ctx.task_id,
                llm_config=ctx.llm_config,
            )
            # 创建【开始初始化项目】事件
            shared_brain = Brain(brain_ctx)

            # 0) Task 根节点（幂等，替代原 Project 根）
            task_root_node_id = self._ensure_task_node(ctx)

            # 1) 信息收集阶段
            information_collection_id = self._ensure_stage_node(
                ctx, task_root_node_id, "Information Collection"
            )
            self._log(ctx.task_id, "INFO", f"信息收集阶段 node_id={information_collection_id}")

            if not self._collect_or_reuse_project_info(ctx, shared_brain, information_collection_id):
                return

            # 2) 生成审计计划
            plan_result = None
            reused_plan_id = find_completed_plan_stage_node_id_for_task(ctx.task_id)
            if reused_plan_id:
                plan_id = reused_plan_id
                self._log(ctx.task_id, "INFO", f"复用已有审计计划 plan_id={plan_id}")
            else:
                plan_id = self._ensure_stage_node(
                    ctx,
                    information_collection_id,
                    "make a plan",
                    parent_label="AuditStage",
                )
                self._log(ctx.task_id, "INFO", f"生成审计计划 plan_id={plan_id}")

                # 制定审计计划
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
                        timeout_seconds=60 * 10,
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

            if not (reused_plan_id or plan_result):
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

            # 3) Sink 发现 + 链路分析
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
            self._bus.publish(TaskStatusEvent(task_id=ctx.task_id, status="completed"))
            self._log(ctx.task_id, "INFO", f"任务 {ctx.task_id} 编排完成")
        except TaskPausedError:
            self._log(ctx.task_id, "INFO", "任务已暂停，编排协作式退出")
            return
        except Exception as ex:
            msg = f"编排异常终止: {ex}"
            self._log(ctx.task_id, "ERROR", msg)
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
    def _drive_sink_and_chain(
        self,
        ctx: ExecutionContext,
        plan_id: str,
        sink_finder: SinkFinder,
        chain_analyzer: ChainAnalyzer,
    ) -> None:
        while True:
            ensure_task_running(ctx.task_id)
            lang_row = fetch_next_pending_language_for_plan(plan_id)
            if not lang_row:
                break
            lang_node_id = lang_row["node_id"]
            language_name = lang_row.get("language") or ""
            while True:
                ensure_task_running(ctx.task_id)
                cat_row = fetch_next_pending_risk_category_for_language(lang_node_id)
                if not cat_row:
                    break
                vul_node_id = cat_row["node_id"]
                category_name = cat_row.get("category_name") or ""
                reasoning_basis = cat_row.get("reasoning_basis", "")
                risk_description = cat_row.get("risk_description", "")
                self._log(
                    ctx.task_id,
                    "INFO",
                    f"语言 {language_name} 漏洞类型 {category_name} (vul_node_id={vul_node_id})",
                )
                self._bus.publish(
                    EventStart(
                        task_id=ctx.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"开始审计：\n"
                               f"语言 {language_name}\n漏洞类型:{category_name}\n描述：{risk_description}\n 依据：{reasoning_basis}",
                    )
                )
                mark_language_status(lang_node_id, "running")
                mark_risk_category_status(vul_node_id, "running")
                knowledge_element_id = ensure_knowledge_element_id_for_risk_category(vul_node_id)
                if cat_row.get("sink_finder_completed"):
                    self._log(ctx.task_id, "INFO", f"{language_name} {category_name}SinkFinder 已完成，跳过")
                else:
                    sink_finder.run(
                        language_name,
                        category_name,
                        vul_node_id,
                        reasoning_basis,
                        risk_description,
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
                            chain_analyzer.resume_secondary_confirmation_for_stored_result(
                                ar_node_id=ar_nid,
                                category_name=category_name,
                                risk_description=cat_row["risk_description"],
                                knowledge_element_id=knowledge_element_id,
                            )
                        except (TaskPausedError, LLMError):
                            # LLM 致命错误（额度/鉴权等）必须向上传播，由编排层标记任务失败，
                            # 不能像普通异常那样仅记日志后继续，否则会被误判为"已完成"。
                            raise
                        except Exception as ex:  # pragma: no cover
                            self._log(
                                ctx.task_id,
                                "ERROR",
                                f"补跑二次校验失败 ar={ar_nid!r}: {ex}",
                            )

                chain_count = 0
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
                        continue
                    mark_sink_flow_leaf_status(leaf_id, SINK_FLOW_LEAF_STATUS_RUNNING)
                    chain_count += 1
                    try:
                        chain_analyzer.run(
                            chain=chain,
                            vul_description=cat_row["risk_description"],
                            category_name=category_name,
                            knowledge_element_id=knowledge_element_id,
                        )
                    except (TaskPausedError, LLMError):
                        # LLM 致命错误（额度/鉴权等）必须向上传播，由编排层标记任务失败，
                        # 不能在此 return（会被外层误判为正常结束并标记 completed）。
                        raise
                    except Exception as ex:  # pragma: no cover
                        self._log(ctx.task_id, "ERROR", f"链路分析异常 leaf={leaf_id}: {ex}")
                        return
                self._log(
                    ctx.task_id,
                    "INFO",
                    f"漏洞类型 {category_name} 链路分析完成，共 {chain_count} 条",
                )
                mark_risk_category_status(vul_node_id, "completed")
            mark_language_status(lang_node_id, "completed")
