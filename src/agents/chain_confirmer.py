# -*- coding: utf-8 -*-
"""
ChainConfirmer Agent —— 漏洞链路二次校验 Agent。

对 ChainAnalyzer 产出的 LIKELY_VULNERABLE / POSSIBLY_VULNERABLE 结论进行独立审查，
以"质疑者"视角验证 5 类核心假设是否成立，最终输出三种状态之一：
  - CONFIRMED：漏洞确认
  - REJECTED：驳回（误报）

设计要点：
  - 与 ChainAnalyzer 共享 Brain（工具集、LLM），但拥有独立的对话上下文
  - 最大轮次较小（默认 15 轮），因为只做校验不做发现
  - 校验结果作为 verification_status / verification_reason /
    vulnerability_analysis_report（Markdown 字符串）、poc（Python 脚本）、level（严重等级）等写回 resolution
"""
import json
import logging
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.core.enums import ActionType
from src.core.event_span import start_event_span
from src.agents.base import BaseAgent
from src.core.task_control import ensure_task_running
from src.agents.brain import Brain
from src.agents.prompt.chain_confirmer import (
    chain_confirmer_system_prompt,
    chain_confirmer_user_prompt,
    chain_confirmer_force_conclude_prompt,
)
from src.core.task_control import TaskPausedError
from services.chain_analysis_service import update_analysis_result_verification, attach_audit_info_record

logger = logging.getLogger(__name__)


class ChainConfirmer(BaseAgent):
    """
    漏洞链路二次校验 Agent。

    接收 ChainAnalyzer 的 resolution 及链路上下文，通过独立的 LLM 对话
    逐项验证核心安全假设，输出确认/驳回/待人工复审结论。
    """
    MODULE_NAME = "chain_confirmer"
    DEFAULT_MAX_ROUNDS = 50
    VERDICTS_NEED_CONFIRMATION = {"LIKELY_VULNERABLE", "POSSIBLY_VULNERABLE"}

    def __init__(self, brain: Optional[Brain] = None, max_rounds: int = DEFAULT_MAX_ROUNDS):
        super().__init__(brain=brain)
        self.max_rounds = max_rounds

    def run(
        self,
        resolution: Dict[str, Any],
        sink_chain_context: str,
        audit_info_context: str,
        risk_category: str,
        risk_description: str,
        knowledge_element_id: str = None,
    ) -> Dict[str, Any]:
        """
        对一个 resolution 执行二次校验。

        Args:
            resolution: ChainAnalyzer 产出的 final_resolution 对象
            sink_chain_context: 格式化后的 Sink 链路上下文
            audit_info_context: 沿途审计信息
            risk_category: 漏洞类型名称
            risk_description: 风险描述

        Returns:
            包含 verification_status、verification_reason、
            vulnerability_analysis_report（Markdown）、poc、level 等的字典
        """
        conversation = self._build_context(
            resolution=resolution,
            sink_chain_context=sink_chain_context,
            audit_info_context=audit_info_context,
            risk_category=risk_category,
            risk_description=risk_description,
        )

        return self._run_confirmation_loop(conversation, knowledge_element_id)

    def maybe_confirm_resolution(
        self,
        resolution: Dict[str, Any],
        category_name: str,
        risk_description: str,
        *,
        knowledge_element_id: Optional[str] = None,
        fetch_sink_chain_context: Callable[[str, Optional[str]], Tuple[str, str]],
    ) -> None:
        """
        当 verdict 为 LIKELY_VULNERABLE 或 POSSIBLY_VULNERABLE 时，
        执行二次校验，并将结果写回 resolution 和 Neo4j。

        Sink 链路与 AuditInfo 上下文由 fetch_sink_chain_context(ar_node_id, knowledge_element_id)
        从 Neo4j 按 resolution['_ar_node_id']（AnalysisResult 的 Neo4j elementId）沿 :FLOW 反查得到，不使用内存中的 sink_nodes。
        """
        verdict = resolution.get("verdict", "")
        if verdict not in self.VERDICTS_NEED_CONFIRMATION:
            return

        ar_node_id = (resolution.get("_ar_node_id") or "").strip()
        if not ar_node_id:
            msg = "[ChainConfirmer] 无法二次校验：resolution 缺少 _ar_node_id"
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            resolution["verification_status"] = "REJECTED"
            resolution["verification_reason"] = "缺少 AnalysisResult 节点引用（_ar_node_id / elementId），无法二次校验"
            resolution["confirmation_rounds"] = 0
            resolution["vulnerability_analysis_report"] = ""
            resolution["poc"] = ""
            resolution["level"] = ""
            return

        try:
            sink_chain_context, audit_info_context = fetch_sink_chain_context(
                ar_node_id,
                knowledge_element_id,
            )
            logger.info(
                "[ChainConfirmer] 触发二次校验 | verdict=%s | branch_id=%s",
                verdict,
                resolution.get("branch_id", ""),
            )
            self._publish_log(
                "INFO",
                f"[ChainConfirmer] 触发二次校验 | verdict={verdict} "
                f"branch_id={resolution.get('branch_id', '')} ar_node_id={ar_node_id}",
            )
            confirmation = self.run(
                resolution=resolution,
                sink_chain_context=sink_chain_context,
                audit_info_context=audit_info_context,
                risk_category=category_name,
                risk_description=risk_description,
                knowledge_element_id=knowledge_element_id,
            )
        except TaskPausedError:
            logger.info(
                "[ChainConfirmer] 任务已暂停/取消，二次校验中断 branch_id=%s",
                resolution.get("branch_id", ""),
            )
            self._publish_log(
                "INFO",
                f"[ChainConfirmer] 任务已暂停/取消，二次校验中断 "
                f"branch_id={resolution.get('branch_id', '')}",
            )
            raise
        except Exception as e:
            logger.exception("[ChainConfirmer] 二次校验或上下文拉取异常，标记为 REJECTED: %s", e)
            tb = traceback.format_exc()
            tail = tb[-4000:] if len(tb) > 4000 else tb
            self._publish_log(
                "ERROR",
                f"[ChainConfirmer] 二次校验或上下文拉取异常，标记为 REJECTED: {e!r}\n{tail}",
            )
            confirmation = {
                "verification_status": "REJECTED",
                "verification_reason": f"二次校验过程异常: {e}",
                "confirmation_rounds": 0,
                "vulnerability_analysis_report": "",
                "poc": "",
                "level": "",
            }

        resolution["verification_status"] = confirmation["verification_status"]
        resolution["verification_reason"] = confirmation["verification_reason"]
        resolution["confirmation_rounds"] = confirmation.get("confirmation_rounds", 0)
        resolution["vulnerability_analysis_report"] = confirmation.get(
            "vulnerability_analysis_report", ""
        ) or ""
        resolution["poc"] = confirmation.get("poc", "") or ""
        resolution["level"] = str(confirmation.get("level") or "").strip()
        if resolution["verification_status"] == "CONFIRMED":
            msg = "确认漏洞"
        else:
            msg = "初次结果误报"
        try:
            start_event_span(
                task_id=self._brain.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.VULNERABILITY,
                reason=(
                    f'[{msg}] {resolution.get("vul_name", "")} '
                    f'{resolution.get("verification_reason", "")}'
                ),
                tool_arguments={
                    "vul_neo4j_ele_id": ar_node_id,
                    "verification_status": resolution["verification_status"],
                    "stage": "confirmer",
                },
            )
        except Exception as e:
            msg = f"[ChainConfirmer] 二次校验结果事件上报失败（已忽略）: {e}"
            logger.warning(msg)
            self._publish_log("WARNING", msg)

        if ar_node_id:
            try:
                update_analysis_result_verification(
                    ar_node_id=ar_node_id,
                    verification_status=confirmation["verification_status"],
                    verification_reason=confirmation["verification_reason"],
                    vulnerability_analysis_report=resolution["vulnerability_analysis_report"],
                    poc=resolution["poc"],
                    vul_id=resolution.get("_vulnerability_id", ""),
                    level=resolution.get("level") or "",
                )
            except Exception as e:
                logger.exception("[ChainConfirmer] 写回 AR verification 失败: %s", e)
                tb = traceback.format_exc()
                tail = tb[-4000:] if len(tb) > 4000 else tb
                self._publish_log(
                    "ERROR",
                    f"[ChainConfirmer] 写回 AR verification 失败: {e!r}\n{tail}",
                )

        logger.info(
            "[ChainConfirmer] 二次校验完成 | status=%s | reason=%s",
            confirmation["verification_status"],
            (confirmation.get("verification_reason") or "")[:100],
        )
        self._publish_log(
            "INFO",
            f"[ChainConfirmer] 二次校验完成 | status={confirmation['verification_status']} "
            f"rounds={confirmation.get('confirmation_rounds', 0)} "
            f"reason={(confirmation.get('verification_reason') or '')[:120]}",
        )

    def _build_context(
        self,
        resolution: Dict[str, Any],
        sink_chain_context: str,
        audit_info_context: str,
        risk_category: str,
        risk_description: str,
    ) -> List[Dict[str, str]]:
        """构造确认 Agent 的完整对话上下文。"""
        tool_schema = self._brain.tool_registry.get_all_tools_schema()

        system_content = chain_confirmer_system_prompt.format(
            project_info=self._brain.project_info_compact or "(无项目信息)",
            tool_registry=tool_schema,
        )

        resolution_json = json.dumps(resolution, ensure_ascii=False, indent=2)
        user_content = chain_confirmer_user_prompt.format(
            original_resolution=resolution_json,
            risk_category=risk_category,
            risk_description=risk_description,
            sink_chain_context=sink_chain_context,
            audit_info_context=audit_info_context or "(无审计信息)",
        )

        return [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]

    def _run_confirmation_loop(
        self,
        conversation: List[Dict[str, str]],
        knowledge_element_id: str = None,
    ) -> Dict[str, Any]:
        """
        执行多轮 LLM 确认循环。

        Returns:
            {verification_status, verification_reason,
             vulnerability_analysis_report, poc, level, confirmation_rounds}
        """
        info_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type="",
            reason="",
        )
        self._publish_log(
            "INFO",
            f"[ChainConfirmer] 开始确认循环 | max_rounds={self.max_rounds}",
        )
        consecutive_invalid_action = 0

        for round_num in range(1, self.max_rounds + 1):
            ensure_task_running(self._brain.task_id)
            self._publish_log(
                "INFO",
                f"[ChainConfirmer] LLM 轮次 {round_num}/{self.max_rounds}",
            )
            step, input_tokens, output_tokens = self._llm_step(conversation)
            if step is None:
                self._publish_log(
                    "WARNING",
                    f"[ChainConfirmer] LLM 返回为空，重试 ({round_num}/{self.max_rounds})",
                )
                continue
            action = step.get("action", "")
            thought = step.get("thought", "")
            if action in ("tool_call", "record_info", "confirmation_result"):
                consecutive_invalid_action = 0
            logger.debug("[ChainConfirmer] step=%s", json.dumps(step, ensure_ascii=False))
            if action == "tool_call":
                tool_name = step.get("tool_name", "") or ""
                self._publish_log(
                    "INFO",
                    f"[ChainConfirmer] 调用工具 {tool_name!r} (轮 {round_num})",
                )
                arguments = step.get("arguments", "")
                tool_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.TOOL_CALL,
                    tool_name=step.get("tool_name", ""),
                    reason=thought,
                    tool_arguments=arguments
                )
                tool_span.add_llm_tokens(input_tokens, output_tokens)
                tool_result = self._execute_tool_call(step, conversation, tool_span)
                if tool_result is not None:
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "TOOL_RESULT",
                            "tool_name": step.get("tool_name", "unknown"),
                            "result": tool_result,
                        }, ensure_ascii=False, default=str),
                    })
                else:
                    tool_result = "工具调用返回为空"
                    self._publish_log(
                        "WARNING",
                        f"[ChainConfirmer] 工具 {tool_name!r} 未返回结果 (轮 {round_num})",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "TOOL_RESULT_NONE",
                            "tool_name": step.get("tool_name", "unknown"),
                            "result": tool_result,
                        }, ensure_ascii=False, default=str),
                    })
                tool_span.set_output(
                    tool_result
                    if isinstance(tool_result, str)
                    else json.dumps(tool_result, ensure_ascii=False, default=str)
                )
                tool_span.finish()
                continue

            if action == "record_info":
                info = step.get("info") or {}
                target = info.get("target") or {}
                raw_eid = target.get("elementId", "")
                element_id = (
                    raw_eid.strip()
                    if isinstance(raw_eid, str)
                    else str(raw_eid or "").strip()
                )
                raw_content = info.get("content", "")
                content = (
                    raw_content.strip()
                    if isinstance(raw_content, str)
                    else str(raw_content or "").strip()
                )
                if not element_id or not content:
                    info_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[ChainConfirmer] record_info 参数无效 (轮 {round_num})",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_RECORD_INFO",
                            "detail": "elementId 与 content 均须为非空",
                            "requirement": (
                                "record_info 须提供非空的 info.target.elementId 与非空的 info.content。"
                            ),
                        }, ensure_ascii=False),
                    })
                    continue

                kid = (knowledge_element_id or "").strip()
                if kid and element_id != kid:
                    info_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[ChainConfirmer] record_info elementId 不匹配 (轮 {round_num}) | "
                        f"got={element_id!r} expected={kid!r}",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_RECORD_INFO",
                            "detail": "elementId 与当前漏洞类型知识库节点不一致",
                            "requirement": (
                                f"record_info 的 info.target.elementId 须为该漏洞类型的全局经验知识库 "
                                f"（当前期望 elementId={kid}）。若经验不适用可跳过 record_info。"
                            ),
                        }, ensure_ascii=False),
                    })
                    continue
                record_span = start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=content,
                        tool_arguments={"analyzer_step": "record_info"},
                    )
                
                record_span.add_llm_tokens(input_tokens, output_tokens)
                record_span.finish()
                result = attach_audit_info_record(
                    target_element_id=element_id,
                    content=content,
                    branch_id="",
                    task_id=self._brain.task_id or "",
                )
                if result.get("ok"):
                    self._publish_log(
                        "INFO",
                        f"[ChainConfirmer] record_info 成功 (轮 {round_num}) | target={element_id}",
                    )
                    out_payload = {
                        "status": "AUDIT_INFO_RECORDED",
                        "audit_node_id": result.get("audit_node_id"),
                        "target_element_id": result.get("target_element_id"),
                    }
                    conversation.append({
                        "role": "user",
                        "content": json.dumps(out_payload, ensure_ascii=False),
                    })
                else:
                    self._publish_log(
                        "WARNING",
                        f"[ChainConfirmer] record_info 失败 (轮 {round_num}) | "
                        f"error={result.get('error', 'unknown')}",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_RECORD_INFO",
                            "detail": result.get("error", "unknown"),
                            "requirement": "record_info 须提供 info.target.elementId（图谱中已有节点）"
                            "与具体非空的 info.content；elementId 须与上下文中的节点一致。",
                        }, ensure_ascii=False),
                    })
                continue

            if action == "confirmation_result":
                result_preview = step.get("result", {})
                self._publish_log(
                    "INFO",
                    f"[ChainConfirmer] 输出确认结果 (轮 {round_num}) | "
                    f"status={result_preview.get('verification_status')}",
                )
                confirm_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.REVIEW,
                    reason=thought,
                    tool_arguments={"analyzer_step": "confirmation_result"},
                )
                confirm_span.add_llm_tokens(input_tokens, output_tokens)
                result = step.get("result", {})
                confirm_span.set_output(
                    json.dumps(
                        {"verification_status": result.get("verification_status")},
                        ensure_ascii=False,
                    )
                )
                confirm_span.finish()
                info_span.finish()
                return self._normalize_result(result, round_num)

            info_span.add_llm_tokens(input_tokens, output_tokens)
            self._publish_log(
                "WARNING",
                f"[ChainConfirmer] 无效 action={action!r} (轮 {round_num})",
            )
            conversation.append({"role": "assistant", "content": json.dumps(step, ensure_ascii=False)})
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "INVALID_ACTION",
                    "requirement": "action 只能是 tool_call 或 confirmation_result、record_info",
                }, ensure_ascii=False),
            })
            consecutive_invalid_action = self._bump_consecutive_invalid_action(
                conversation, consecutive_invalid_action
            )

        self._publish_log(
            "WARNING",
            f"[ChainConfirmer] 已达最大轮次 {self.max_rounds}，进入强制收口",
        )
        info_span.finish()
        return self._force_conclude(conversation)

    def _force_conclude(
        self,
        conversation: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """超过最大轮次时强制收口。"""
        self._publish_log("INFO", "[ChainConfirmer] 执行强制收口 LLM 调用")
        force_msg = chain_confirmer_force_conclude_prompt.format(
            max_rounds=self.max_rounds,
        )
        conversation.append({"role": "user", "content": force_msg})

        force_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.REVIEW,
            reason="max_rounds_force_conclude",
            tool_arguments={"analyzer_step": "force_conclude"},
        )
        step, input_tokens, output_tokens = self._llm_step(conversation)
        force_span.add_llm_tokens(input_tokens, output_tokens)
        if step and step.get("action") == "confirmation_result":
            result = step.get("result", {})
            self._publish_log(
                "INFO",
                f"[ChainConfirmer] 强制收口成功 | status={result.get('verification_status')}",
            )
            force_span.set_output(
                json.dumps(
                    {"verification_status": result.get("verification_status")},
                    ensure_ascii=False,
                )
            )
            force_span.finish()
            return self._normalize_result(result, self.max_rounds)

        self._publish_log(
            "WARNING",
            f"[ChainConfirmer] 强制收口未得到有效结果，默认 REJECTED | max_rounds={self.max_rounds}",
        )
        force_span.set_output(json.dumps({"outcome": "rejected_max_rounds"}, ensure_ascii=False))
        force_span.finish()
        return {
            "verification_status": "REJECTED",
            "verification_reason": f"二次校验超过最大轮次（{self.max_rounds}轮），无法给出明确结论。",
            "vulnerability_analysis_report": "",
            "poc": "",
            "level": "",
            "confirmation_rounds": self.max_rounds,
        }

    @staticmethod
    def _normalize_result(result: Dict[str, Any], round_num: int) -> Dict[str, Any]:
        """标准化确认结果，确保必要字段存在。"""
        valid_statuses = {"CONFIRMED", "REJECTED"}
        status = result.get("verification_status", "REJECTED")
        if status not in valid_statuses:
            status = "REJECTED"

        raw_level = result.get("level", "")
        level = raw_level.strip() if isinstance(raw_level, str) else ""

        return {
            "verification_status": status,
            "verification_reason": result.get("verification_reason", ""),
            "vulnerability_analysis_report": result.get("vulnerability_analysis_report", ""),
            "poc": result.get("poc", ""),
            "level": level,
            "confirmation_rounds": round_num,
        }
