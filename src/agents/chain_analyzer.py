# -*- coding: utf-8 -*-
"""
ChainAnalyzer Agent —— 链路分析阶段核心 Agent。

设计要点：通用分叉 + 上下文隔离

fork 的每条分支与 insert_node 使用完全相同的节点结构（type / file / line / function
/ description），任何类型的发现都可以触发分叉：
  - 多个 caller（多个调用者）
  - 多条 data_flow（数据通过不同中间函数流向 sink）
  - 多个 param_source（不同参数来源）
  - 多个 entry_point（不同类型的系统入口）
  - 多个 guard（不同分支上的安全边界不同）

图结构示意（通用分叉）：

  SinkFlowNode (leaf)
    ├─[:TRACE]→ ChainNode (data_flow: formatA) [branch=br_1]
    │              └─[:TRACE]→ ChainNode (entry: POST /upload) [branch=br_1]
    │                             └─[:HAS_RESULT]→ AnalysisResult
    └─[:TRACE]→ ChainNode (data_flow: formatB) [branch=br_2]
                   └─[:TRACE]→ ChainNode (guard: whitelist) [branch=br_2]
                                  └─[:HAS_RESULT]→ AnalysisResult
"""
import json
import logging
import os
import traceback
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ActionType
from src.core.event_span import start_event_span
from src.agents.base import BaseAgent
from src.core.task_control import ensure_task_running
from src.agents.brain import Brain
from src.agents.chain_confirmer import ChainConfirmer
from src.core.task_control import TaskPausedError
from src.llm import LLMError
from src.services.context_compressor import ContextCompressor
from src.agents.prompt.chain_analyzer import (
    chain_analyzer_system_prompt,
    chain_analyzer_force_conclude_prompt, chain_node_prompt,
)
from src.services.chain_analysis_service import (
    attach_audit_info_record,
    create_chain_node,
    find_chain_node_by_file_function_and_category,
    fetch_completed_analysis_result_downstream_of_chain_node,
    merge_existing_chain_node,
    fetch_analysis_result_as_resolution_dict,
    fetch_audit_info_contents_by_element_ids,
    fetch_flow_chain_nodes_for_analysis_result,
    fetch_node_lines_by_element_ids,
    link_trace,
    mark_analysis_branch_completed,
    persist_analysis_result,
    update_node_status_by_element_ids,
)
from src.tools import ReadLinesTool
from src.utils.ids import generate_id
from src.knowledge import build_audit_system_prompt
from src.knowledge.audit_skills import AUDIT_WORKFLOW, QUALITY_STANDARDS, COMBINED_VULN_PATTERNS, LINE_VERIFICATION_FLOW
from src.knowledge.security_domains import SECURITY_DOMAINS, UNIVERSAL_SECURITY_HINTS
from src.knowledge.detection_patterns import SECURITY_CHECKLIST, get_evidence_template
from src.knowledge.gbt_standards import GBT_EVIDENCE_REQUIREMENTS

logger = logging.getLogger(__name__)


class _TraceTail:
    """记录当前 TRACE 链路的尾节点，保证 insert_node 连接到正确位置。"""

    __slots__ = ("node_id", "is_sink_flow")

    def __init__(self, node_id: str, is_sink_flow: bool):
        self.node_id = node_id
        self.is_sink_flow = is_sink_flow


class ChainAnalyzer(BaseAgent):
    """
    链路分析 Agent。

    对每条 Chain Path 执行多轮 LLM 分析，支持在任何节点类型上分叉为
    多条独立分支，每条分支拥有隔离的对话上下文和 ChainNode 序列。
    """
    MODULE_NAME = "chain_analyzer"
    DEFAULT_MAX_ROUNDS = 35
    VERDICTS_NEED_CONFIRMATION = {"LIKELY_VULNERABLE"}
    VALID_FINAL_VERDICTS = frozenset({
        "LIKELY_VULNERABLE",
        "SAFE",
    })
    VALID_FINAL_CONFIDENCE = frozenset({"HIGH", "MEDIUM", "LOW"})

    @staticmethod
    def _coerce_mislabeled_protocol_step(step: Dict[str, Any]) -> Dict[str, Any]:
        """
        将误写的 tool_call + tool_name(fork|...) 规范为顶层 action。

        部分模型会把分叉写成 OpenAI 风格 function call，导致 run_tool('fork') 等无效调用。
        """
        if not isinstance(step, dict) or step.get("action") != "tool_call":
            return step
        tn = str(step.get("tool_name") or "").strip()
        if tn not in ("fork", "insert_node", "record_info", "final_resolution"):
            return step
        args = step.get("arguments")
        if not isinstance(args, dict):
            args = {}
        thought = step.get("thought", "")
        if not isinstance(thought, str):
            thought = str(thought) if thought is not None else ""

        if tn == "fork":
            branches = args.get("branches")
            if isinstance(branches, list):
                out: Dict[str, Any] = {"action": "fork", "branches": branches}
                if thought:
                    out["thought"] = thought
                return out
        if tn == "insert_node":
            node = args.get("node")
            if isinstance(node, dict):
                out = {"action": "insert_node", "node": node}
                if thought:
                    out["thought"] = thought
                return out
        if tn == "record_info":
            info = args.get("info")
            if isinstance(info, dict):
                return {"action": "record_info", "info": info}
        if tn == "final_resolution":
            res = args.get("resolution")
            if isinstance(res, dict):
                out = {"action": "final_resolution", "resolution": res}
                if thought:
                    out["thought"] = thought
                return out
        return step

    @staticmethod
    def _remap_neo4j_file_path(file_path: str, project_path: str) -> str:
        """
        重映射 Neo4j 节点中可能存储的临时目录绝对路径。

        当项目通过 ``source_type=upload|git`` 创建时，源码会被复制到临时目录
        ``{TMP_BASE}/project/{uuid}/``，该路径可能被写入 Neo4j。实际部署/二次扫描
        时临时目录可能已被清理，需要将路径重映射到当前项目根 ``project_path``。

        返回重映射后的路径；非临时路径原样返回。
        """
        if not file_path or not os.path.isabs(file_path):
            return file_path

        from src.tmp_dir import get_tmp_base
        tmp_base = str(get_tmp_base()).replace("\\", "/")
        project_prefix = f"{tmp_base}/project/"
        norm_path = file_path.replace("\\", "/")

        if not norm_path.startswith(project_prefix):
            return file_path

        # norm_path = {tmp_base}/project/{uuid}/rel/path/file.java
        # rest      = {uuid}/rel/path/file.java
        rest = norm_path[len(project_prefix):]
        first_slash = rest.find("/")
        if first_slash == -1:
            return file_path  # 只有 {uuid}，没有相对路径，无法映射
        rel_path = rest[first_slash + 1:]  # rel/path/file.java

        actual_root = str(project_path).replace("\\", "/")
        return os.path.normpath(f"{actual_root}/{rel_path}")

    def __init__(self, brain: Optional[Brain] = None, max_rounds: int = DEFAULT_MAX_ROUNDS):
        super().__init__(brain=brain)
        self.max_rounds = max_rounds
        self._confirmer = ChainConfirmer(brain=brain)
        # 上下文压缩器：防止多轮对话（max 70 轮）token 溢出
        self._context_compressor: Optional[ContextCompressor] = None

    def _init_compressor(self) -> None:
        """懒初始化上下文压缩器（需要 brain 已设置）。"""
        if self._context_compressor is not None:
            return
        if self._brain is None or self._brain.llm is None:
            return

        def _ask_wrapper(messages: List[Dict[str, str]]):
            """将 brain.ask 的 (result, in_tok, out_tok) 适配为压缩器的签名。"""
            result, in_tok, out_tok = self._brain.ask(messages)
            content = result.get("content", "") if isinstance(result, dict) else str(result)
            return content, in_tok, out_tok

        self._context_compressor = ContextCompressor(
            ask_fn=_ask_wrapper,
            max_history_tokens=8000,
        )

    def _maybe_compress(
        self,
        conversation: List[Dict[str, str]],
    ) -> List[Dict[str, str]]:
        """在每轮 LLM 调用后检查是否需要压缩对话历史。

        压缩策略：
        - 消息数 ≤ 12 时不压缩（对话还在构建阶段）
        - 估算 token 超过 8000 时触发压缩
        - 压缩保留 system 消息 + 结构化摘要 + 最近 4 条消息
        """
        if self._context_compressor is None:
            self._init_compressor()
        if self._context_compressor is None:
            return conversation  # 脱机模式或无 LLM，跳过压缩

        # 消息太少时不压缩
        non_system = [m for m in conversation if m.get("role") != "system"]
        if len(non_system) <= 12:
            return conversation

        if not self._context_compressor.should_compress(conversation):
            return conversation

        system_msg = conversation[0] if conversation and conversation[0].get("role") == "system" else None
        try:
            compressed = self._context_compressor.apply_compression(conversation, system_msg)
            self._publish_log(
                "INFO",
                f"[ChainAnalyzer] 上下文压缩完成: {len(conversation)} 条消息 → {len(compressed)} 条",
            )
            return compressed
        except Exception as e:
            self._publish_log(
                "WARNING",
                f"[ChainAnalyzer] 上下文压缩失败，继续使用原始对话: {e!r}",
            )
            return conversation

    # ==================================================================
    # 公共入口
    # ==================================================================

    def run(
        self,
        chain: Dict[str, Any],
        vul_description: str,
        category_name: str,
        knowledge_element_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        分析一条 Chain Path，返回所有分支的 AnalysisResult 列表。

        Returns:
            所有分支的 resolution dict 列表。无分叉时列表长度为 1。
        """
        if not isinstance(chain, dict):
            msg = f"[ChainAnalyzer] chain 入参须为 dict，实际为 {type(chain).__name__}"
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return []

        leaf_raw = chain.get("leaf_sink_node_id")
        leaf_id = str(leaf_raw).strip() if leaf_raw is not None else ""
        sink_nodes_raw = chain.get("sink_nodes")
        if not isinstance(sink_nodes_raw, list):
            msg = (
                f"[ChainAnalyzer] 链路入参缺少 sink_nodes 或非 list | keys={list(chain.keys())}"
            )
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return []

        sink_nodes: List[Dict[str, Any]] = [n for n in sink_nodes_raw if isinstance(n, dict)]
        if len(sink_nodes) != len(sink_nodes_raw):
            msg = "[ChainAnalyzer] sink_nodes 中含非 dict 项，已忽略"
            logger.warning(msg)
            self._publish_log("WARNING", msg)

        if not leaf_id:
            msg = (
                f"[ChainAnalyzer] 链路入参缺少或空的 leaf_sink_node_id | keys={list(chain.keys())}"
            )
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return []

        if not sink_nodes:
            msg = (
                f"[ChainAnalyzer] sink_nodes 为空或无可用的 dict 项，无法分析 | "
                f"leaf_sink_node_id={leaf_id!r}"
            )
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return []

        trace_tail = _TraceTail(node_id=leaf_id, is_sink_flow=True)
        self._publish_log(
            "INFO",
            f"[ChainAnalyzer] 开始链路分析 | category={category_name} "
            f"leaf_sink_node_id={leaf_id} sink_nodes={len(sink_nodes)}",
        )

        branch_node = sink_nodes[-1]
        branch_conversation = self._build_branch_context(
            sink_nodes=sink_nodes,
            category_name=category_name,
            risk_description=vul_description,
            branch_node=branch_node,
            knowledge_element_id=knowledge_element_id,
        )

        results = self._run_analysis_loop(
            conversation=branch_conversation,
            trace_tail=trace_tail,
            sink_nodes=sink_nodes,
            category_name=category_name,
            risk_description=vul_description,
            knowledge_element_id=knowledge_element_id,
        )

        return results

    def resume_secondary_confirmation_for_stored_result(
        self,
        ar_node_id: str,
        category_name: str,
        risk_description: str,
        knowledge_element_id: Optional[str] = None,
    ) -> None:
        """
        对图上已存在、尚未 completed 的 AnalysisResult 补跑与 ChainConfirmer.maybe_confirm_resolution
        相同的二次校验逻辑，并随后将本分支 FLOW 链与 AR 标为 completed（与结案路径一致）。
        """
        aid = str(ar_node_id).strip() if ar_node_id else ""
        if not aid:
            return
        resolution = fetch_analysis_result_as_resolution_dict(aid)
        if not resolution:
            msg = f"[ChainAnalyzer] 无法补跑二次校验：未找到 AnalysisResult elementId={aid!r}"
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return
        logger.info("[ChainAnalyzer] 补跑二次校验（存量 AR）| ar_node_id=%r", aid)
        self._publish_log(
            "INFO",
            f"[ChainAnalyzer] 补跑二次校验（存量 AR）| ar_node_id={aid} category={category_name}",
        )
        try:
            self._confirmer.maybe_confirm_resolution(
                resolution=resolution,
                category_name=category_name,
                risk_description=risk_description,
                knowledge_element_id=knowledge_element_id,
                fetch_sink_chain_context=self._sink_chain_context_from_ar,
            )
        except TaskPausedError:
            logger.info("[ChainAnalyzer] 任务已暂停/取消，跳过结案 ar_node_id=%r", aid)
            raise
        mark_analysis_branch_completed(aid, publish_log=self._publish_log)

    def _after_final_resolution_persisted(
        self,
        resolution: Dict[str, Any],
        category_name: str,
        risk_description: str,
        knowledge_element_id: Optional[str] = None,
    ) -> None:
        """
        持久化 AnalysisResult 之后：按需二次校验，再将本分支 FLOW 链 A→z 与 AR 标为 completed。
        同时把最终判定镜像到 PostgreSQL 的 findings 表（由事件总线落库）。
        """
        verdict = resolution.get("verdict", "SAFE")
        if verdict != "SAFE":
            try:
                self._confirmer.maybe_confirm_resolution(
                    resolution=resolution,
                    category_name=category_name,
                    risk_description=risk_description,
                    knowledge_element_id=knowledge_element_id,
                    fetch_sink_chain_context=self._sink_chain_context_from_ar,
                )
            except (TaskPausedError, LLMError):
                # 暂停/取消，或 LLM 致命错误（额度/鉴权等）：不可吞掉，向上传播。
                raise
            except Exception as e:
                logger.exception(
                    "[ChainAnalyzer] 二次校验流程未完整执行（已吞异常避免阻断结案）: %s",
                    e,
                )
                tb = traceback.format_exc()
                tail = tb[-4000:] if len(tb) > 4000 else tb
                self._publish_log(
                    "ERROR",
                    f"[ChainAnalyzer] 二次校验流程未完整执行（已吞异常避免阻断结案）: {e!r}\n{tail}",
                )
        ar_id = resolution.get("_ar_node_id", "") or ""
        if ar_id and verdict == "SAFE":
            mark_analysis_branch_completed(ar_id, publish_log=self._publish_log)
        elif ar_id and resolution.get("verification_status") in {"CONFIRMED", "REJECTED"}:
            mark_analysis_branch_completed(ar_id, publish_log=self._publish_log)

    def _sink_chain_context_from_ar(
        self,
        ar_node_id: str,
        knowledge_element_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        根据 AnalysisResult 的 Neo4j elementId（``_ar_node_id``）从 Neo4j 拉取 (SinkFlowNode|ChainNode)-[:FLOW]*→z→HAS_RESULT→ar
        上的节点序列，并格式化为与 _format_sink_chain 相同的上下文文本。

        Knowledge 的 elementId 由编排入口传入，不在此从图上反查 RiskCategory。
        """
        nodes = fetch_flow_chain_nodes_for_analysis_result(ar_node_id)
        if not nodes:
            return (
                "(未能从 Neo4j 根据 AnalysisResult 反查 FLOW 链；请确认存在 "
                "(SinkFlowNode|ChainNode)-[:HAS_RESULT]->(:AnalysisResult) 且 elementId(ar) 与 _ar_node_id 一致)",
                "",
            )
        return self._format_sink_chain(nodes, knowledge_element_id=knowledge_element_id)

    def _final_resolution_validation_error(self, resolution: Any) -> Optional[str]:
        """
        校验 final_resolution 中 verdict 及与 verdict 绑定的字段是否一致。
        返回 None 表示通过；否则返回供 LLM 修正的中文说明。
        """
        if not isinstance(resolution, dict):
            return "final_resolution 的 resolution 必须是 JSON 对象。"

        verdict_raw = resolution.get("verdict")
        if not isinstance(verdict_raw, str) or not verdict_raw.strip():
            return (
                "resolution.verdict 必填，且只能是以下之一（区分大小写、无多余空格）："
                "LIKELY_VULNERABLE、SAFE。"
            )
        verdict = verdict_raw.strip()
        if verdict not in self.VALID_FINAL_VERDICTS:
            return (
                f"resolution.verdict 当前为 {verdict_raw!r}，取值非法。"
                "请改为：LIKELY_VULNERABLE、SAFE 之一（不存在疑似/待定中间态）。"
            )

        conf_raw = resolution.get("confidence")
        if not isinstance(conf_raw, str) or conf_raw.strip() not in self.VALID_FINAL_CONFIDENCE:
            return "resolution.confidence 须为 HIGH、MEDIUM、LOW 之一（区分大小写）。"

        vul_name = resolution.get("vul_name")
        vul_name_s = vul_name.strip() if isinstance(vul_name, str) else ""
        detail = resolution.get("detail")
        summary = resolution.get("summary")
        detail_s = ""
        for part in (detail, summary):
            if isinstance(part, str) and part.strip():
                detail_s = part.strip()
                break

        if verdict in self.VERDICTS_NEED_CONFIRMATION:
            if not vul_name_s:
                return (
                    "当 verdict 为 LIKELY_VULNERABLE 时，"
                    "vul_name 不得为空，须根据审计概括漏洞名称。"
                )
            if not detail_s:
                return (
                    "当 verdict 为 LIKELY_VULNERABLE 时，"
                    "detail 不得为空，须描述从 Entry 到 Sink 的路径、防御缺失与利用要点。"
                )
        else:
            if vul_name_s:
                return (
                    "当 verdict 为 SAFE 时，vul_name 必须为空字符串，"
                    "请去掉漏洞名称或调整 verdict 与结论一致。"
                )

        return None

    def _normalize_final_resolution_payload(self, resolution: Dict[str, Any]) -> Dict[str, Any]:
        """
        校验通过后：浅拷贝并补全与系统 prompt「选项 E」一致的字段形态，
        便于 persist / PostgreSQL 与主循环非强制路径行为一致。
        """
        out = dict(resolution)
        verdict = out.get("verdict", "")
        out["verdict"] = verdict.strip() if isinstance(verdict, str) else "SAFE"
        conf = out.get("confidence", "")
        out["confidence"] = conf.strip() if isinstance(conf, str) else "LOW"
        vn = out.get("vul_name")
        out["vul_name"] = vn.strip() if isinstance(vn, str) else ""

        detail = out.get("detail")
        summary = out.get("summary")
        d = detail.strip() if isinstance(detail, str) else ""
        if d:
            out["detail"] = d
        elif isinstance(summary, str) and summary.strip():
            out["detail"] = summary.strip()
        else:
            out["detail"] = ""

        def _coerce_list(name: str) -> None:
            val = out.get(name)
            if val is None:
                out[name] = []
                return
            if isinstance(val, list):
                out[name] = val
                return
            if name == "findings" and isinstance(val, dict):
                out[name] = [val]
                return
            if name in ("entry_points", "security_boundaries") and isinstance(val, str) and val.strip():
                out[name] = [val.strip()]
                return
            out[name] = []

        _coerce_list("entry_points")
        _coerce_list("findings")
        _coerce_list("security_boundaries")
        return out

    # ==================================================================
    # 主分析循环（可重入：主分析和分支分析共用）
    # ==================================================================

    def _run_analysis_loop(
        self,
        conversation: List[Dict[str, str]],
        trace_tail: _TraceTail,
        sink_nodes: List[Dict[str, Any]],
        category_name: str,
        risk_description: str,
        branch_id: str = "",
        knowledge_element_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        执行多轮 LLM 分析循环。

        返回值是 resolution 列表：
        - 无分叉：[resolution]
        - fork：[branch_1_resolution, branch_2_resolution, ...]
        """
        inserted_chain_nodes: List[Dict[str, Any]] = []
        all_results: List[Dict[str, Any]] = []
        consecutive_invalid_action = 0
        consecutive_tool_only = 0
        consecutive_no_discovery = 0
        max_tool_only = 8  # 从 12 降到 8，尽早退出无进展探测
        info_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.INFORMATION,
            reason=f"开始链路分析循环 | branch_id={branch_id or '(root)'} | category={category_name}",
        )
        self._publish_log(
            "INFO",
            f"[ChainAnalyzer] 开始分析循环 | branch_id={branch_id or '(root)'} "
            f"trace_tail={trace_tail.node_id} max_rounds={self.max_rounds}",
        )

        for round_num in range(1, self.max_rounds + 1):
            ensure_task_running(self._brain.task_id)
            self._publish_log(
                "INFO",
                f"[ChainAnalyzer] LLM 轮次 {round_num}/{self.max_rounds} | branch_id={branch_id or '(root)'}",
            )
            step, input_tokens, output_tokens = self._llm_step(conversation)
            if step is None:
                self._publish_log(
                    "WARNING",
                    f"[ChainAnalyzer] LLM 返回为空，重试 ({round_num}/{self.max_rounds})",
                )
                continue
            coerced = self._coerce_mislabeled_protocol_step(step)
            if coerced is not step:
                step = coerced
                if conversation and conversation[-1].get("role") == "assistant":
                    conversation[-1]["content"] = json.dumps(
                        step, ensure_ascii=False, default=str
                    )
            action = step.get("action", "")
            thought = step.get("thought", "")
            if action in (
                "tool_call",
                "fork",
                "insert_node",
                "record_info",
                "final_resolution",
                "neo4j_update_node",
            ):
                consecutive_invalid_action = 0

            if action in ("fork", "insert_node", "record_info", "final_resolution"):
                consecutive_tool_only = 0

            # --- tool_call ---
            if action == "tool_call":
                tool_name = step.get("tool_name", "") or ""
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] 调用工具 {tool_name!r} (轮 {round_num}) | branch_id={branch_id or '(root)'}",
                )
                arguments = step.get("arguments", {})
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
                        f"[ChainAnalyzer] 工具 {tool_name!r} 未返回结果 (轮 {round_num})",
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

                # 连续 tool_only 达到阈值 → 提前强制收口
                consecutive_tool_only += 1
                if consecutive_tool_only >= max_tool_only:
                    self._publish_log(
                        "WARNING",
                        f"[ChainAnalyzer] 连续 {consecutive_tool_only} 轮仅调用工具无进展，"
                        f"提前进入强制收口 (轮 {round_num})",
                    )
                    info_span.finish()
                    resolution = self._force_conclude(
                        conversation=conversation,
                        trace_tail=trace_tail,
                        branch_id=branch_id,
                        inserted_chain_nodes=inserted_chain_nodes,
                        category_name=category_name,
                        risk_description=risk_description,
                        knowledge_element_id=knowledge_element_id,
                    )
                    all_results.append(resolution)
                    self._report_cache_stats(self._brain.task_id)
                    return all_results
                continue
            logger.debug("[ChainAnalyzer] step=%s", json.dumps(step, ensure_ascii=False))

            # --- neo4j_update_node (LLM 误将工具名写为 action，统一为 tool_call) ---
            if action == "neo4j_update_node":
                step["tool_name"] = "neo4j_update_node"
                step["arguments"] = {"node_spec": step.get("node_spec", {}), "updates": step.get("updates", {})}
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] 处理 neo4j_update_node (重映射为 tool_call) | branch_id={branch_id or '(root)'}",
                )
                tool_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.TOOL_CALL,
                    tool_name="neo4j_update_node",
                    reason=thought,
                    tool_arguments=step["arguments"],
                )
                tool_span.add_llm_tokens(input_tokens, output_tokens)
                tool_result = self._execute_tool_call(step, conversation, tool_span)
                if tool_result is not None:
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "TOOL_RESULT",
                            "tool_name": "neo4j_update_node",
                            "result": tool_result,
                        }, ensure_ascii=False, default=str),
                    })
                else:
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "TOOL_RESULT_NONE",
                            "tool_name": "neo4j_update_node",
                            "result": "neo4j_update_node 工具调用未返回结果",
                        }, ensure_ascii=False, default=str),
                    })
                tool_span.set_output(
                    tool_result if isinstance(tool_result, str) else json.dumps(tool_result, ensure_ascii=False, default=str)
                )
                tool_span.finish()
                consecutive_tool_only += 1
                continue

            # --- fork ---
            if action == "fork":
                branches_data = step.get("branches", [])
                if not branches_data or len(branches_data) < 2:
                    info_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[ChainAnalyzer] fork 分支数不足 (轮 {round_num}) | count={len(branches_data)}",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_FORK",
                            "requirement": "fork 需要至少 2 条分支。如果只有 1 条路径，请使用 insert_node。",
                        }, ensure_ascii=False),
                    })
                    continue

                fork_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.CHAIN_ANALYSIS,
                    reason=thought,
                    tool_arguments={"analyzer_step": "fork"},
                )
                fork_span.add_llm_tokens(input_tokens, output_tokens)
                fork_span.set_output(
                    json.dumps(
                        {"status": "fork", "branch_count": len(branches_data)},
                        ensure_ascii=False,
                    )
                )
                fork_span.finish()
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] fork {len(branches_data)} 条分支 (轮 {round_num})",
                )
                fork_results = self._handle_fork(
                    branches_data=branches_data,
                    fork_point_tail=trace_tail,
                    sink_nodes=sink_nodes,
                    category_name=category_name,
                    risk_description=risk_description,
                    knowledge_element_id=knowledge_element_id,
                )
                all_results.extend(fork_results)
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] fork 完成 | results={len(fork_results)}",
                )
                info_span.finish()
                self._report_cache_stats(self._brain.task_id)
                return all_results

            # --- insert_node ---
            if action == "insert_node":
                node_spec = step.get("node", {})
                if node_spec == {}:
                    info_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[ChainAnalyzer] insert_node 缺少 node 规格 (轮 {round_num})",
                    )
                    conversation.append({"role": "assistant", "content": json.dumps(step, ensure_ascii=False)})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_insert_node",
                            "requirement": "node不能为空",
                        }, ensure_ascii=False),
                    })
                    continue

                insert_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.CHAIN_ANALYSIS,
                    reason=thought,
                    tool_arguments={"analyzer_step": "insert_node"},
                )
                insert_span.add_llm_tokens(input_tokens, output_tokens)
                branches_data = [node_spec]
                insert_span.set_output(
                    json.dumps({"status": "insert_node"}, ensure_ascii=False)
                )
                insert_span.finish()
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] insert_node (轮 {round_num}) | "
                    f"file={node_spec.get('file')} line={node_spec.get('line')}",
                )
                fork_results = self._handle_fork(
                    branches_data=branches_data,
                    fork_point_tail=trace_tail,
                    sink_nodes=sink_nodes,
                    category_name=category_name,
                    risk_description=risk_description,
                    knowledge_element_id=knowledge_element_id,
                )
                all_results.extend(fork_results)
                info_span.finish()
                self._report_cache_stats(self._brain.task_id)
                return all_results

            # --- record_info ---
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
                        f"[ChainAnalyzer] record_info 参数无效 (轮 {round_num})",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_RECORD_INFO",
                            "detail": "elementId 与 content 均须为非空",
                            "requirement": (
                                "record_info 须提供非空的 info.target.elementId（图谱中已有节点）"
                                "与非空的 info.content。"
                            ),
                        }, ensure_ascii=False),
                    })
                    continue

                result = attach_audit_info_record(
                    target_element_id=element_id,
                    content=content,
                    branch_id=branch_id,
                    task_id=self._brain.task_id or "",
                )
                record_span = start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=content,
                        tool_arguments={"analyzer_step": "record_info"},
                    )
                record_span.add_llm_tokens(input_tokens, output_tokens)
                record_span.finish()
                if result.get("ok"):
                    self._publish_log(
                        "INFO",
                        f"[ChainAnalyzer] record_info 成功 (轮 {round_num}) | "
                        f"branch_id={branch_id} target={element_id}",
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
                        f"[ChainAnalyzer] record_info 失败 (轮 {round_num}) | "
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

            # --- final_resolution ---
            if action == "final_resolution":
                raw_resolution = step.get("resolution", {})
                verdict_err = self._final_resolution_validation_error(raw_resolution)
                if verdict_err:
                    info_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[ChainAnalyzer] final_resolution 校验失败 (轮 {round_num}) | {verdict_err[:200]}",
                    )
                    conversation.append({"role": "assistant", "content": json.dumps(step, ensure_ascii=False)})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_FINAL_RESOLUTION",
                            "detail": verdict_err,
                            "requirement": (
                                "请根据上述说明修正 resolution（verdict、confidence、vul_name、detail 等），"
                                "重新输出一条 action 为 final_resolution 的 JSON，其它 action 在此场景下不允许。"
                            ),
                        }, ensure_ascii=False),
                    })
                    continue

                resolution_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.CHAIN_ANALYSIS,
                    reason=thought,
                    tool_arguments={"analyzer_step": "final_resolution"},
                )
                resolution_span.add_llm_tokens(input_tokens, output_tokens)
                resolution = self._normalize_final_resolution_payload(raw_resolution)
                resolution["analysis_rounds"] = round_num

                ar_node_id, vulnerability_id = persist_analysis_result(
                    self._brain.task_id,
                    self._brain.project_id,
                    attach_to_node_id=trace_tail.node_id,
                    attach_is_sink_flow=trace_tail.is_sink_flow,
                    resolution=resolution,
                    branch_id=branch_id,
                    category_name=category_name,
                    project_root=str(self._brain.project_path or ""),
                )
                find_vul_name = resolution.get("vul_name", "")
                confidence = resolution.get("confidence", "")
                verdict = resolution.get("verdict", "SAFE")
                detail = resolution.get("detail", "")
                if str(verdict).strip().upper() == "SAFE":
                    msg = f'[链路安全] {detail}'
                else:
                    msg = f'[待校验]发现初步结果：{find_vul_name}\n 置信度：{confidence}'
                resolution_span.set_output(msg)
                resolution_span.finish()
                vul_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.VULNERABILITY,
                    reason=msg,
                    tool_arguments={"vul_neo4j_ele_id": ar_node_id},
                )
                vul_span.finish()
                resolution["_ar_node_id"] = ar_node_id
                resolution["_vulnerability_id"] = vulnerability_id
                self._publish_log(
                    "INFO",
                    f"[ChainAnalyzer] 结案 (轮 {round_num}) | verdict={verdict} "
                    f"vul_name={find_vul_name} branch_id={branch_id} ar_node_id={ar_node_id}",
                )
                self._after_final_resolution_persisted(
                    resolution=resolution,
                    category_name=category_name,
                    risk_description=risk_description,
                    knowledge_element_id=knowledge_element_id,
                )
                all_results.append(resolution)
                info_span.finish()
                self._report_cache_stats(self._brain.task_id)
                return all_results

            # unknown action
            info_span.add_llm_tokens(input_tokens, output_tokens)
            self._publish_log(
                "WARNING",
                f"[ChainAnalyzer] 无效 action={action!r} (轮 {round_num}) {json.dumps(step, ensure_ascii=False)[:200]}",
            )
            conversation.append({"role": "assistant", "content": json.dumps(step, ensure_ascii=False)[0:50]})
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "INVALID_ACTION",
                    "requirement": "action 只能是 tool_call / fork / insert_node / record_info / final_resolution",
                }, ensure_ascii=False),
            })
            consecutive_invalid_action = self._bump_consecutive_invalid_action(
                conversation, consecutive_invalid_action
            )

            # 每轮结束后压缩上下文（防止 70 轮对话 token 溢出）
            conversation = self._maybe_compress(conversation)

        # 超过最大轮次 → 强制收口
        self._publish_log(
            "WARNING",
            f"[ChainAnalyzer] 已达最大轮次 {self.max_rounds}，进入强制收口 | branch_id={branch_id or '(root)'}",
        )
        info_span.finish()
        self._report_cache_stats(self._brain.task_id)
        resolution = self._force_conclude(
            conversation=conversation,
            trace_tail=trace_tail,
            branch_id=branch_id,
            inserted_chain_nodes=inserted_chain_nodes,
            category_name=category_name,
            risk_description=risk_description,
            knowledge_element_id=knowledge_element_id,
        )
        all_results.append(resolution)
        return all_results

    def _handle_fork(
        self,
        branches_data: List[Dict[str, Any]],
        fork_point_tail: _TraceTail,
        sink_nodes: List[Dict[str, Any]],
        category_name: str,
        risk_description: str,
        knowledge_element_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        处理 fork：为每条分支创建独立的上下文并执行分析。

        branches_data 中每条分支的格式与 insert_node 的 node 字段完全一致：
        {type, file, line, function, description}

        关键设计：
        1. 每条分支拥有全新的对话上下文（不继承主分析的工具调用历史）
        2. 分支的第一个 ChainNode 连接到 fork_point_tail
        3. 分支内后续 ChainNode 线性串联到自己的 trace_tail
        4. 各分支的 max_rounds 独立计算
        5. 先一次性将所有分叉首节点写入 Neo4j 并接好 TRACE，再逐分支跑分析循环
           （保证图上分叉结构先完整；每条分支使用 sink_nodes 的独立副本 + 本分支首节点，
           禁止在共享入参上 append，避免分支间上下文污染）
        """
        all_branch_results: List[Dict[str, Any]] = []
        branch_plans: List[Dict[str, Any]] = []
        self._publish_log(
            "INFO",
            f"[ChainAnalyzer] 处理分叉 | branches={len(branches_data)} "
            f"fork_point={fork_point_tail.node_id} category={category_name}",
        )

        for i, branch_node in enumerate(branches_data):
            branch_id = generate_id("br")
            node_type = branch_node.get("type", "data_flow")
            file_val = branch_node.get("file", "")
            _raw_line = branch_node.get("line")
            if _raw_line is None:
                line_val = 0
            else:
                try:
                    line_val = int(_raw_line)
                except (TypeError, ValueError):
                    line_val = 0
            func_val = branch_node.get("function", "")
            reason_val = branch_node.get("reason", "")

            task_id = self._brain.task_id or ""
            existing_cn = find_chain_node_by_file_function_and_category(
                file=file_val,
                function=func_val,
                category_name=category_name,
                task_id=task_id,
            )
            skip_analysis = False
            reused_ar_element_id: Optional[str] = None

            if existing_cn:
                existing_node_id = str(existing_cn.get("node_id") or "").strip()
                _info_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=(
                        f"复用已有节点 | branch_id={branch_id} | node_id={existing_node_id} | "
                        f"type={node_type} | {func_val}({file_val}:{line_val}) | {reason_val}"
                    ),
                )
                _info_span.finish()
                cn_row = merge_existing_chain_node(
                    existing_node_id,
                    new_line=line_val,
                    new_reason=reason_val,
                    task_id=task_id,
                ) or existing_cn
                reused_ar_element_id = fetch_completed_analysis_result_downstream_of_chain_node(
                    existing_node_id,
                    task_id=task_id,
                )
                if reused_ar_element_id:
                    skip_analysis = True
            else:
                _info_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=(
                        f"发现新节点 | branch_id={branch_id} | type={node_type} | "
                        f"{func_val}({file_val}:{line_val}) | {reason_val}"
                    ),
                )
                _info_span.finish()
                cn_row = create_chain_node(
                    node_type=node_type,
                    branch_id=branch_id,
                    file=file_val,
                    line=line_val,
                    function=func_val,
                    reason=reason_val,
                    task_id=task_id,
                )
            first_node_id = cn_row["node_id"]
            link_trace(
                source_id=fork_point_tail.node_id,
                target_node_id=first_node_id,
                source_is_sink_flow=fork_point_tail.is_sink_flow,
                task_id=self._brain.task_id or "",
            )

            if cn_row.get("elementId") is not None:
                branch_node["elementId"] = cn_row.get("elementId")
            branch_node["labels"] = cn_row.get("labels") or []

            branch_plans.append(
                {
                    "branch_id": branch_id,
                    "branch_node": branch_node,
                    "branch_tail": _TraceTail(
                        node_id=first_node_id, is_sink_flow=False
                    ),
                    "skip_analysis": skip_analysis,
                    "reused_ar_element_id": reused_ar_element_id,
                }
            )

        for i, plan in enumerate(branch_plans):
            branch_id = plan["branch_id"]
            branch_node = plan["branch_node"]
            branch_tail = plan["branch_tail"]
            if plan.get("skip_analysis") and plan.get("reused_ar_element_id"):
                ar_eid = str(plan["reused_ar_element_id"]).strip()
                _info_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=(
                        f"跳过已分析分支 | branch_id={branch_id} | "
                        f"复用 AR elementId={ar_eid} | node_id={branch_tail.node_id}"
                    ),
                )
                _info_span.finish()
                complete_eids: List[str] = []
                seen_eids: set = set()
                for node in sink_nodes:
                    raw_eid = node.get("elementId")
                    if raw_eid in (None, ""):
                        continue
                    eid = str(raw_eid).strip()
                    if eid and eid not in seen_eids:
                        seen_eids.add(eid)
                        complete_eids.append(eid)
                branch_eid_raw = branch_node.get("elementId")
                if branch_eid_raw not in (None, ""):
                    branch_eid = str(branch_eid_raw).strip()
                    if branch_eid and branch_eid not in seen_eids:
                        seen_eids.add(branch_eid)
                        complete_eids.append(branch_eid)
                if complete_eids:
                    update_node_status_by_element_ids(complete_eids, "completed")
                resolution = fetch_analysis_result_as_resolution_dict(ar_eid)
                if resolution:
                    resolution["reused_analysis"] = True
                    resolution["branch_id"] = branch_id
                    resolution["branch_node"] = branch_node
                    all_branch_results.append(resolution)
                    continue

            branch_sink_nodes = list(sink_nodes)
            branch_sink_nodes.append(branch_node)
            branch_conversation = self._build_branch_context(
                sink_nodes=branch_sink_nodes,
                category_name=category_name,
                risk_description=risk_description,
                branch_node=branch_node,
                knowledge_element_id=knowledge_element_id,
            )

            branch_results = self._run_analysis_loop(
                conversation=branch_conversation,
                trace_tail=branch_tail,
                sink_nodes=branch_sink_nodes,
                category_name=category_name,
                risk_description=risk_description,
                branch_id=branch_id,
                knowledge_element_id=knowledge_element_id,
            )

            for r in branch_results:
                r["branch_id"] = branch_id
                r["branch_node"] = branch_node

            all_branch_results.extend(branch_results)

        return all_branch_results


    def _build_branch_context(
        self,
        sink_nodes: List[Dict[str, Any]],
        category_name: str,
        risk_description: str,
        branch_node: Dict[str, Any],
        knowledge_element_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """
        构造分支分析的对话上下文（与主分析完全隔离）。
        只包含 sink 链路信息 + 该分支的节点信息。
        """
        sink_chain_context, audit_info_context = self._format_sink_chain(
            sink_nodes,
            knowledge_element_id=knowledge_element_id,
        )
        tool_schema = self._brain.tool_registry.get_all_tools_schema()

        system_content = chain_analyzer_system_prompt.format(
            project_info=self._brain.project_info_compact or "(无项目信息)",
            tool_registry=tool_schema,
        )

        # 注入知识库审计增强提示词
        audit_enhancement = build_audit_system_prompt(
            language=category_name,
            include_priority_layers=False,
            include_severity_guide=True,
            include_evidence_contract=True,
            include_dedup_rules=True,
            include_dual_verdict=True,
            include_language_rules=False,
        )
        if audit_enhancement:
            system_content += "\n\n" + audit_enhancement

        # 注入安全领域检查清单（按漏洞类型精确匹配）
        _VULN_TO_DOMAIN = {
            "认证": "authentication_authorization", "授权": "authentication_authorization",
            "越权": "authentication_authorization", "IDOR": "authentication_authorization",
            "会话": "session_management", "Session": "session_management",
            "输入验证": "input_validation", "注入": "input_validation",
            "SQL注入": "input_validation", "XSS": "input_validation",
            "命令注入": "input_validation", "代码执行": "input_validation",
            "加密": "cryptography", "密码": "cryptography", "密钥": "cryptography",
            "业务逻辑": "business_logic", "竞态": "race_conditions",
            "文件": "file_operations", "上传": "file_operations", "路径遍历": "file_operations",
            "API": "api_security", "CORS": "api_security",
            "依赖": "dependencies", "组件": "dependencies",
            "信息泄露": "information_disclosure", "泄露": "information_disclosure",
            "SSRF": "api_security",
            "反序列化": "input_validation",
        }
        matched_domain_id = None
        for keyword, domain_id in _VULN_TO_DOMAIN.items():
            if keyword in category_name:
                matched_domain_id = domain_id
                break
        if matched_domain_id and matched_domain_id in SECURITY_DOMAINS:
            domain_data = SECURITY_DOMAINS[matched_domain_id]
            checks = domain_data.get("checks", [])
            if checks:
                system_content += f"\n\n## {domain_data.get('title', '')}检查清单\n"
                for chk in checks[:5]:
                    system_content += f"- {chk}\n"

        # 注入组合漏洞分析模式（仅在涉及多漏洞组合场景时注入）
        _COMBO_KEYWORDS = ["组合", "链式", "利用链", "攻击链", "SSRF", "RCE", "XSS", "CSRF", "注入"]
        if any(kw in category_name for kw in _COMBO_KEYWORDS):
            system_content += "\n\n" + COMBINED_VULN_PATTERNS

        # 注入通用安全检查清单（精简版，仅注入与当前漏洞类型相关的部分）
        _CHECKLIST_SECTIONS = {
            "注入": "### 注入", "SQL": "### 注入", "XSS": "### 注入", "命令": "### 注入",
            "认证": "### 认证与授权", "授权": "### 认证与授权", "越权": "### 认证与授权",
            "敏感数据": "### 敏感数据", "加密": "### 敏感数据", "密码": "### 敏感数据",
            "文件": "### 文件操作", "上传": "### 文件操作", "路径遍历": "### 文件操作",
            "反序列化": "### 反序列化",
        }
        matched_section = None
        for kw, section_header in _CHECKLIST_SECTIONS.items():
            if kw in category_name:
                matched_section = section_header
                break
        if matched_section and matched_section in SECURITY_CHECKLIST:
            section_start = SECURITY_CHECKLIST.find(matched_section)
            if section_start >= 0:
                # 找到下一个 ### 或文件末尾
                next_section = SECURITY_CHECKLIST.find("\n### ", section_start + 1)
                section_content = SECURITY_CHECKLIST[section_start:next_section] if next_section > 0 else SECURITY_CHECKLIST[section_start:]
                system_content += "\n\n## 安全检查清单（相关部分）\n" + section_content.strip()

        # 注入证据点模板（按需，仅匹配当前漏洞类型）
        evidence_template = get_evidence_template(category_name)
        if evidence_template:
            system_content += "\n\n## 证据要求\n"
            system_content += f"- 必须包含: {', '.join(evidence_template['required_evidence'])}\n"
            system_content += f"- 安全信号(kill switch): {', '.join(evidence_template['kill_switch_signals'])}\n"

        # 注入漏洞类型审计指南（框架感知检测矩阵、危险模式示例、CWE/国标）
        try:
            from src.knowledge.audit_vulnerability_guides import get_vulnerability_guide
            vul_guide = get_vulnerability_guide(category_name)
            if vul_guide:
                system_content += "\n\n" + vul_guide
        except Exception:
            pass

        # 注入安全检查清单（按漏洞类型精确匹配）
        try:
            from src.services.security_checklist import get_security_checklist
            checklist = get_security_checklist(category_name)
            if checklist:
                system_content += "\n\n" + checklist
        except Exception:
            pass

        # 注入 GB/T 证据要求（当漏洞类型有 GB/T 映射时）
        from src.knowledge.gbt_standards import VULN_GBT_MAP
        if category_name in VULN_GBT_MAP or any(kw in category_name for kw in VULN_GBT_MAP):
            system_content += "\n\n" + GBT_EVIDENCE_REQUIREMENTS

        # 注入安全领域 MD（按漏洞类型匹配：business_logic, oauth_oidc_saml, input_validation 等）
        try:
            from src.knowledge.md_loader import inject_domain_knowledge
            domain_md = inject_domain_knowledge(category_name, max_domains=2)
            if domain_md:
                system_content += domain_md
        except Exception:
            pass

        # 注入 GB/T 漏洞审计细则 MD（按漏洞类型匹配）
        try:
            from src.knowledge.md_loader import inject_gbt_vuln_knowledge
            gbt_md = inject_gbt_vuln_knowledge(category_name)
            if gbt_md:
                system_content += gbt_md
        except Exception:
            pass

        user_content = chain_node_prompt.format(
            risk_category=category_name,
            risk_description=risk_description,
            sink_chain_context=sink_chain_context,
            branch_type=branch_node.get("type", "data_flow"),
            branch_function=branch_node.get("function", "?"),
            branch_file=branch_node.get("file", "?"),
            branch_line=branch_node.get("line", "?"),
            branch_reason=branch_node.get("reason", ""),
            sink_chain_audit_info= audit_info_context,
        )

        return [{"role": "system", "content": system_content}, {"role": "user", "content": user_content}]

    @staticmethod
    def _format_sink_node_attr_value(attr_key: str, value: Any) -> str:
        if value is None:
            return ""
        if attr_key == "labels":
            seq = value if isinstance(value, (list, tuple)) else [value]
            return ", ".join(str(x) for x in seq)
        if isinstance(value, (dict, list)):
            try:
                return json.dumps(value, ensure_ascii=False)
            except TypeError:
                return str(value)
        return str(value)

    def _format_sink_chain(
        self,
        sink_nodes: List[Dict[str, Any]],
        knowledge_element_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        if not sink_nodes:
            return "(无 sink 点信息)", ""
        kid = (knowledge_element_id or "").strip()
        lines = []
        if kid:
            lines.append(
                "【全局知识库】本漏洞类型 :Knowledge 节点 Neo4j elementId="
                f"{kid}（跨链路共性 AuditInfo 可将 record_info.target.elementId 设为此值）"
            )
        read_lines = ReadLinesTool(base_path=self._brain.project_path)
        flow_ids = []
        sink_element_ids = [
            node.get("elementId") for node in sink_nodes if node.get("elementId") not in (None, "")
        ]
        if sink_element_ids:
            update_node_status_by_element_ids(sink_element_ids, "running")
        audit_info = []
        audit_info_by_eid = fetch_audit_info_contents_by_element_ids(sink_element_ids)

        missing_line_eids = [
            node.get("elementId") for node in sink_nodes
            if not (node.get("line", "") or "") and node.get("elementId") not in (None, "")
        ]
        line_info_by_eid = fetch_node_lines_by_element_ids(missing_line_eids) if missing_line_eids else {}

        for i, node in enumerate(sink_nodes):
            raw_file_path = node.get('file', '') or ''
            file_path = self._remap_neo4j_file_path(raw_file_path, self._brain.project_path)
            line = node.get('line', '') or ''
            end_line = node.get('end_line', '') or ''

            if not line:
                eid = node.get("elementId", "")
                if eid and eid in line_info_by_eid:
                    fetched = line_info_by_eid[eid]
                    line = str(fetched.get("line", "") or "")
                    end_line = end_line or str(fetched.get("end_line", "") or "")
            sink_node_id = node.get('sink_node_id', '')
            node_id = node.get('node_id', '')
            prefix = "→ →FLOW→ →" if i > 0 else ""
            lines.append(
                f"{prefix}[{i + 1}] {node.get('function', '?')} "
                f"({file_path}:{line}-{end_line})"
            )
            for attr_key in sorted(node.keys()):
                val_str = self._format_sink_node_attr_value(
                    attr_key, node.get(attr_key)
                )
                lines.append(f"    {attr_key}: {val_str}")
            if file_path != '' and line != '':
                try:
                    line_num = int(str(line).strip())
                except (TypeError, ValueError):
                    line_num = None
                if line_num is not None:
                    lines.append(
                        "    code（当前节点的代码，无需重复读取该部分代码；line|code ）:"
                    )
                    if str(end_line).strip():
                        try:
                            end_num = int(str(end_line).strip())
                            start_ln, end_ln = line_num, end_num
                        except (TypeError, ValueError):
                            start_ln, end_ln = max(1, line_num - 5), line_num + 5
                    else:
                        start_ln, end_ln = max(1, line_num - 5), line_num + 5
                    res = read_lines.run(file_path, start_ln, end_ln)
                    if res.success:
                        lines.extend(res.data)
            element_id_raw = node.get("elementId")
            eid_key = ""
            if element_id_raw is not None:
                eid_key = str(element_id_raw).strip()
            pieces: List[str] = []
            if eid_key:
                pieces = audit_info_by_eid.get(eid_key) or []
            audit_info_supplement = ";".join(pieces) if pieces else ""
            if audit_info_supplement:
                audit_info.append(
                    f"针对 sink node elementId={eid_key} 的补充信息AuditInfo.content，"
                    f"共 {len(pieces)} 条:{audit_info_supplement}"
                )
            if node_id != '':
                flow_ids.append(node_id)
            elif sink_node_id != '':
                flow_ids.append(sink_node_id)
            else:
                flow_ids.append(element_id_raw)

        lines.append("\n整个sink->source的流向如下:")
        chian_flow_str = ""
        for flow_id in flow_ids:
            chian_flow_str += f"[{flow_id}]->"
        lines.append(chian_flow_str)
        if kid:
            global_pieces = (
                fetch_audit_info_contents_by_element_ids([kid]).get(kid) or []
            )
            if global_pieces:
                joined = ";".join(global_pieces)
                audit_info.append(
                    "【全局审计经验信息知识库】来自本漏洞类型 Knowledge 节点，经 :HAS_AUDIT_INFO→AuditInfo，"
                    f"elementId={kid}，共 {len(global_pieces)} 条：{joined}"
                )
        return "\n".join(lines), "\n".join(audit_info)

    @staticmethod
    def _format_chain_nodes(chain_nodes: List[Dict[str, Any]]) -> str:
        if not chain_nodes:
            return "(尚无已确认的链路节点)"
        lines = []
        for i, cn in enumerate(chain_nodes):
            lines.append(
                f"  [{i + 1}] type={cn.get('type', '?')} | "
                f"file={cn.get('file', '')} line={cn.get('line', '')} "
                f"func={cn.get('function', '')} | "
                f"{cn.get('description', '')}"
            )
        return "\n".join(lines)

    # ==================================================================
    # 强制收口
    # ==================================================================

    def _force_conclude(
        self,
        conversation: List[Dict[str, str]],
        trace_tail: _TraceTail,
        branch_id: str,
        inserted_chain_nodes: List[Dict[str, Any]],
        category_name: str,
        risk_description: str,
        knowledge_element_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._publish_log(
            "INFO",
            f"[ChainAnalyzer] 执行强制收口 | branch_id={branch_id} trace_tail={trace_tail.node_id}",
        )
        force_msg = chain_analyzer_force_conclude_prompt.format(
            max_rounds=self.max_rounds,
        )
        conversation.append({"role": "user", "content": force_msg})
        force_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.CHAIN_ANALYSIS,
            reason="max_rounds_force_conclude",
            tool_arguments={"analyzer_step": "force_conclude"},
        )
        step, input_tokens, output_tokens = self._llm_step(conversation)
        force_span.add_llm_tokens(input_tokens, output_tokens)
        if step and step.get("action") == "final_resolution":
            candidate = step.get("resolution", {})
            v_err = self._final_resolution_validation_error(candidate)
            if v_err is None:
                resolution = self._normalize_final_resolution_payload(candidate)
            else:
                msg = (
                    f"[ChainAnalyzer] 强制收口 final_resolution 未通过校验，使用兜底 | "
                    f"{v_err[:120]}"
                )
                logger.warning(msg)
                self._publish_log("WARNING", msg)
                resolution = self._make_fallback_resolution(resolution_candidate=candidate)
        else:
            resolution = self._make_fallback_resolution()
        resolution["analysis_rounds"] = self.max_rounds
        ar_node_id, vulnerability_id = persist_analysis_result(
            self._brain.task_id,
            self._brain.project_id,
            attach_to_node_id=trace_tail.node_id,
            attach_is_sink_flow=trace_tail.is_sink_flow,
            resolution=resolution,
            branch_id=branch_id,
            category_name=category_name,
            project_root=str(self._brain.project_path or ""),
        )
        resolution["_ar_node_id"] = ar_node_id
        resolution["_vulnerability_id"] = vulnerability_id
        self._after_final_resolution_persisted(
            resolution=resolution,
            category_name=category_name,
            risk_description=risk_description,
            knowledge_element_id=knowledge_element_id,
        )
        force_span.set_output(
            json.dumps(
                {"verdict": resolution.get("verdict"), "used_llm_step": bool(step)},
                ensure_ascii=False,
            )
        )
        force_span.finish()
        return resolution

    @staticmethod
    def _make_fallback_resolution(
        resolution_candidate: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        msg = "超过最大分析轮次，未得到分析结果标记为安全。"
        detail = msg
        if isinstance(resolution_candidate, dict):
            d = resolution_candidate.get("detail")
            if isinstance(d, str) and d.strip():
                detail = d.strip()
        return {
            "verdict": "SAFE",
            "confidence": "LOW",
            "vul_name": "",
            "detail": msg + "\n" + detail,
            "entry_points": [],
            "security_boundaries": [],
        }
