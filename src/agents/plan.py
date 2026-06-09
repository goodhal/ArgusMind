# -*- coding: utf-8 -*-
"""
Plan Agent —— 项目审计计划生成阶段。

根据项目信息，通过多轮 LLM 对话 + 工具调用，生成审计计划。
"""
import json
import os
from typing import Any, Dict, List, Optional

from src.core.enums import ActionType
from src.agents.base import BaseAgent
from src.agents.brain import Brain
from src.agents.prompt.plan import plan_prompt
from src.core.event_span import start_event_span
from src.core.task_control import ensure_task_running
from src.knowledge import LANGUAGE_VULN_MAP, AUDIT_SKILLS
from src.knowledge.audit_skills import AUDIT_WORKFLOW, QUALITY_STANDARDS
from src.knowledge.audit_config import AUDIT_PROFILES, AUDIT_SCHEDULING
from src.knowledge.component_vulns import format_component_vulns_for_prompt


class Plan(BaseAgent):
    """审计计划生成 Agent。"""

    DEFAULT_MAX_ROUNDS = 10
    MODULE_NAME = "Plan"

    def __init__(self, brain: Optional[Brain] = None, max_rounds: int = DEFAULT_MAX_ROUNDS):
        super().__init__(brain=brain)
        self.max_rounds = max_rounds

    def run(self) -> Optional[Dict[str, Any]]:
        conversation = self._build_context()

        plan_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.PLANNING,
            reason="开始制定审计计划",
        )
        self._publish_log("INFO", "[Plan] 开始制定审计计划")

        for round_num in range(1, self.max_rounds + 1):
            ensure_task_running(self._brain.task_id)
            self._publish_log("INFO", f"[Plan] LLM 轮次 {round_num}/{self.max_rounds}")
            step, input_tokens, output_tokens = self._llm_step(conversation)
            if step is None:
                plan_span.add_llm_tokens(input_tokens, output_tokens)
                self._publish_log(
                    "WARNING",
                    f"[Plan] LLM 返回为空，重试 ({round_num}/{self.max_rounds})",
                )
                continue

            next_action = (step or {}).get("next_action", {}) or {}
            action_type = next_action.get("type")

            if action_type == "final":
                final_output = step.get("final_output")
                plan_span.add_llm_tokens(input_tokens, output_tokens)
                if final_output is None:
                    self._publish_log(
                        "WARNING",
                        f"[Plan] final 缺少 final_output (轮 {round_num})",
                    )
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "FINAL_WITHOUT_OUTPUT",
                            "requirement": "type=final 时 final_output 不能为空，且必须是计划JSON",
                        }, ensure_ascii=False),
                    })
                    continue
                self._brain.plan = final_output
                self._report_cache_stats(self._brain.task_id)
                plan_span.finish()
                self._publish_log("INFO", f"[Plan] 审计计划生成完成 (轮 {round_num})")
                return final_output

            # 兼容 LLM 将工具名误设为 action_type
            _known_tools_fallback = {"ripgrep_search", "read_file", "read_lines",
                "ripgrep_files", "list_files", "code_search", "class_hierarchy", "remote_repo",
                "code_agent", "ripgrep", "search", "grep", "read", "cat", "list", "ls",
                "gitnexus_context", "list_directory", "dir"}
            if action_type == "tool_call":
                tool_name = next_action.get("tool_name", "") or ""
            elif action_type in _known_tools_fallback:
                self._publish_log(
                    "INFO",
                    f"[Plan] 自动修正 action_type={action_type!r} → tool_call (tool_name={action_type!r})",
                )
                tool_name = action_type
                next_action["type"] = "tool_call"
                next_action.setdefault("tool_name", action_type)
                action_type = "tool_call"
            else:
                action_type = action_type  # fall through to the invalid handler below

            if action_type == "tool_call":
                self._publish_log(
                    "INFO",
                    f"[Plan] 调用工具 {tool_name!r} (轮 {round_num})",
                )
                tool_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.TOOL_CALL,
                    tool_name=next_action.get("tool_name", ""),
                    reason=f"调用 {next_action.get('tool_name', '')} 工具",
                    tool_arguments=next_action.get('arguments', {}) or {},
                )
                tool_result = self._execute_tool_call(next_action, conversation, tool_span)
                tool_span.set_output(json.dumps(tool_result, ensure_ascii=False, default=str))
                tool_span.add_llm_tokens(input_tokens, output_tokens)
                if tool_result is None:
                    self._publish_log(
                        "WARNING",
                        f"[Plan] 工具 {tool_name!r} 未返回结果 (轮 {round_num})",
                    )
                    tool_span.mark_failed("工具调用未返回结果")
                else:
                    tool_span.finish()
                if tool_result is not None:
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "TOOL_RESULT",
                            "tool_name": next_action.get("tool_name", "unknown"),
                            "result": tool_result,
                        }, ensure_ascii=False, default=str),
                    })
                continue

            plan_span.add_llm_tokens(input_tokens, output_tokens)
            self._publish_log(
                "WARNING",
                f"[Plan] 无效 next_action.type={action_type!r} (轮 {round_num})",
            )
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "INVALID_NEXT_ACTION",
                    "requirement": "next_action.type 只能是 tool_call 或 final",
                }, ensure_ascii=False),
            })

        self._publish_log(
            "WARNING",
            f"[Plan] 已达最大轮次 {self.max_rounds}，计划生成失败",
        )
        self._report_cache_stats(self._brain.task_id)
        plan_span.finish()
        return None

    def _build_context(self) -> List[Dict[str, str]]:
        tool_schema = self._brain.tool_registry.get_all_tools_schema()
        system_content = plan_prompt.replace("{tool_registry}", tool_schema)

        # 注入知识库：各语言支持的漏洞类型参考
        knowledge_hint = self._build_knowledge_hint()
        if knowledge_hint:
            system_content += "\n\n" + knowledge_hint

        # 注入项目规模信息，帮助 LLM 控制漏洞类型数量
        scale_hint = self._build_scale_hint()
        if scale_hint:
            system_content += "\n\n" + scale_hint

        return [
            {"role": "system", "content": system_content},
            {"role": "user", "content": self._brain.project_info},
        ]

    def _build_knowledge_hint(self) -> str:
        """基于知识库生成各语言漏洞类型参考提示。"""
        if not LANGUAGE_VULN_MAP:
            return ""

        parts = ["# 知识库参考：各语言常见漏洞类型\n"]
        for lang, vuln_types in LANGUAGE_VULN_MAP.items():
            lang_display = lang.lstrip(".")
            types_str = "、".join(vuln_types) if isinstance(vuln_types, (list, tuple)) else str(vuln_types)
            parts.append(f"- **{lang_display}**：{types_str}")

        # 注入审计技能摘要（仅注入与当前项目语言相关的技能）
        if AUDIT_SKILLS:
            parts.append("\n## 审计技能参考")
            for skill in AUDIT_SKILLS[:8]:  # 限制长度
                name = skill.get("name", "")
                desc = skill.get("description", "")
                priority = skill.get("priority", "")
                if name:
                    parts.append(f"- **{name}**（{priority}）：{desc}")

        # 注入审计流程知识（仅三层分工概要，不注入完整检查清单）
        if AUDIT_WORKFLOW:
            # 只取三层分工表格部分，不注入完整检查清单
            workflow_summary = AUDIT_WORKFLOW.split("## LLM审计详细检查清单")[0]
            parts.append("\n## 审计流程参考")
            parts.append(workflow_summary.strip())

        # 注入审计配置（仅关键参数，不注入全部配置）
        if AUDIT_SCHEDULING:
            parts.append(f"\n## 审计调度参数")
            parts.append(f"- 批次大小：{AUDIT_SCHEDULING.get('maxFilesPerBatch', 6)} 文件/批")
            parts.append(f"- 最大并行：{AUDIT_SCHEDULING.get('maxParallelRequests', 5)} 请求")
            parts.append(f"- 检查点间隔：{AUDIT_SCHEDULING.get('checkpointInterval', 3)} 批次")

        # 注入已知漏洞组件参考（当项目包含 Java/Python/JS 等语言时）
        project_langs = set(LANGUAGE_VULN_MAP.keys()) if LANGUAGE_VULN_MAP else set()
        if project_langs:
            component_hint = format_component_vulns_for_prompt()
            if component_hint:
                parts.append(component_hint)

        return "\n".join(parts)

    def _build_scale_hint(self) -> str:
        """根据项目规模生成漏洞类型数量约束提示。"""
        # 移除项目文件数限制，让 LLM 自由决定漏洞类型数量
        return ""
