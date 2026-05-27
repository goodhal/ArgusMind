# -*- coding: utf-8 -*-
"""
Plan Agent —— 项目审计计划生成阶段。

根据项目信息，通过多轮 LLM 对话 + 工具调用，生成审计计划。
"""
import json
from typing import Any, Dict, List, Optional

from src.core.enums import ActionType
from src.agents.base import BaseAgent
from src.agents.brain import Brain
from src.agents.prompt.plan import plan_prompt
from src.core.event_span import start_event_span
from src.core.task_control import ensure_task_running


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
                plan_span.finish()
                self._publish_log("INFO", f"[Plan] 审计计划生成完成 (轮 {round_num})")
                return final_output

            if action_type == "tool_call":
                tool_name = next_action.get("tool_name", "") or ""
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
        plan_span.finish()
        return None

    def _build_context(self) -> List[Dict[str, str]]:
        tool_schema = self._brain.tool_registry.get_all_tools_schema()
        system_content = plan_prompt.replace("{tool_registry}", tool_schema)
        return [
            {"role": "system", "content": system_content},
            {"role": "user", "content": self._brain.project_info},
        ]
