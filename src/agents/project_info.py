# -*- coding:utf-8 -*-　　
# @name: project_info
# @auth: rainy-autumn@outlook.com
# @version:
"""
ProjectInfo Agent —— 信息收集阶段：OpenCode 生成系统级项目介绍 + Tokei 语言分布，
再由 LLM 产出供后续 Agent 使用的 project_info_compact。
"""
import json
import logging
from typing import Any, Dict, Optional

from src.core.enums import ActionType
from src.core.event_span import event_span, start_event_span
from src.agents.base import BaseAgent
from src.core.task_control import ensure_task_running
from src.agents.brain import Brain
from src.llm import LLMError
from src.agents.prompt.project_info import (
    opencode_project_info_prompt,
    project_info_compact_system_prompt,
    project_info_compact_user_template,
)
from src.schemas.project import ProjectUpdate
from src.services.project_service import update_project
from src.tools import TokeiTool
from src.utils import parse_json

logger = logging.getLogger(__name__)


def _truncate_for_reason(text: object, limit: int = 8000) -> str:
    """与 Brain._short 类似：写入 events.reason 时控制长度。"""
    s = text if isinstance(text, str) else repr(text)
    if len(s) <= limit:
        return s
    return s[:limit] + f"...(truncated {len(s) - limit} chars)"


class ProjectInfo(BaseAgent):
    """
    收集项目级上下文：Tokei 统计 + code_agent（OpenCode）长文介绍，
    并调用 LLM 将合并后的原文压缩为 project_info_compact。
    """

    MODULE_NAME = "ProjectInfo"

    def __init__(self, brain: Optional[Brain] = None):
        super().__init__(brain=brain)

    def run(self) -> Optional[Dict[str, Any]]:
        ensure_task_running(self._brain.task_id)
        self._publish_log(
            "INFO",
            f"[ProjectInfo] 开始收集项目信息 | path={self._brain.project_path}",
        )
        tokei_tool = TokeiTool()
        code_res = tokei_tool.run(self._brain.project_path)
        if code_res.success:
            self._publish_log("INFO", "[ProjectInfo] Tokei 语言统计完成")
        else:
            self._publish_log(
                "WARNING",
                f"[ProjectInfo] Tokei 统计失败 | error={code_res.error!r}",
            )

        try:
            tool = self._brain.get_tool("code_agent")
            if tool is None:
                self._publish_log("WARNING", "[ProjectInfo] code_agent 工具未注册，跳过")
            elif not tool.status:
                self._publish_log("WARNING", "[ProjectInfo] code_agent 不可用，跳过")
            if tool is not None:
                if tool.status:
                    self._publish_log("INFO", "[ProjectInfo] 调用 code_agent 生成长文介绍")
                    info_span = start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.TOOL_CALL,
                        tool_name="code_agent",
                        reason="调用code_agent工具进行项目信息收集"
                    )
                    tool.set_event_id(info_span.event_id)
                    ensure_task_running(self._brain.task_id)
                    session_id = tool.create_session()
                    result = tool.run(
                        msg=opencode_project_info_prompt + f"\n项目目录:{self._brain.project_path}",
                        session_id=session_id,
                        task_id=self._brain.task_id,
                    )
                    self._brain.project_info = (result.data or {}).get("response_text", "")
                    info_span.set_output(self._brain.project_info)
                    self._brain.set_project_info_session_id(session_id)
                    if self._brain.project_info == '':
                        info_span.mark_failed()
                        self._publish_log("WARNING", "[ProjectInfo] code_agent 返回空 project_info")
                    else:
                        self._publish_log(
                            "INFO",
                            f"[ProjectInfo] code_agent 完成 | chars={len(self._brain.project_info)}",
                        )
                        if self._brain.project_info != "" and code_res.data is not None:
                            self._brain.project_info += "\n 语言分布如下：" + json.dumps(code_res.data, ensure_ascii=False)
                        token_input = (result.data or {}).get("token_input", 0)
                        token_output = (result.data or {}).get("token_output", 0)
                        info_span.add_code_agent_tokens(token_input, token_output)
                        info_span.finish()

                        self._fill_project_info_compact()
                        self._persist_project_info_to_db(code_res.data if code_res.success else None)
            self._publish_log("INFO", "[ProjectInfo] 项目信息收集流程结束")
            return None
        except LLMError:
            # LLM 致命错误（额度/鉴权等）：向上抛出，使任务标记失败，
            # 不能降级为返回 FAILED 字典后被编排层忽略并标记完成。
            self._publish_log("ERROR", "[ProjectInfo] 信息收集时 LLM 调用发生致命错误，向上抛出")
            raise
        except RuntimeError as e:
            self._publish_log("ERROR", f"[ProjectInfo] 收集失败: {e!r}")
            return {
                "error": str(e),
                "status": "FAILED",
            }

    def _persist_project_info_to_db(self, code_stats: Optional[Dict[str, Any]]) -> None:
        """把收集到的项目信息写回数据库的 projects 表。"""
        project_id = (self._brain.project_id or "").strip()
        if not project_id:
            msg = "[ProjectInfo] 持久化跳过: project_id 为空"
            logger.warning(msg)
            self._publish_log("WARNING", msg)
            return
        try:
            update_kwargs: Dict[str, Any] = {
                "description": self._brain.project_info or "",
                "description_compact": self._brain.project_info_compact or "",
                "session_id": self._brain.get_project_info_session_id() or "",
            }

            if isinstance(code_stats, dict):
                update_kwargs["language_stats"] = code_stats
                total = code_stats.get("total")
                if isinstance(total, dict):
                    files = total.get("files")
                    code_lines = total.get("code")
                    if isinstance(files, int):
                        update_kwargs["file_count"] = files
                    if isinstance(code_lines, int):
                        update_kwargs["line_count"] = code_lines

            updated = update_project(project_id, ProjectUpdate(**update_kwargs))
            if updated is None:
                msg = f"[ProjectInfo] 持久化失败: 未找到项目 project_id={project_id}"
                logger.error(msg)
                self._publish_log("ERROR", msg)
            else:
                self._publish_log("INFO", f"[ProjectInfo] 已写回数据库 project_id={project_id}")
        except Exception as e:
            logger.exception("[ProjectInfo] 持久化异常: project_id=%s, error=%s", project_id, e)
            self._publish_log("ERROR", f"[ProjectInfo] 持久化异常: {e!r}")

    def _fill_project_info_compact(self) -> None:
        """用 LLM 将当前 project_info 压缩写入 project_info_compact。"""
        raw = (self._brain.project_info or "").strip()
        if not raw:
            self._publish_log("WARNING", "[ProjectInfo] 跳过压缩: project_info 为空")
            return

        self._publish_log("INFO", "[ProjectInfo] 开始 LLM 压缩 project_info_compact")
        base = "项目根目录：" + self._brain.project_path + "\n"
        user_content = project_info_compact_user_template.replace("{raw_project_info}", raw)
        conversation = [
            {"role": "system", "content": project_info_compact_system_prompt},
            {"role": "user", "content": user_content},
        ]

        for attempt in range(self.max_retries):
            info_span = start_event_span(
                task_id=self._brain.task_id,
                module=self.MODULE_NAME,
                action_type=ActionType.THINKING,
                reason="将项目信息进行压缩"
            )
            try:
                step, input_tokens, output_tokens = self._llm_step(conversation)
            except LLMError:
                # LLM 致命错误（额度/鉴权等）：向上抛出而非静默返回，确保任务标记失败。
                info_span.mark_failed("压缩 LLM 调用发生致命错误")
                self._publish_log(
                    "ERROR",
                    f"[ProjectInfo] 压缩时 LLM 调用发生致命错误 (attempt {attempt + 1})，向上抛出",
                )
                raise
            except Exception as e:
                info_span.mark_failed(f"压缩 LLM 调用异常: {str(e)}")
                logger.exception("[ProjectInfo] 压缩 LLM 调用异常: %s", e)
                self._publish_log(
                    "ERROR",
                    f"[ProjectInfo] 压缩 LLM 调用异常 (attempt {attempt + 1}): {e!r}",
                )
                return

            if step is None:
                self._publish_log(
                    "WARNING",
                    f"[ProjectInfo] 压缩 LLM 返回为空 (attempt {attempt + 1}/{self.max_retries})",
                )
                info_span.mark_failed("LLM 返回为空")
                continue

            compact = step.get("project_info_compact", "")
            if isinstance(compact, str) and compact.strip():
                self._brain.project_info_compact = base + compact.strip()
                info_span.add_llm_tokens(input_tokens, output_tokens)
                info_span.set_output(self._brain.project_info_compact)
                info_span.finish()
                self._publish_log(
                    "INFO",
                    f"[ProjectInfo] 压缩完成 | compact_chars={len(self._brain.project_info_compact)}",
                )
                return

            self._publish_log(
                "WARNING",
                f"[ProjectInfo] 压缩结果无效 (attempt {attempt + 1}/{self.max_retries})",
            )
            info_span.mark_failed("项目压缩信息获取失败")

            conversation.append({"role": "assistant", "content": json.dumps(compact, ensure_ascii=False)})
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "MISSING_PROJECT_INFO_COMPACT",
                    "requirement": "JSON 中必须包含非空的 project_info_compact 字符串",
                }, ensure_ascii=False),
            })
