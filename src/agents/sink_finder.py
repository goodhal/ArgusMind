# -------------------------------------
# @file      : sink_finder.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2026/3/3 22:23
# -------------------------------------------
import json
import os
import re
import traceback
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ActionType
from src.core.event_span import start_event_span, EventSpan
from src.agents.base import BaseAgent
from src.core.task_control import ensure_task_running
from src.llm import LLMError
from src.agents.brain import Brain
from src.agents.prompt.sink_finder import sink_finder_prompt
from src.agents.prompt.sink_finder_refine import build_sink_refine_system_prompt
from services.plan_service import mark_risk_category_sink_finder_completed
from services.sink_flow_service import persist_sink_flow_to_neo4j
from src.utils.ids import generate_uuid
from src.utils.json_parse import parse_json
from src.knowledge import LANGUAGE_AUDIT_RULES_LLM, build_audit_system_prompt
from src.knowledge.framework_rules import detect_framework, get_dangerous_patterns, get_framework_vulns
from src.knowledge.security_domains import get_grep_rules, QUICK_GREP_RULES
from src.knowledge.detection_patterns import format_detection_patterns_for_prompt, get_language_checklist

_SINK_RES_SCHEMA_HINT = (
    "顶层须为 JSON 数组；每项为对象，必填字段："
    "file(非空相对路径), line(正整数), end_line(正整数且>=line), "
    "function(字符串), related_exec(字符串，可为空；非空时为 file:line:function 或 <file:line:function>), "
    "reason(非空字符串)"
)


def _preview_value(value: Any, max_len: int = 200) -> Any:
    """将异常值压缩为可放入错误反馈的预览。"""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        s = value.replace("\n", "\\n")
        return s if len(s) <= max_len else s[:max_len] + "...(truncated)"
    if isinstance(value, (list, dict)):
        try:
            s = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            s = repr(value)
        return s if len(s) <= max_len else s[:max_len] + "...(truncated)"
    return f"<{type(value).__name__}>"


def _sink_validation_error(
    code: str,
    *,
    index: Optional[int] = None,
    field: Optional[str] = None,
    actual: Any = None,
    expected: str = "",
    message: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if index is not None:
        err["index"] = index
    if field:
        err["field"] = field
    if actual is not None or field:
        err["actual"] = _preview_value(actual)
        if actual is not None:
            err["actual_type"] = type(actual).__name__
    if expected:
        err["expected"] = expected
    if extra:
        err.update(extra)
    return err


def _build_invalid_sink_format_fix_detail(
    validation_err: Dict[str, Any],
    *,
    error_code: str = "INVALID_SINK_FORMAT",
    result_file_path: str = "",
    raw_sink_res: Any = None,
) -> str:
    payload: Dict[str, Any] = {
        "info": f"校验结果文件内容出错",
        "error": error_code,
        "validation": validation_err,
        "schema": _SINK_RES_SCHEMA_HINT,
    }
    if result_file_path:
        payload["result_file"] = result_file_path
    if isinstance(raw_sink_res, list):
        payload["sink_count"] = len(raw_sink_res)
        if validation_err.get("index") is not None:
            idx = validation_err["index"]
            if 0 <= idx < len(raw_sink_res):
                payload["offending_item"] = _preview_value(raw_sink_res[idx], max_len=500)
    elif raw_sink_res is not None:
        payload["raw_top_level_type"] = type(raw_sink_res).__name__
        payload["raw_preview"] = _preview_value(raw_sink_res, max_len=500)
    return json.dumps(payload, ensure_ascii=False)


def _validate_and_normalize_sink_res(sink_res, project_path: str):
    """
    校验 opencode 返回的 sink JSON 结构，并尽可能做类型规范化（如 int-like）。
    期望格式：
    [
      {
        file: str,
        line: int,
        end_line: int,
        function: str,
        related_exec: str (可为空),
        reason: str
      },
      ...
    ]
    """
    if not isinstance(sink_res, list):
        return None, _sink_validation_error(
            "RESULT_NOT_LIST",
            actual=sink_res,
            expected="JSON 数组，如 [{\"file\": \"...\", ...}, ...]",
            message=f"顶层结果必须是 JSON 数组，当前为 {type(sink_res).__name__}",
        )

    required_keys = ["file", "line", "end_line", "function", "related_exec", "reason"]
    normalized = []
    for idx, item in enumerate(sink_res):
        if not isinstance(item, dict):
            return None, _sink_validation_error(
                "ITEM_NOT_OBJECT",
                index=idx,
                actual=item,
                expected="对象，包含 file/line/end_line/function/related_exec/reason",
                message=f"第 {idx} 条 sink 必须是 JSON 对象，当前为 {type(item).__name__}",
            )

        missing = [k for k in required_keys if k not in item]
        if missing:
            return None, _sink_validation_error(
                "MISSING_KEYS",
                index=idx,
                expected=f"对象须包含字段: {required_keys}",
                message=f"第 {idx} 条 sink 缺少必填字段: {missing}",
                extra={
                    "missing": missing,
                    "present_keys": list(item.keys()),
                },
            )

        # file
        file_v = item.get("file")
        if not isinstance(file_v, str) or not file_v.strip():
            return None, _sink_validation_error(
                "INVALID_FILE",
                index=idx,
                field="file",
                actual=file_v,
                expected="非空字符串，项目根目录下的相对路径",
                message=f"第 {idx} 条 sink 的 file 必须为非空字符串，当前值无效",
            )
        file_norm = file_v.strip()
        if os.path.isabs(file_norm):
            return None, _sink_validation_error(
                "FILE_MUST_BE_RELATIVE",
                index=idx,
                field="file",
                actual=file_norm,
                expected="相对路径，如 src/module/foo.py",
                message=f"第 {idx} 条 sink 的 file 不能是绝对路径: {file_norm}",
            )
        # 防止路径穿越（相对路径也不允许 ..）
        parts = file_norm.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            return None, _sink_validation_error(
                "FILE_PATH_TRAVERSAL_NOT_ALLOWED",
                index=idx,
                field="file",
                actual=file_norm,
                expected="相对路径且不得包含 .. 段",
                message=f"第 {idx} 条 sink 的 file 不允许路径穿越: {file_norm}",
            )
        abs_file_path = os.path.normpath(os.path.join(project_path, file_norm))
        if not os.path.exists(abs_file_path):
            return None, _sink_validation_error(
                "FILE_NOT_FOUND",
                index=idx,
                field="file",
                actual=file_norm,
                expected="相对路径且对应文件在项目中存在",
                message=f"第 {idx} 条 sink 的 file 在项目中不存在: {file_norm}",
                extra={"abs_path": abs_file_path, "project_path": project_path},
            )

        def _to_int(value, field_name):
            # bool 不是合法 int
            if isinstance(value, bool):
                raise ValueError(f"{field_name} must be int, not bool")
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                if value.is_integer():
                    return int(value)
                raise ValueError(f"{field_name} must be int-like float")
            if isinstance(value, str):
                s = value.strip()
                if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                    return int(s)
                raise ValueError(f"{field_name} must be int-like string")
            raise ValueError(f"{field_name} must be int")

        # line / end_line
        try:
            line_v = _to_int(item.get("line"), "line")
            end_line_v = _to_int(item.get("end_line"), "end_line")
        except ValueError as e:
            return None, _sink_validation_error(
                "INVALID_LINE_FIELDS",
                index=idx,
                field="line/end_line",
                actual={"line": item.get("line"), "end_line": item.get("end_line")},
                expected="正整数，或可解析为整数的数字/数字字符串",
                message=f"第 {idx} 条 sink 的 line/end_line 类型无效: {e}",
            )
        if line_v <= 0 or end_line_v <= 0:
            return None, _sink_validation_error(
                "LINE_FIELDS_MUST_BE_POSITIVE",
                index=idx,
                field="line/end_line",
                actual={"line": line_v, "end_line": end_line_v},
                expected="line 与 end_line 均为大于 0 的整数",
                message=f"第 {idx} 条 sink 的 line/end_line 必须为正整数，当前 line={line_v}, end_line={end_line_v}",
            )
        if end_line_v < line_v:
            return None, _sink_validation_error(
                "INVALID_LINE_RANGE",
                index=idx,
                field="line/end_line",
                actual={"line": line_v, "end_line": end_line_v},
                expected="end_line >= line",
                message=f"第 {idx} 条 sink 的行号范围无效: end_line({end_line_v}) 不能小于 line({line_v})",
            )

        # function
        function_v = item.get("function")
        if not isinstance(function_v, str):
            return None, _sink_validation_error(
                "INVALID_FUNCTION",
                index=idx,
                field="function",
                actual=function_v,
                expected="字符串（函数/方法名）",
                message=f"第 {idx} 条 sink 的 function 必须是字符串，当前为 {type(function_v).__name__}",
            )
        function_norm = function_v

        # related_exec: 可为空字符串；非空时做轻量格式校验
        # 支持两种格式：
        # 1) <file:line:function>
        # 2) file:line:function
        related_exec_v = item.get("related_exec")
        if not isinstance(related_exec_v, str):
            return None, _sink_validation_error(
                "INVALID_RELATED_EXEC",
                index=idx,
                field="related_exec",
                actual=related_exec_v,
                expected="字符串；无关联调用时填 \"\"",
                message=f"第 {idx} 条 sink 的 related_exec 必须是字符串，当前为 {type(related_exec_v).__name__}",
            )
        related_exec_norm = related_exec_v.strip()
        if related_exec_norm:
            if related_exec_norm.startswith("<") and related_exec_norm.endswith(">"):
                inner = related_exec_norm[1:-1].strip()
            else:
                inner = related_exec_norm

            # file:line:function 中 line 需要是整数；使用 rsplit 避免函数名中包含额外冒号导致 split 异常
            parts_inner = inner.rsplit(":", 2)
            if len(parts_inner) != 3:
                return None, _sink_validation_error(
                    "RELATED_EXEC_INNER_FORMAT_INVALID",
                    index=idx,
                    field="related_exec",
                    actual=related_exec_norm,
                    expected="file:line:function 或 <file:line:function>，且恰好包含两个冒号分隔的三段",
                    message=(
                        f"第 {idx} 条 sink 的 related_exec 格式错误，无法解析为 file:line:function: "
                        f"{related_exec_norm}"
                    ),
                    extra={"parsed_parts": parts_inner},
                )

            rel_file, rel_line_s, _rel_func = parts_inner
            rel_file = rel_file.strip()
            rel_line_s = rel_line_s.strip()
            if not rel_file or not rel_line_s or not re.match(r"^-?\d+$", rel_line_s):
                return None, _sink_validation_error(
                    "RELATED_EXEC_LINE_INVALID",
                    index=idx,
                    field="related_exec",
                    actual=related_exec_norm,
                    expected="中间段 line 为正整数字符串，file 与 function 非空",
                    message=(
                        f"第 {idx} 条 sink 的 related_exec 中 line 无效: "
                        f"file={rel_file!r}, line={rel_line_s!r}, raw={related_exec_norm}"
                    ),
                )

        # reason
        reason_v = item.get("reason")
        if not isinstance(reason_v, str) or not reason_v.strip():
            return None, _sink_validation_error(
                "INVALID_REASON",
                index=idx,
                field="reason",
                actual=reason_v,
                expected="非空字符串，说明该 sink 的安全风险原因",
                message=f"第 {idx} 条 sink 的 reason 必须为非空字符串",
            )
        reason_norm = reason_v.strip()

        normalized.append({
            "file": file_norm,
            "line": line_v,
            "end_line": end_line_v,
            "function": function_norm,
            "related_exec": related_exec_norm,
            "reason": reason_norm,
        })

    return normalized, None


def _normalize_file_for_key(file_v: str) -> str:
    """
    为了保证 id/节点去重一致性，将 file 统一为：
    - 去首尾空白
    - 统一斜杠为 '/'
    """
    return file_v.strip().replace("\\", "/")


def _sink_node_id(file_v: str, line_v: int, function_v: str) -> str:
    """sink_node_id: 由 file + line + function 生成（确定性）。"""
    file_key = _normalize_file_for_key(file_v)
    func_key = (function_v or "").strip()
    return f"{file_key}:{line_v}:{func_key}"


def _parse_related_exec_tag(related_exec_tag: str) -> Optional[Tuple[str, int, str]]:
    """
    解析 related_exec。
    兼容两种输入：
    - <file:line:function>
    - file:line:function
    返回 (file, line, function)，file 以项目根相对路径字符串返回（不做 abs 化）。
    """
    if not related_exec_tag:
        return None
    tag = related_exec_tag.strip()
    if tag.startswith("<") and tag.endswith(">"):
        inner = tag[1:-1].strip()
    else:
        inner = tag

    parts_inner = inner.rsplit(":", 2)
    if len(parts_inner) != 3:
        return None

    rel_file, rel_line_s, rel_func = parts_inner
    rel_file = _normalize_file_for_key(rel_file.strip())
    rel_line_s = rel_line_s.strip()
    if not re.match(r"^-?\d+$", rel_line_s):
        return None
    rel_line = int(rel_line_s)
    if rel_line <= 0:
        return None
    return rel_file, rel_line, (rel_func or "").strip()


def _normalize_related_file_path(rel_file: str, project_path: str) -> Optional[str]:
    """将相关节点的 file 进行安全规范化，并校验存在性。"""
    rel_file_norm = _normalize_file_for_key(rel_file)
    parts = rel_file_norm.split("/")
    if any(p == ".." for p in parts):
        return None
    if os.path.isabs(rel_file_norm):
        return None
    abs_file_path = os.path.normpath(os.path.join(project_path, rel_file_norm))
    if not os.path.exists(abs_file_path):
        return None
    return rel_file_norm


def _postprocess_sink_res_expand_related_nodes(
        sink_res: list[dict],
        project_path: str,
) -> list[dict]:
    """
    按用户规则对 sink_res 做两件事：
    1) 为每个 sink 计算确定性 sink_node_id（file+line+function）。
    2) 对每个 sink 的 related_exec（<file:line:function> 或 file:line:function），解析并补齐一个“related_exec_node”节点；
       如果 sink_res 内不存在该 related 节点，则自动生成一个完整节点（补 file/line/function）。

    返回值：
    - 对所有节点：新增 sink_id / sink_node_id（两者相同）
    - 对所有原始 sink：新增 related_exec_node（为 related 节点的 sink_node_id）
    - 对缺失生成节点：related_exec_node 为空字符串
    """
    node_by_id: dict[str, dict] = {}
    order: list[str] = []

    def _ensure_node(file_v: str, line_v: int, end_line_v: int, function_v: str, reason_v: str) -> dict:
        nid = _sink_node_id(file_v, line_v, function_v)
        if nid not in node_by_id:
            node = {
                "file": _normalize_file_for_key(file_v),
                "line": line_v,
                "end_line": end_line_v,
                "function": (function_v or "").strip(),
                "related_exec": "",
                "reason": reason_v,
                "sink_id": nid,
                "sink_node_id": nid,
                "related_exec_node": "",
            }
            node_by_id[nid] = node
            order.append(nid)
        else:
            # 如果这个节点之前是“related_exec 衍生的占位节点”，后续又作为真实 sink 出现，
            # 则用真实 sink 的 end_line/reason 信息进行升级（保证后续建图/证据更准确）。
            existing = node_by_id[nid]
            auto_reason = "auto_generated_from_related_exec"
            if existing.get("reason") == auto_reason and reason_v != auto_reason:
                existing["file"] = _normalize_file_for_key(file_v)
                existing["line"] = line_v
                existing["end_line"] = end_line_v
                existing["function"] = (function_v or "").strip()
                existing["reason"] = reason_v
        return node_by_id[nid]

    for item in sink_res:
        file_v = _normalize_file_for_key(item["file"])
        line_v = int(item["line"])
        end_line_v = int(item["end_line"])
        function_v = (item.get("function") or "").strip()
        reason_v = item.get("reason") or "unknown"

        node = _ensure_node(
            file_v=file_v,
            line_v=line_v,
            end_line_v=end_line_v,
            function_v=function_v,
            reason_v=reason_v,
        )

        related_tag = item.get("related_exec") or ""
        parsed = _parse_related_exec_tag(related_tag)
        if parsed is None:
            # 保留原始 tag 便于 debug（不参与节点关系）
            node["related_exec"] = related_tag
            node["related_exec_node"] = ""
            continue

        rel_file, rel_line, rel_func = parsed
        rel_file_norm = _normalize_related_file_path(rel_file, project_path)
        if rel_file_norm is None:
            node["related_exec"] = related_tag
            node["related_exec_node"] = ""
            continue

        rel_node = _ensure_node(
            file_v=rel_file_norm,
            line_v=rel_line,
            end_line_v=rel_line,
            function_v=rel_func,
            reason_v="auto_generated_from_related_exec",
        )

        # 保留原始 tag，同时给出可用于建边的目标节点 id
        node["related_exec"] = related_tag
        node["related_exec_node"] = rel_node["sink_node_id"]

    return [node_by_id[nid] for nid in order]


def _build_flow_trees_from_sink_nodes(nodes: list[dict]) -> dict:
    """
    基于节点的 related_exec_node 与 sink_node_id 生成 FLOW 关系树（森林）。

    规则：
    - 如果节点 A 的 id 是相关点 related_exec_node，且相关节点存在于本次 nodes 集合中，
      则形成边：A -> [:FLOW] -> B（B 的 related_exec_node == A.id）
    - 如果 parent 不存在，则该节点作为 root（或森林中的独立树）。
    - 以树结构表达：root.children[...]
    """
    nodes_by_id: dict[str, dict] = {n["sink_node_id"]: n for n in nodes if n.get("sink_node_id")}
    children_by_parent: dict[str, list[str]] = {}

    def _safe_key(n: dict) -> tuple:
        # 排序 key：先 file 再 line 再 function，保证输出稳定
        return (n.get("file") or "", int(n.get("line") or 0), n.get("function") or "")

    roots: set[str] = set(nodes_by_id.keys())

    for nid, node in nodes_by_id.items():
        parent_id = node.get("related_exec_node") or ""
        if parent_id and parent_id in nodes_by_id and parent_id != nid:
            roots.discard(nid)
            children_by_parent.setdefault(parent_id, []).append(nid)

    # 为保证稳定输出，对每个父节点的 children 排序
    for parent_id, child_ids in children_by_parent.items():
        nodes_sorted = sorted((nodes_by_id[cid] for cid in child_ids), key=_safe_key)
        children_by_parent[parent_id] = [n["sink_node_id"] for n in nodes_sorted]

    def _build_subtree(nid: str, path: set[str]) -> dict:
        # 防止异常数据造成环
        if nid in path:
            return {"id": nid, "cycle": True, "children": []}

        node = nodes_by_id[nid]
        next_path = set(path)
        next_path.add(nid)

        child_ids = children_by_parent.get(nid, [])
        return {
            "id": nid,
            "file": node.get("file") or "",
            "line": node.get("line"),
            "end_line": node.get("end_line"),
            "function": node.get("function") or "",
            "reason": node.get("reason") or "",
            "children": [_build_subtree(cid, next_path) for cid in child_ids],
        }

    trees = [_build_subtree(rid, set()) for rid in sorted(roots, key=lambda x: _safe_key(nodes_by_id[x]))]
    return {"trees": trees, "roots": sorted(roots)}


def _enrich_and_overwrite_sink_result_file(
        brain: Brain,
        result_file_path: str,
        sink_res: list[dict],
        project_path: str,
) -> None:
    """
    按 file/line/end_line 使用 read_lines 读取代码片段（裁剪到文件范围内）：
    - 若 end_line - line <= 10：读取 [line-5, end_line+5]；
    - 若 end_line - line > 10：只读取 [line, line+10]，避免拉取长函数全文。
    将每个 sink 格式化为 key:value 文本块，块之间用 ----- 分隔，覆盖写入 result_file_path。
    """
    blocks: list[str] = []
    for item in sink_res:
        file_norm = _normalize_file_for_key(item["file"])
        line_v = int(item["line"])
        end_line_v = int(item["end_line"])
        abs_fp = os.path.normpath(os.path.join(project_path, file_norm))
        if end_line_v - line_v > 10:
            start_l = max(1, line_v)
            end_l = line_v + 10
        else:
            start_l = max(1, line_v - 5)
            end_l = end_line_v + 5
        code_text = ""
        try:
            raw = Path(abs_fp).read_text(encoding="utf-8")
            n = len(raw.splitlines())
        except OSError:
            n = 0
        if n > 0:
            sl = max(1, min(start_l, n))
            el = max(sl, min(end_l, n))
            tool_out = brain.run_tool(
                "read_lines",
                file_path=abs_fp,
                start_line=sl,
                end_line=el,
            )
            if tool_out.get("success"):
                data = tool_out.get("data") or []
                code_text = "\n".join(data) if isinstance(data, list) else str(data)
            else:
                code_text = f"[read_lines 失败: {tool_out.get('error', 'unknown')}]"
        lines_out: list[str] = []
        for k in ("file", "line", "end_line", "function", "related_exec", "reason"):
            lines_out.append(f"{k}: {item.get(k, '')}")
        lines_out.append("code:")
        lines_out.extend(code_text.split("\n") if code_text else [""])
        blocks.append("\n".join(lines_out))
    merged = "\n-----\n".join(blocks)
    with open(result_file_path, "w", encoding="utf-8") as f:
        f.write(merged)


class SinkFinder(BaseAgent):
    MODULE_NAME = "sink_finder"

    def __init__(self, brain: Optional[Brain] = None):
        super().__init__(brain)
        self.max_retries = 10
        # 混合模式已退役：不再使用 OpenCode

        # 提前终止：连续无发现轮次阈值
        self._early_stop_consecutive_empty = 4  # 连续4轮工具调用无实质发现则提前退出
        
        # 集成优化器
        from src.services.llm_optimizer import get_optimizer, Limiter
        from src.services.context_compressor import ContextCompressor
        self._optimizer = get_optimizer()
        self._optimizer.load_cache()
        self._limiter = Limiter(max_concurrent=3)
        # 延迟初始化上下文压缩器，避免在 brain 为 None 时出错
        self._context_compressor = None

    @staticmethod
    def _is_tool_result_substantive(tool_result: Any, tool_name: str) -> bool:
        """判断工具调用结果是否包含实质发现（非空结果）。

        用于提前终止机制：如果连续多轮工具调用都返回空结果，
        说明该漏洞类型在项目中可能不存在，可以提前退出。
        """
        if not isinstance(tool_result, dict):
            return tool_result is not None

        # success=False 的结果不算实质发现
        if not tool_result.get("success", True):
            return False

        # ripgrep / search 类工具：检查匹配数
        data = tool_result.get("data", tool_result)
        if isinstance(data, dict):
            # 匹配数为 0 或空列表
            matches = data.get("matches", data.get("results", data.get("lines", None)))
            if matches is not None:
                if isinstance(matches, (list, str)):
                    return len(matches) > 0
                return bool(matches)
            # 文件列表为空
            files = data.get("files", data.get("file_list", None))
            if files is not None:
                return len(files) > 0 if isinstance(files, list) else bool(files)

        # read_file / read_lines：有内容就算实质发现
        if tool_name.startswith("read_"):
            content = tool_result.get("content", tool_result.get("data", ""))
            if isinstance(content, str):
                return len(content.strip()) > 0
            return bool(content)

        # 默认：有结果就算实质发现
        return True

    def _build_quick_scan_hint(self, vul_name: str, language: str) -> str:
        """从快速扫描结果中提取与当前漏洞类型相关的线索，按需注入。"""
        if not self._brain or not hasattr(self._brain, "quick_scan_findings"):
            return ""
        qs_findings = self._brain.quick_scan_findings
        if not qs_findings:
            return ""

        # 漏洞类型关键词映射（中英文）
        vuln_keywords = {
            "命令注入": ["COMMAND_INJECTION", "命令注入", "命令执行"],
            "SQL注入": ["SQL_INJECTION", "SQL注入", "sql_injection"],
            "代码执行": ["CODE_INJECTION", "代码执行", "代码注入", "RCE"],
            "路径遍历": ["PATH_TRAVERSAL", "路径遍历", "目录遍历"],
            "XSS": ["XSS", "跨站脚本"],
            "SSRF": ["SSRF", "服务端请求伪造"],
            "XXE": ["XXE", "XML外部实体"],
            "反序列化": ["DESERIALIZATION", "反序列化"],
            "认证绕过": ["AUTH_BYPASS", "认证绕过"],
            "IDOR": ["IDOR", "越权"],
            "CSRF": ["CSRF"],
            "文件上传": ["FILE_UPLOAD", "文件上传"],
            "组件漏洞": ["COMPONENT_VULNERABILITY", "组件"],
        }

        # 找到匹配的关键词
        matched_keywords = set()
        for key, keywords in vuln_keywords.items():
            if key in vul_name:
                matched_keywords.update(keywords)
        # 也加入 vul_name 本身
        matched_keywords.add(vul_name)

        if not matched_keywords:
            return ""

        # 筛选匹配的快速扫描结果
        relevant = []
        for f in qs_findings:
            f_vuln = f.get("vuln_type", "")
            f_title = f.get("title", "")
            for kw in matched_keywords:
                if kw in f_vuln or kw in f_title:
                    relevant.append(f)
                    break

        if not relevant:
            return ""

        # 构建提示（限制数量避免上下文膨胀）
        hint = "\n\n## 快速扫描线索（规则引擎预扫描结果，仅供参考）\n"
        hint += "以下位置已被规则引擎标记为潜在风险点，请重点关注：\n"
        for f in relevant[:8]:
            location = f.get("location", f.get("file", ""))
            severity = f.get("severity", "")
            evidence = f.get("evidence", "")
            hint += f"- **{location}** [{severity}] {evidence}\n"
        hint += "\n注意：以上线索来自正则规则匹配，可能存在误报，请结合代码上下文验证。\n"
        return hint

    def _build_pattern_hint(self, vul_name: str, language: str) -> str:
        """从共享缓存（Orchestrator 已运行过的 PatternAnalyzer）提取相关线索。

        不再重复 os.walk + PatternAnalyzer — 避免每个 category 都触发完整扫描。
        """
        if not self._brain or not hasattr(self._brain, "pattern_analyzer_results"):
            return ""
        pa_result = self._brain.pattern_analyzer_results
        if not pa_result:
            return ""

        # 漏洞类型到英文映射（精简版）
        vuln_type_en_map = {
            "命令注入": "COMMAND_INJECTION", "命令执行": "COMMAND_INJECTION",
            "SQL注入": "SQL_INJECTION", "代码执行": "CODE_INJECTION",
            "代码注入": "CODE_INJECTION", "RCE": "CODE_INJECTION",
            "路径遍历": "PATH_TRAVERSAL", "目录遍历": "PATH_TRAVERSAL",
            "XSS": "XSS", "跨站脚本": "XSS",
            "SSRF": "SSRF", "服务端请求伪造": "SSRF",
            "XXE": "XXE", "XML外部实体": "XXE",
            "反序列化": "DESERIALIZATION", "不安全反序列化": "DESERIALIZATION",
            "认证绕过": "AUTH_BYPASS",
            "文件上传": "FILE_UPLOAD",
            "弱加密": "WEAK_CRYPTO", "弱哈希": "WEAK_HASH",
            "硬编码凭据": "HARDCODED_CREDENTIALS", "硬编码密码": "HARDCODED_CREDENTIALS",
            "开放重定向": "OPEN_REDIRECT",
            "JWT": "JWT_VULNERABILITIES",
            "SSTI": "SSTI", "JNDI": "JNDI_INJECTION",
            "日志注入": "LOG_INJECTION", "信息泄露": "INFORMATION_DISCLOSURE",
            "竞态条件": "RACE_CONDITION", "缓冲区溢出": "BUFFER_OVERFLOW",
        }

        matched_types: set[str] = set()
        for key, en_type in vuln_type_en_map.items():
            if key.lower() in vul_name.lower() or vul_name.lower() in key.lower():
                matched_types.add(en_type)
        matched_types.add(vul_name.upper().replace(" ", "_").replace("/", "_"))

        if not matched_types:
            return ""

        # 从缓存中提取匹配的发现
        import os as _os
        matched_files: dict = {}
        for r in pa_result.get("results", []):
            for f in r.get("findings", []):
                f_type = f.get("vuln_type", "")
                if f_type in matched_types:
                    fp = f.get("file_path", "")
                    if fp and fp not in matched_files:
                        matched_files[fp] = (f.get("line", 0), f.get("severity", "MEDIUM"), f.get("evidence", "")[:60])
                        if len(matched_files) >= 10:
                            break
            if len(matched_files) >= 10:
                break

        if not matched_files:
            return ""

        hint = "\n\n## 代码模式分析线索（独立模式匹配引擎，无需 sink 点）\n"
        hint += "以下代码位置检测到了与当前漏洞类型相关的危险模式：\n"
        for fp, (line, severity, evidence) in matched_files.items():
            hint += f"- **{_os.path.basename(fp)}:{line}** [{severity}] `{evidence}`\n"
        hint += "\n注意：以上线索来自预扫描的 PatternAnalyzer 缓存，无需 sink 点即可能发现问题。\n"
        return hint

    def _build_gapfill_hint(self, vul_name: str) -> str:
        """从防漏报兜底任务中提取与当前漏洞类型相关的盲区提示，按需注入。"""
        if not self._brain or not hasattr(self._brain, "gapfill_tasks"):
            return ""
        gapfill_tasks = self._brain.gapfill_tasks
        if not gapfill_tasks:
            return ""

        # 漏洞类型关键词映射
        vuln_keywords = {
            "命令注入": ["COMMAND_INJECTION", "命令注入"],
            "SQL注入": ["SQL_INJECTION", "SQL注入"],
            "代码执行": ["CODE_INJECTION", "代码执行"],
            "路径遍历": ["PATH_TRAVERSAL", "路径遍历"],
            "XSS": ["XSS", "跨站脚本"],
            "SSRF": ["SSRF"],
            "XXE": ["XXE"],
            "反序列化": ["DESERIALIZATION", "反序列化"],
            "认证绕过": ["AUTH_BYPASS", "认证绕过"],
            "CSRF": ["CSRF"],
            "硬编码密钥": ["HARD_CODED_SECRET", "硬编码"],
            "弱加密": ["WEAK_CRYPTO", "弱加密"],
        }

        matched_keywords = set()
        for keywords in vuln_keywords.values():
            if any(kw in vul_name for kw in keywords):
                matched_keywords.update(keywords)

        if not matched_keywords:
            return ""

        relevant = []
        for task in gapfill_tasks:
            attack_class = task.get("attackClass", "")
            if any(kw in attack_class for kw in matched_keywords):
                relevant.append(task)

        if not relevant:
            return ""

        hint = "\n\n## 防漏报盲区提示（覆盖率追踪发现的未检查区域）\n"
        hint += "以下区域在当前审计中尚未被充分覆盖，请额外关注：\n"
        for task in relevant[:5]:
            target = task.get("targetFile", task.get("subsystem", ""))
            attack = task.get("attackClass", "")
            reason = task.get("reason", "")
            hint += f"- **{target}** 缺少 {attack} 检查 ({reason})\n"
        hint += "\n注意：以上是覆盖率分析发现的盲区，请确保这些区域得到审查。\n"
        return hint

    def _build_rag_hint(self, vul_name: str) -> str:
        """从 RAG 服务按需检索与当前漏洞类型相关的知识文档。"""
        try:
            from src.services.rag_service import get_rag_service
            rag = get_rag_service()
            results = rag.query(vul_name, top_k=3)
            if not results:
                return ""
            hint = "\n\n## 相关安全知识（RAG 检索）\n"
            for doc in results[:3]:
                title = doc.get("title", "")
                content = doc.get("content", "")
                if content and len(content) > 300:
                    content = content[:300] + "..."
                hint += f"- **{title}**: {content}\n"
            return hint
        except Exception:
            return ""

    def run(self, language, vul_name, vul_node_id, reasoning_basis, risk_description):
        # 注入知识库语言审计规则
        lang_ext = f".{language.lower()}" if not language.startswith(".") else language.lower()
        lang_rules = LANGUAGE_AUDIT_RULES_LLM.get(lang_ext, "")
        system_content = sink_finder_prompt
        if lang_rules:
            system_content += "\n\n" + lang_rules

        # 注入框架特定漏洞规则（仅注入与当前漏洞类型相关的危险模式）
        lang_key = language.lower().lstrip(".")
        dangerous = get_dangerous_patterns(lang_key)
        if dangerous:
            vuln_to_danger = {
                "命令注入": "command_exec", "命令执行": "command_exec",
                "SQL注入": "sql_injection_risk", "sql_injection": "sql_injection_risk",
                "反序列化": "deserialization", "不安全反序列化": "deserialization",
                "XXE": "xxe", "XML外部实体": "xxe",
                "SSRF": "ssrf", "服务端请求伪造": "ssrf",
                "代码执行": "code_exec", "远程代码执行": "code_exec", "RCE": "code_exec",
                "路径遍历": "path_traversal", "目录遍历": "path_traversal",
                "XSS": "xss", "跨站脚本": "xss",
                "文件上传": "file_upload",
            }
            matched_cats = set()
            for vul_keyword, cat in vuln_to_danger.items():
                if vul_keyword in vul_name and cat in dangerous:
                    matched_cats.add(cat)
            if matched_cats:
                danger_hint = "\n## 该语言相关危险模式\n"
                for cat in matched_cats:
                    patterns = dangerous[cat]
                    danger_hint += f"- **{cat}**: {', '.join(patterns[:5])}\n"
                system_content += danger_hint

        # 注入快速检索规则
        grep_rules = get_grep_rules(vul_name)
        if grep_rules:
            grep_hint = "\n## 快速检索规则\n"
            for rule in grep_rules[:5]:
                grep_hint += f"- `{rule['pattern']}`: {rule['description']}\n"
            system_content += grep_hint

        # 注入 Source→Sink→Safety 检测模式（按需，仅匹配当前语言和漏洞类型）
        detection_hint = format_detection_patterns_for_prompt(lang_key, vul_name)
        if detection_hint:
            system_content += detection_hint

        # 注入语言专属检查清单（按需，仅匹配当前语言）
        lang_checklist = get_language_checklist(lang_key)
        if lang_checklist:
            system_content += "\n\n" + lang_checklist

        # 注入快速扫描线索（按需，仅匹配当前漏洞类型）
        quick_scan_hint = self._build_quick_scan_hint(vul_name, language)
        if quick_scan_hint:
            system_content += quick_scan_hint

        # 注入 PatternAnalyzer 模式匹配线索（从缓存读取，无需重复扫描）
        pattern_hint = self._build_pattern_hint(vul_name, language)
        if pattern_hint:
            system_content += pattern_hint
            self._publish_log("DEBUG",
                              f"[SinkFinder] PatternAnalyzer 缓存命中 {vul_name}")

        # 注入漏洞类型审计指南（框架感知检测矩阵、危险模式示例、CWE/国标）
        try:
            from src.knowledge.audit_vulnerability_guides import get_vulnerability_guide
            vul_guide = get_vulnerability_guide(vul_name)
            if vul_guide:
                system_content += "\n\n" + vul_guide
        except Exception:
            pass

        msg = [
            {"role": "system",
             "content": system_content},
            {"role": "user", "content": "项目信息：\n" + self._brain.project_info},
            {"role": "user",
             "content": f"本次审计**目标**：\n语言：{language}\n漏洞类型：{vul_name} \n漏洞描述：{risk_description}\n相关依据:{reasoning_basis}"}
        ]
        result_file_path = str(self._brain.tmp_dir / f"{generate_uuid()}.txt")
        sink_res = []

        sink_finder_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.SINK_DISCOVERY,
            reason=f"开始寻找 {language} 语言的 {vul_name} 类型的sink触发点",
        )
        self._publish_log(
            "INFO",
            f"[SinkFinder] 开始 sink 发现 | language={language} vul_name={vul_name} "
            f"vul_node_id={vul_node_id}",
        )

        # ── 直接使用 LLM 多轮工具循环发现 sink（不再使用 OpenCode）──
        self._publish_log(
            "INFO",
            f"[SinkFinder] 使用 LLM 多轮工具循环 | language={language} vul_name={vul_name}",
        )
        msg = [
            {"role": "system",
             "content": system_content},
            {"role": "user", "content": "项目信息：\n" + self._brain.project_info},
            {"role": "user",
             "content": f"本次审计**目标**：\n语言：{language}\n漏洞类型：{vul_name} \n漏洞描述：{risk_description}\n相关依据:{reasoning_basis}"}
        ]
        result_file_path = str(self._brain.tmp_dir / f"{generate_uuid()}.txt")
        sink_res = []
        input_tokens, output_tokens = 0, 0
        consecutive_empty_rounds = 0
        for step in range(self.max_retries):
                ensure_task_running(self._brain.task_id)
                self._publish_log(
                    "INFO",
                    f"[SinkFinder] LLM 轮次 {step + 1}/{self.max_retries}",
                )
                try:
                    res, input_tokens, output_tokens = self._llm_step(msg)
                except LLMError:
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    sink_finder_span.mark_failed("LLM 调用发生致命错误")
                    raise
                except ValueError as e:
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    msg.append({"role": "assistant", "content": "(模型返回内容无法解析为JSON)"})
                    msg.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_JSON",
                            "detail": str(e),
                            "requirement": "请严格按统一输出协议只返回JSON对象"
                        }, ensure_ascii=False)
                    })
                    continue
                except Exception as e:
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    tb = traceback.format_exc()
                    tail = tb[-4000:] if len(tb) > 4000 else tb
                    self._publish_log("ERROR", f"[SinkFinder] LLM 调用异常: {e!r}\n{tail}")
                    raise RuntimeError(f"调用 LLM 时发生错误: {e}") from e

                if res is None:
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log("WARNING", f"[SinkFinder] LLM 返回为空，重试 ({step + 1}/{self.max_retries})")
                    continue

                next_action = (res or {}).get("next_action", {}) or {}
                action_type = next_action.get("type", "")

                # ---- 工具调用（兼容 LLM 将工具名误设为 action_type） ----
                if action_type == "tool_call" or action_type in {"ripgrep_search", "read_file", "read_lines",
                        "ripgrep_files", "list_files", "code_search", "class_hierarchy", "remote_repo",
                        "code_agent", "ripgrep", "search", "grep", "read", "cat", "list", "ls",
                        "list_directory", "dir"}:
                    if action_type != "tool_call":
                        self._publish_log(
                            "INFO",
                            f"[SinkFinder] 自动修正 action_type={action_type!r} → tool_call (tool_name={action_type!r})",
                        )
                        next_action["type"] = "tool_call"
                        next_action.setdefault("tool_name", action_type)
                    tool_name = next_action.get("tool_name", "")
                    if not tool_name:
                        sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                        msg.append({
                            "role": "user",
                            "content": json.dumps({
                                "error": "MISSING_TOOL_NAME",
                                "requirement": "tool_call 需要提供 tool_name"
                            }, ensure_ascii=False)
                        })
                        continue

                    self._publish_log("INFO", f"[SinkFinder] 调用工具 {tool_name!r} (轮 {step + 1})")
                    tool_span = start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.TOOL_CALL,
                        tool_name=tool_name,
                        reason=f"调用 {tool_name} 工具",
                        tool_arguments=next_action.get('arguments', {}) or {},
                    )
                    # 使用并发限制器执行工具调用
                    tool_result = self._limiter(self._execute_tool_call, next_action, msg, tool_span)
                    tool_span.set_output(json.dumps(tool_result, ensure_ascii=False, default=str))
                    tool_span.add_llm_tokens(input_tokens, output_tokens)
                    if tool_result is None:
                        tool_span.mark_failed("工具调用未返回结果")
                    else:
                        tool_span.finish()
                    if tool_result is not None:
                        msg.append({
                            "role": "user",
                            "content": json.dumps({
                                "status": "TOOL_RESULT",
                                "tool_name": tool_name,
                                "result": tool_result,
                            }, ensure_ascii=False, default=str),
                        })
                        if self._is_tool_result_substantive(tool_result, tool_name):
                            consecutive_empty_rounds = 0
                        else:
                            consecutive_empty_rounds += 1
                    else:
                        consecutive_empty_rounds += 1

                    # 提前终止：连续多轮工具调用无实质发现
                    if consecutive_empty_rounds >= self._early_stop_consecutive_empty:
                        self._publish_log(
                            "INFO",
                            f"[SinkFinder] 提前终止 | 连续 {consecutive_empty_rounds} 轮工具调用无实质发现",
                        )
                        _info_span = start_event_span(
                            task_id=self._brain.task_id,
                            module=self.MODULE_NAME,
                            action_type=ActionType.INFORMATION,
                            reason=f"{language} 语言的 {vul_name} 类型连续{consecutive_empty_rounds}轮无发现，提前终止",
                        )
                        _info_span.finish()
                        break
                    continue

                # ---- final：LLM 直接产出 sink JSON 数组 ----
                if action_type == "final":
                    final_output = res.get("final_output")
                    if not isinstance(final_output, list):
                        self._publish_log("WARNING", "[SinkFinder] final 缺少有效的 final_output 数组")
                        msg.append({
                            "role": "user",
                            "content": json.dumps({
                                "error": "FINAL_WITHOUT_OUTPUT",
                                "requirement": "type=final 时 final_output 必须是 JSON 数组",
                            }, ensure_ascii=False),
                        })
                        continue

                    self._publish_log("INFO", f"[SinkFinder] LLM 返回 final，sink 候选={len(final_output)}")
                    normalized, err = _validate_and_normalize_sink_res(final_output, self._brain.project_path)
                    if err:
                        self._publish_log(
                            "WARNING",
                            f"[SinkFinder] sink 格式校验失败 | code={err.get('code')} "
                            f"field={err.get('field')} message={err.get('message')}",
                        )
                        fix_detail = json.dumps({
                            "error": "INVALID_SINK_FORMAT",
                            "validation": err,
                            "schema_hint": _SINK_RES_SCHEMA_HINT,
                            "requirement": "请修正上述 sink 项后重新输出 final",
                        }, ensure_ascii=False)
                        msg.append({"role": "user", "content": fix_detail})
                        continue

                    self._publish_log("INFO", f"[SinkFinder] sink 校验通过 | count={len(normalized)}")
                    _info_span = start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"{language} 语言的 {vul_name} 类型共发现{len(normalized)}条sink点",
                    )
                    _info_span.finish()
                    sink_res = normalized
                    break

                # ---- 无效 action_type ----
                sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                self._publish_log(
                    "WARNING",
                    f"[SinkFinder] 无效 next_action.type={action_type!r} (轮 {step + 1})",
                )
                msg.append({"role": "assistant", "content": json.dumps(res, ensure_ascii=False)})
                msg.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "INVALID_NEXT_ACTION",
                        "requirement": "next_action.type 只能是 tool_call 或 final"
                    }, ensure_ascii=False)
                })
                continue

        if not sink_res:
            self._publish_log(
                "WARNING",
                f"[SinkFinder] 主循环结束但未发现有效 sink | max_retries={self.max_retries}",
            )

        # ── 混合模式增强已移除（不再使用 OpenCode）──

        if sink_res:
            sink_res_backup = deepcopy(sink_res)
            _enrich_and_overwrite_sink_result_file(
                self._brain, result_file_path, sink_res, self._brain.project_path
            )
            self._publish_log(
                "INFO",
                f"[SinkFinder] 开始精炼 | candidates={len(sink_res_backup)} evidence={result_file_path}",
            )
            try:
                refiner = SinkRefineAgent(self._brain)
                sink_res = refiner.run(
                    os.path.abspath(result_file_path),
                    language,
                    vul_name,
                    sink_res_backup,
                )
            except LLMError:
                raise
            except Exception as e:
                self._publish_log(
                    "WARNING",
                    f"[SinkFinder] 精炼失败，回退原始结果: {e!r}",
                )
                sink_res = sink_res_backup

        sink_nodes = _postprocess_sink_res_expand_related_nodes(sink_res, self._brain.project_path)
        flow = _build_flow_trees_from_sink_nodes(sink_nodes)
        self._publish_log(
            "INFO",
            f"[SinkFinder] 后处理完成 | nodes={len(sink_nodes)} trees={len(flow.get('trees') or [])} "
            f"roots={len(flow.get('roots') or [])}",
        )
        persist_sink_flow_to_neo4j(vul_node_id, sink_nodes, flow, self._brain.task_id)
        self._publish_log(
            "INFO",
            f"[SinkFinder] 已落库 Neo4j 并标记完成 | vul_node_id={vul_node_id}",
        )
        mark_risk_category_sink_finder_completed(vul_node_id)
        self._report_cache_stats(self._brain.task_id)
        sink_finder_span.finish()
        return {"nodes": sink_nodes, **flow}


def _read_sink_evidence_file_text(abs_path: str) -> str:
    """读取 enrich 后的 sink 证据文件全文，供 SinkRefineAgent 直接写入提示词。"""
    if not os.path.isfile(abs_path):
        return f"[错误：证据文件不存在或不是普通文件: {abs_path}]"
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        return f"[错误：无法读取证据文件: {e}]"


class SinkRefineAgent(BaseAgent):
    """
    Sink 精炼 Agent。

    在证据文件（enrich 后的纯文本）上使用 Brain + 工具循环，筛选并整理 sink，
    输出与发现阶段同构的 JSON 列表。与 Chain 系 Agent 一致，继承 BaseAgent 以复用
    工具执行与日志前缀等公共能力。
    """
    MODULE_NAME = "sink_finder"
    # 精炼阶段不暴露的工具（其余以注册表为准，全部加入 schema 与可调用集合）
    _EXCLUDED_TOOLS = frozenset({"code_agent"})

    DEFAULT_MAX_STEPS = 25

    def __init__(self, brain: Optional[Brain] = None, max_steps: int = DEFAULT_MAX_STEPS):
        super().__init__(brain=brain)
        self.max_steps = max_steps

    def run(
            self,
            result_file_abs: str,
            language: str,
            vul_name: str,
            fallback_sink_res: list[dict],
    ) -> list[dict]:
        if not self._brain:
            return fallback_sink_res

        reg = self._brain.tool_registry
        registry_schema = reg.get_tools_schema_excluding(self._EXCLUDED_TOOLS)
        evidence_path = os.path.normpath(os.path.abspath(result_file_abs))
        evidence_text = _read_sink_evidence_file_text(evidence_path)
        conversation: List[Dict[str, Any]] = [
            {
                "role": "system",
                "content": build_sink_refine_system_prompt(registry_schema),
            },
            {
                "role": "user",
                "content": (
                    f"[任务输入]\n"
                    f"- 编程语言: {language}\n"
                    f"- 漏洞类型/描述: {vul_name}\n\n"
                    f"## sink 候选证据文件（全文）\n"
                    f"{evidence_text}\n\n"
                    f"---\n\n"
                    f"项目概览（供核对路径与语义）:\n{self._brain.project_info_compact}\n"
                ),
            },
        ]

        project_path = self._brain.project_path
        out: list[dict] = list(fallback_sink_res)

        sink_refine_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.SINK_REFINE,
            reason=f"开始对 {language} 语言的 {vul_name} 类型的sink触发点进行初步处理",
        )
        self._publish_log(
            "INFO",
            f"[SinkRefineAgent] 开始精炼 | language={language} vul_name={vul_name} "
            f"candidates={len(fallback_sink_res)} evidence={evidence_path}",
        )
        input_tokens, output_tokens = 0, 0
        for _round_num in range(1, self.max_steps + 1):
            ensure_task_running(self._brain.task_id)
            self._publish_log(
                "INFO",
                f"[SinkRefineAgent] LLM 轮次 {_round_num}/{self.max_steps}",
            )
            try:
                step, input_tokens, output_tokens = self._llm_step(conversation)
            except LLMError:
                sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
                sink_refine_span.mark_failed("LLM 调用发生致命错误")
                raise
            except ValueError as e:
                sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
                conversation.append({"role": "assistant", "content": "(模型返回内容无法解析为JSON)"})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "INVALID_JSON",
                        "detail": str(e),
                    }, ensure_ascii=False),
                })
                continue
            except Exception as e:
                tb = traceback.format_exc()
                tail = tb[-4000:] if len(tb) > 4000 else tb
                self._publish_log(
                    "ERROR",
                    f"[SinkRefineAgent] LLM 调用异常: {e!r}\n{tail}",
                )
                raise RuntimeError(f"SinkRefineAgent 调用 LLM 失败: {e}") from e

            if step is None:
                self._publish_log(
                    "WARNING",
                    f"[SinkRefineAgent] LLM 返回为空，重试 ({_round_num}/{self.max_steps})",
                )
                continue

            envelope = step if isinstance(step, dict) else None
            content = json.dumps(step, ensure_ascii=False)
            if envelope is None:
                sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
                self._publish_log(
                    "WARNING",
                    f"[SinkRefineAgent] 顶层非 JSON 对象 (轮 {_round_num})",
                )
                conversation.append({"role": "assistant", "content": content})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "INVALID_ENVELOPE",
                        "detail": "顶层必须是 JSON 对象",
                    }, ensure_ascii=False),
                })
                continue

            next_action = (envelope.get("next_action") or {}) if isinstance(envelope, dict) else {}
            action = (next_action or {}).get("type", "")

            # 兼容 LLM 将工具名误设为 action_type
            _known_tools_for_fallback = {"ripgrep_search", "read_file", "read_lines",
                "ripgrep_files", "list_files", "code_search", "class_hierarchy", "remote_repo",
                "code_agent", "ripgrep", "search", "grep", "read", "cat", "list", "ls",
                "list_directory", "dir"}
            if action != "tool_call" and action != "final" and action in _known_tools_for_fallback:
                self._publish_log(
                    "INFO",
                    f"[SinkRefineAgent] 自动修正 action_type={action!r} → tool_call",
                )
                next_action["type"] = "tool_call"
                next_action.setdefault("tool_name", action)
                action = "tool_call"

            if action == "tool_call":
                tool_name = (next_action or {}).get("tool_name", "") or ""
                if tool_name == "":
                    sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[SinkRefineAgent] tool_call 缺少 tool_name (轮 {_round_num})",
                    )
                    allowed = sorted(n for n in reg.list_names() if n not in self._EXCLUDED_TOOLS)
                    conversation.append({"role": "assistant", "content": content})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_TOOL",
                            "detail": f"须为已注册且未排除的工具；当前可用: {allowed}；排除: {sorted(self._EXCLUDED_TOOLS)}",
                        }, ensure_ascii=False),
                    })
                    continue

                arguments = dict((next_action or {}).get("arguments") or {})
                self._publish_log(
                    "INFO",
                    f"[SinkRefineAgent] 调用工具 {tool_name!r} (轮 {_round_num}) | "
                    f"args_keys={list(arguments.keys())}",
                )
                tool_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.TOOL_CALL,
                    tool_name=tool_name,
                    reason=f"调用 {tool_name} 工具",
                    tool_arguments=arguments,
                )
                conversation.append({"role": "assistant", "content": content})
                # 使用并发限制器执行工具调用
                tool_result = self._limiter(self._execute_tool_call,
                    {"tool_name": tool_name, "arguments": arguments},
                    conversation,
                    tool_span,
                )
                if tool_result is None:
                    tool_result = {
                        "success": False,
                        "error": "工具调用未返回结果",
                        "data": None,
                        "meta": {},
                    }
                    self._publish_log(
                        "WARNING",
                        f"[SinkRefineAgent] 工具 {tool_name!r} 未返回结果 (轮 {_round_num})",
                    )
                    tool_span.set_output(json.dumps(tool_result))
                    tool_span.mark_failed("工具调用未返回结果")
                else:
                    success = tool_result.get("success", False) if isinstance(tool_result, dict) else False
                    if not success:
                        self._publish_log(
                            "WARNING",
                            f"[SinkRefineAgent] 工具 {tool_name!r} 执行失败 (轮 {_round_num}) | "
                            f"error={tool_result.get('error') if isinstance(tool_result, dict) else tool_result!r}",
                        )
                    else:
                        self._publish_log(
                            "INFO",
                            f"[SinkRefineAgent] 工具 {tool_name!r} 执行成功 (轮 {_round_num})",
                        )
                    tool_span.set_output(json.dumps(tool_result))
                    tool_span.finish()

                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "tool": tool_name,
                        "result": tool_result,
                    }, ensure_ascii=False),
                })
                tool_span.finish()
                continue

            if action == "final":
                sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
                sinks = envelope.get("sinks")
                if not isinstance(sinks, list):
                    self._publish_log(
                        "WARNING",
                        f"[SinkRefineAgent] final 缺少 sinks 数组 (轮 {_round_num})",
                    )
                    conversation.append({"role": "assistant", "content": content})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "MISSING_SINKS",
                            "detail": "final 时须包含 sinks 数组",
                        }, ensure_ascii=False),
                    })
                    continue
                normalized, err = _validate_and_normalize_sink_res(sinks, project_path)
                if err:
                    self._publish_log(
                        "WARNING",
                        f"[SinkRefineAgent] final sinks 校验失败 (轮 {_round_num}) | "
                        f"code={err.get('code')} message={err.get('message')}",
                    )
                    conversation.append({"role": "assistant", "content": content})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_SINKS",
                            "detail": err,
                        }, ensure_ascii=False),
                    })
                    continue
                self._publish_log(
                    "INFO",
                    f"[SinkRefineAgent] 精炼完成 | before={len(fallback_sink_res)} after={len(normalized)}",
                )
                _info_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=f"{language} 语言的 {vul_name} 类型sink点经过处理剩余{len(normalized)}条",
                )
                _info_span.finish()
                self._report_cache_stats(self._brain.task_id)
                sink_refine_span.finish()
                return normalized

            sink_refine_span.add_llm_tokens(input_tokens, output_tokens)
            self._publish_log(
                "WARNING",
                f"[SinkRefineAgent] 无效 next_action.type={action!r} (轮 {_round_num})",
            )
            conversation.append({"role": "assistant", "content": content})
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "INVALID_NEXT_ACTION",
                    "detail": "next_action.type 须为 tool_call 或 final",
                }, ensure_ascii=False),
            })

        self._publish_log(
            "WARNING",
            f"[SinkRefineAgent] 已达最大轮次 {self.max_steps}，回退 fallback | count={len(out)}",
        )
        self._report_cache_stats(self._brain.task_id)
        sink_refine_span.finish()
        return out
