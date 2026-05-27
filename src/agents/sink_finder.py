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
from src.agents.brain import Brain
from src.agents.prompt.sink_finder import sink_finder_prompt
from src.agents.prompt.sink_finder_refine import build_sink_refine_system_prompt
from services.plan_service import mark_risk_category_sink_finder_completed
from services.sink_flow_service import persist_sink_flow_to_neo4j
from src.utils.ids import generate_uuid
from src.utils.json_parse import parse_json

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

    def run(self, language, vul_name, vul_node_id, reasoning_basis, risk_description):
        msg = [
            {"role": "system",
             "content": sink_finder_prompt},
            {"role": "user", "content": "项目信息：\n" + self._brain.project_info},
            {"role": "user",
             "content": f"本次审计**目标**：\n语言：{language}\n漏洞类型：{vul_name} \n漏洞描述：{risk_description}\n相关依据:{reasoning_basis}"}
        ]
        # code_agent = self._brain.get_tool("code_agent")
        # code_agent_sid = code_agent.fork(self._brain.get_project_info_session_id())
        code_agent_sid = ""
        result_file_path = str(self._brain.tmp_dir / f"{generate_uuid()}.txt")

        sink_res = []

        def _build_tool_msg(base_msg: str) -> str:
            goal_msg = f'''[约束]
本任务中的结果项表示“安全待检查点”，不是狭义最终 sink，也不是所有经过数据流的中间节点。

仅输出在目标漏洞语义下具有独立审查价值的代码位置。一个位置只有在满足以下任一条件时才应输出：
- 动态数据、资源标识、控制条件、状态变更或敏感操作在此形成了可独立审查的完整安全语义；
- 该位置与后续安全关键执行点存在直接语义关联，且其风险原因可被清晰说明；
- 该位置承载了关键约束、边界判定、危险构造或缓解失效的核心语义。

请避免以下情况：
- 不要把函数/方法定义行作为结果，除非函数定义本身就是最小必要的安全语义承载点；
- 不要把普通中间变量、局部赋值、纯拼接子表达式拆分成多个结果；
- 不要仅因某函数参与数据流就将其作为结果；
- 对同一条风险语义链，只保留最接近语义闭合、最利于人工审查的位置。\n[目标]针对{language}代码，以\"{vul_name}\"为目标做语义驱动的 sink 发现，借助\"GitNexus\"工具，找出所有可能的sink点。不要调用子代理。\n\n[指令]'''
            return goal_msg + base_msg

        def _run_code_agent_once(tool_name: str, session_id: str, tool_msg: str, event_span: EventSpan):
            arguments = {
                "msg": tool_msg,
                "session_id": session_id,
                "result_file_flag": True,
                "result_file_path": result_file_path,
                "output": """格式：
[
  {
    "file": 项目根目录的相对路径,
    "line": 起始行号,
    "end_line": 结束行号,
    "function": 如果位于方法内则填写 function_name，否则为空,
    "related_exec": "(项目根目录的相对路径)file:line:function_name" 当前节点在项目内部调用链中直接关联的下一个安全关键操作位置（仅保留语义层关键点，不包含底层引擎调用,如果是方法调用则应该是该方法源码所在的位置）可以为空,
    "reason": 原因说明
  },
  ...
]
【related_exec 填写规则】
1. 方向性约束：related_exec 必须指向当前函数体内**直接调用**的下一个安全关键操作，绝不可填写“谁调用了当前函数”（上游调用者）。
2. 验证步骤：填写前必须逐行检查当前函数体内的所有函数调用语句，确认是否存在安全关键调用。
3. 空值条件：若当前函数体内未调用任何安全关键函数，related_exec 必须为空字符串 ""。
4. 禁止推断：不得根据函数名或上下文猜测调用关系，必须以代码中实际存在的调用语句为准。
""",
            }
            return self._run_code_agent(tool_name, arguments, event_span)

        def _run_code_agent_repair_once(tool_name: str, session_id: str, fix_detail: str, event_span: EventSpan):
            repair_msg = "请根据以下错误信息修复结果并重新生成：\n" + fix_detail
            arguments = {
                "msg": repair_msg,
                "session_id": session_id,
            }
            return self._run_code_agent(tool_name, arguments, event_span)

        sink_finder_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.SINK_DISCOVERY,
            reason=f"开始寻找 {language} 语言的 {vul_name} 类型的sink触发点",
        )
        self._publish_log(
            "INFO",
            f"[SinkFinder] 开始 sink 发现 | language={language} vul_name={vul_name} "
            f"vul_node_id={vul_node_id} result_file={result_file_path}",
        )
        input_tokens, output_tokens = 0, 0
        for step in range(self.max_retries):
            ensure_task_running(self._brain.task_id)
            self._publish_log(
                "INFO",
                f"[SinkFinder] LLM 轮次 {step + 1}/{self.max_retries}",
            )
            try:
                res, input_tokens, output_tokens = self._llm_step(msg)
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
                self._publish_log(
                    "ERROR",
                    f"[SinkFinder] LLM 调用异常: {e!r}\n{tail}",
                )
                raise RuntimeError(f"调用 LLM 时发生错误: {e}") from e
            if res is None:
                sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                self._publish_log(
                    "WARNING",
                    f"[SinkFinder] LLM 返回为空，重试 ({step + 1}/{self.max_retries})",
                )
                continue
            # ask() 成功时返回解析后的 dict/list
            envelope = res

            # 2) 读 next_action
            next_action = (envelope or {}).get("next_action", {}) or {}
            action_type = next_action.get("type", "")

            # 3) 如果 tool_call：执行工具
            if action_type == "tool_call":
                tool_name = next_action.get("tool_name", "")
                if tool_name != "code_agent":
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[SinkFinder] 非法工具调用 tool_name={tool_name!r}，仅允许 code_agent",
                    )
                    msg.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_TOOL_Arguments",
                            "detail": "tool调用错误，只允许code_agent",
                            "requirement": "tool调用错误，只允许code_agent"
                        }, ensure_ascii=False)
                    })
                    continue
                arguments = next_action.get("arguments") or {}
                tool_msg = arguments.get("msg", "")
                if tool_msg == "":
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log("WARNING", "[SinkFinder] code_agent 调用缺少 msg 参数")
                    msg.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "INVALID_TOOL_Arguments",
                            "detail": "msg 参数缺失或为空",
                            "requirement": "msg参数错误"
                        }, ensure_ascii=False)
                    })
                    continue

                self._publish_log(
                    "INFO",
                    f"[SinkFinder] 调用 code_agent | result_file={result_file_path} "
                    f"msg_preview={tool_msg[:200]}{'...' if len(tool_msg) > 200 else ''}",
                )
                code_agent_span = start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.TOOL_CALL,
                    tool_name="code_agent",
                    reason=tool_msg,
                    tool_arguments={"msg": tool_msg},
                )
                # 4.1 先把assistant输出记录进对话
                msg.append({"role": "assistant", "content": json.dumps(res, ensure_ascii=False)})
                tool_msg = _build_tool_msg(tool_msg)
                tool_msg = f"项目基本信息：{self._brain.project_info_compact}\n" + tool_msg
                # 4.2 调用工具（统一返回dict）
                try:
                    tool_result = _run_code_agent_once(tool_name, code_agent_sid, tool_msg, code_agent_span)
                except Exception as e:
                    sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
                    self._publish_log(
                        "WARNING",
                        f"[SinkFinder] code_agent 执行异常: {e!r}",
                    )
                    msg.append({
                        "role": "user",
                        "content": json.dumps({
                            "error": "TOOL_EXECUTION_FAILED",
                            "detail": str(e),
                        }, ensure_ascii=False)
                    })
                    continue

                repair_success = False
                for repair_round in range(1, self.max_retries + 1):
                    if not tool_result.get("success", False):
                        self._publish_log(
                            "WARNING",
                            f"[SinkFinder] code_agent 未成功 (修复轮 {repair_round}) | "
                            f"error={tool_result.get('error')!r}",
                        )
                        fix_detail = json.dumps({
                            "error": "TOOL_EXECUTION_UNSUCCESSFUL",
                            "detail": tool_result.get("error", None) or "tool returned success=False",
                        }, ensure_ascii=False)
                        try:
                            tool_result = _run_code_agent_repair_once(tool_name, code_agent_sid, fix_detail, code_agent_span)
                            continue
                        except Exception as e:
                            code_agent_span.mark_failed(str(e))
                            msg.append({
                                "role": "user",
                                "content": json.dumps({
                                    "error": "TOOL_EXECUTION_FAILED",
                                    "detail": str(e),
                                }, ensure_ascii=False)
                            })
                            break

                    if not os.path.exists(result_file_path):
                        self._publish_log(
                            "WARNING",
                            f"[SinkFinder] 结果文件不存在 (修复轮 {repair_round}) | path={result_file_path}",
                        )
                        fix_detail = json.dumps({
                            "error": "RESULT_FILE_MISSING",
                            "detail": f"结果文件不存在,是否是不存在sink，如果不存在则写入空的数组结果到结果文件中: {result_file_path}",
                        }, ensure_ascii=False)
                        try:
                            tool_result = _run_code_agent_repair_once(tool_name, code_agent_sid, fix_detail, code_agent_span)
                            continue
                        except Exception as e:
                            code_agent_span.mark_failed(str(e))
                            msg.append({
                                "role": "user",
                                "content": json.dumps({
                                    "error": "TOOL_EXECUTION_FAILED",
                                    "detail": str(e),
                                }, ensure_ascii=False)
                            })
                            break

                    try:
                        with open(result_file_path, "r", encoding="utf-8") as f:
                            raw_sink_res = parse_json(f.read())
                    except (ValueError, OSError) as e:
                        self._publish_log(
                            "WARNING",
                            f"[SinkFinder] 结果文件解析失败 (修复轮 {repair_round}) | "
                            f"path={result_file_path} err={e!r}",
                        )
                        fix_detail = json.dumps({
                            "error": "RESULT_FILE_READ_FAILED",
                            "detail": str(e),
                            "path": result_file_path,
                        }, ensure_ascii=False)
                        try:
                            tool_result = _run_code_agent_repair_once(tool_name, code_agent_sid, fix_detail, code_agent_span)
                            continue
                        except Exception as e2:
                            code_agent_span.mark_failed(str(e))
                            msg.append({
                                "role": "user",
                                "content": json.dumps({
                                    "error": "TOOL_EXECUTION_FAILED",
                                    "detail": str(e2),
                                }, ensure_ascii=False)
                            })
                            break

                    normalized_sink_res, err = _validate_and_normalize_sink_res(
                        raw_sink_res, self._brain.project_path
                    )
                    if err:
                        self._publish_log(
                            "WARNING",
                            f"[SinkFinder] sink 格式校验失败 (修复轮 {repair_round}) | "
                            f"code={err.get('code')} field={err.get('field')} index={err.get('index')} "
                            f"message={err.get('message')}",
                        )
                        fix_detail = _build_invalid_sink_format_fix_detail(
                            err,
                            result_file_path=result_file_path,
                            raw_sink_res=raw_sink_res,
                        )
                        try:
                            tool_result = _run_code_agent_repair_once(tool_name, code_agent_sid, fix_detail, code_agent_span)
                            continue
                        except Exception as e:
                            code_agent_span.mark_failed(str(e))
                            msg.append({
                                "role": "user",
                                "content": json.dumps({
                                    "error": "TOOL_EXECUTION_FAILED",
                                    "detail": str(e),
                                }, ensure_ascii=False)
                            })
                            break
                    self._publish_log(
                        "INFO",
                        f"[SinkFinder] code_agent 结果校验通过 | count={len(normalized_sink_res)}",
                    )
                    start_event_span(
                        task_id=self._brain.task_id,
                        module=self.MODULE_NAME,
                        action_type=ActionType.INFORMATION,
                        reason=f"{language} 语言的 {vul_name} 类型共发现{len(normalized_sink_res)}条sink点",
                    )
                    sink_res = normalized_sink_res
                    repair_success = True
                    break

                if repair_success:
                    code_agent_span.finish()
                    break
                self._publish_log(
                    "WARNING",
                    f"[SinkFinder] code_agent 结果修复未成功，继续 LLM 轮次 ({step + 1}/{self.max_retries})",
                )
                continue

            if action_type == "final":
                self._publish_log("INFO", "[SinkFinder] LLM 返回 final，结束主循环")
                break
            sink_finder_span.add_llm_tokens(input_tokens, output_tokens)
            self._publish_log(
                "WARNING",
                f"[SinkFinder] 无效 next_action.type={action_type!r}，回喂纠正",
            )
            # 5) action_type 不符合协议：回喂纠正
            msg.append({"role": "assistant", "content": json.dumps(res, ensure_ascii=False)})
            msg.append({
                "role": "user",
                "content": json.dumps({
                    "error": "INVALID_NEXT_ACTION",
                    "requirement": "next_action.type 只能是 code_agent 或 final"
                }, ensure_ascii=False)
            })
            continue

        if not sink_res:
            self._publish_log(
                "WARNING",
                f"[SinkFinder] 主循环结束但未发现 sink | max_retries={self.max_retries}",
            )

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
        sink_finder_span.finish()
        # 同时把 nodes 原样返回（方便后续落库时直接 MERGE）
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
                tool_result = self._execute_tool_call(
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
                start_event_span(
                    task_id=self._brain.task_id,
                    module=self.MODULE_NAME,
                    action_type=ActionType.INFORMATION,
                    reason=f"{language} 语言的 {vul_name} 类型sink点经过处理剩余{len(normalized)}条",
                )
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
        sink_refine_span.finish()
        return out
