# -*- coding: utf-8 -*-
"""Neo4j 常用操作工具：供 AI 通过 ToolRegistry 调用，Cypher 一律使用 $参数，禁止拼接用户值进查询字符串。"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from neo4j.graph import Node, Path, Relationship

from src.tools.base import (
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_UNAVAILABLE,
    BaseTool,
    ToolResult,
)
from src.tools.registry import ToolRegistry
from src.storage.neo4j.client import Neo4jClient
from src.storage.neo4j.repository import Neo4jRepository

_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_MAX_READ_ROWS_HARD = 2000
_DEFAULT_READ_LIMIT = 500
_DEFAULT_FIND_LIMIT = 100


def _get_neo4j_client_optional() -> Optional[Neo4jClient]:
    try:
        from src.storage.manager import get_neo4j_client

        return get_neo4j_client()
    except RuntimeError:
        return None


def _get_repo_optional() -> Optional[Neo4jRepository]:
    try:
        from src.storage.manager import get_neo4j_repository

        return get_neo4j_repository()
    except RuntimeError:
        return None


def _validate_ident(name: str, kind: str) -> None:
    if not name or not _IDENT_RE.match(name):
        raise ValueError(f"非法{kind} {name!r}：须为字母开头，仅含字母、数字、下划线")


def _assert_single_statement(cypher: str) -> None:
    parts = [p.strip() for p in cypher.split(";") if p.strip()]
    if len(parts) != 1:
        raise ValueError("仅允许单条 Cypher 语句（不能包含多个以分号分隔的语句）")


def _coerce_param_map(value: Any, arg_name: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        if not value.strip():
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as e:
            raise ValueError(f"{arg_name} 须为合法 JSON 对象字符串：{e}") from e
        if not isinstance(parsed, dict):
            raise ValueError(f"{arg_name} 解析后须为 JSON 对象")
        return dict(parsed)
    raise ValueError(f"{arg_name} 须为 dict 或 JSON 对象字符串")


def _coerce_labels(value: Any) -> List[str]:
    if value is None:
        raise ValueError("labels 不能为空")
    if isinstance(value, list):
        out = [str(x).strip() for x in value if str(x).strip()]
        if not out:
            raise ValueError("labels 至少包含一个有效标签")
        return out
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("labels 不能为空")
        if s.startswith("["):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError as e:
                raise ValueError(f"labels JSON 无效: {e}") from e
            if not isinstance(parsed, list):
                raise ValueError("labels 字符串为 JSON 时须为数组")
            return _coerce_labels(parsed)
        return [p.strip() for p in s.split(",") if p.strip()]
    raise ValueError("labels 须为字符串数组或逗号分隔字符串")


def _serialize_graph_value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, Node):
        return {
            "_neo_type": "node",
            "element_id": v.element_id,
            "labels": list(v.labels),
            "properties": dict(v),
        }
    if isinstance(v, Relationship):
        out = {
            "_neo_type": "relationship",
            "element_id": v.element_id,
            "type": v.type,
            "properties": dict(v),
        }
        try:
            sn = v.start_node
            en = v.end_node
            out["start_node_element_id"] = sn.element_id
            out["end_node_element_id"] = en.element_id
        except Exception:
            pass
        return out
    if isinstance(v, Path):
        return {
            "_neo_type": "path",
            "nodes": [_serialize_graph_value(n) for n in v.nodes],
            "relationships": [_serialize_graph_value(r) for r in v.relationships],
        }
    if isinstance(v, list):
        return [_serialize_graph_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _serialize_graph_value(x) for k, x in v.items()}
    mod = type(v).__module__
    if mod.startswith("neo4j.time"):
        return str(v)
    return str(v)


def _records_to_rows(records: list, max_rows: int) -> Tuple[List[Dict[str, Any]], bool]:
    out: List[Dict[str, Any]] = []
    truncated = False
    for i, rec in enumerate(records):
        if i >= max_rows:
            truncated = True
            break
        row: Dict[str, Any] = {}
        for k in rec.keys():
            row[k] = _serialize_graph_value(rec[k])
        out.append(row)
    return out, truncated


def _node_spec_to_match(alias: str, node_spec: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    node_spec = dict(node_spec)
    if node_spec.get("id") in (None, ""):
        node_spec.pop("id", None)
    if "id" not in node_spec and "elementId" in node_spec:
        ev = node_spec.get("elementId")
        if ev not in (None, ""):
            node_spec["id"] = ev
    if "id" in node_spec:
        pk = f"{alias}_eid"
        return (
            f"MATCH ({alias}) WHERE elementId({alias}) = ${pk}",
            {pk: node_spec["id"]},
        )
    if "label" in node_spec:
        label = node_spec["label"]
        _validate_ident(str(label), "节点标签")
        _skip = frozenset({"label", "id", "elementId"})
        props = {k: v for k, v in node_spec.items() if k not in _skip}
        for k in props:
            _validate_ident(k, "属性名")
        if props:
            props_str = ", ".join([f"{k}: ${alias}_{k}" for k in props])
            clause = f"MATCH ({alias}:{label} {{{props_str}}})"
            params = {f"{alias}_{k}": v for k, v in props.items()}
            return clause, params
        return f"MATCH ({alias}:{label})", {}
    raise ValueError("node_spec 须含 id（elementId）或 label（及可选匹配属性）")


class _Neo4jClientMixin:
    """延迟解析 Neo4j 客户端；未初始化时 status 为 False。"""

    @property
    def status(self) -> bool:
        return _get_neo4j_client_optional() is not None

    def _client(self) -> Neo4jClient:
        c = _get_neo4j_client_optional()
        if c is None:
            raise RuntimeError("Neo4j 未初始化或不可用")
        return c


class Neo4jReadCypherTool(_Neo4jClientMixin, BaseTool):
    """只读 Cypher：必须使用 $param 占位符，勿把动态值写进查询字面量。"""

    _parameters_schema = [
        {
            "name": "cypher",
            "type": "string",
            "description": "单条只读 Cypher（MATCH/RETURN 等）；动态值用 $name 占位并在 parameters 中传入",
            "required": True,
        },
        {
            "name": "parameters",
            "type": "object",
            "description": "Cypher 参数字典，如 {\"task_id\": \"x\"}；可为空对象",
            "required": False,
        },
        {
            "name": "max_rows",
            "type": "integer",
            "description": f"最多返回行数，默认 {_DEFAULT_READ_LIMIT}，上限 {_MAX_READ_ROWS_HARD}",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_read_cypher"

    @property
    def description(self) -> str:
        return (
            "在 Neo4j 上执行单条只读 Cypher；所有动态值必须通过 parameters 以 $键 绑定，禁止字符串拼接。"
            f"返回行列表（每行为列名到值的字典），最多 max_rows 行。"
            " 注意：Neo4j 内部标识用函数 elementId(n)，不是节点属性 n.elementId；"
            "按业务主键匹配 SinkFlowNode 用 sink_node_id，ChainNode 用 node_id；"
            "不要在模式里写 {{elementId: $x}}。"
        )

    def run(
        self,
        cypher: str,
        parameters: Any = None,
        max_rows: Any = None,
        **kwargs: Any,
    ) -> ToolResult:
        if not cypher or not str(cypher).strip():
            return ToolResult(
                success=False,
                error="cypher 不能为空",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        cy = str(cypher).strip()
        try:
            _assert_single_statement(cy)
            params = _coerce_param_map(parameters, "parameters")
            limit = _DEFAULT_READ_LIMIT
            if max_rows is not None:
                limit = int(max_rows)
            if limit < 1:
                limit = 1
            if limit > _MAX_READ_ROWS_HARD:
                limit = _MAX_READ_ROWS_HARD
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        try:
            records = self._client().execute_read(cy, params)
            rows, truncated = _records_to_rows(records, limit)
            return ToolResult(
                success=True,
                data={"rows": rows, "row_count": len(rows)},
                meta={"truncated": truncated, "fetched_records": len(records)},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jWriteCypherTool(_Neo4jClientMixin, BaseTool):
    """写入类 Cypher（CREATE/MERGE/SET/DELETE 等），必须使用 $param。"""

    _parameters_schema = [
        {
            "name": "cypher",
            "type": "string",
            "description": "单条写入 Cypher；动态值用 $name 并在 parameters 传入",
            "required": True,
        },
        {
            "name": "parameters",
            "type": "object",
            "description": "Cypher 参数字典",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_write_cypher"

    @property
    def description(self) -> str:
        return (
            "执行单条会修改图的 Cypher（如 CREATE/MERGE/SET/DELETE）；"
            "必须用 $参数 传递动态值，禁止拼接。"
        )

    def run(self, cypher: str, parameters: Any = None, **kwargs: Any) -> ToolResult:
        if not cypher or not str(cypher).strip():
            return ToolResult(
                success=False,
                error="cypher 不能为空",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        cy = str(cypher).strip()
        try:
            _assert_single_statement(cy)
            params = _coerce_param_map(parameters, "parameters")
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        try:
            records = self._client().execute_write(cy, params)
            rows, _ = _records_to_rows(records, len(records) + 1)
            return ToolResult(
                success=True,
                data={"rows": rows, "row_count": len(rows)},
                meta={},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jMergeNodeTool(_Neo4jClientMixin, BaseTool):
    """按 match_properties MERGE 节点，可选 ON CREATE / ON MATCH 更新属性（均参数化）。"""

    _parameters_schema = [
        {
            "name": "label",
            "type": "string",
            "description": "节点标签（单个，如 Project）",
            "required": True,
        },
        {
            "name": "match_properties",
            "type": "object",
            "description": "用于 MERGE 匹配的相等属性（键为属性名）",
            "required": True,
        },
        {
            "name": "on_create_properties",
            "type": "object",
            "description": "仅在创建时 SET 的属性（n += 映射）",
            "required": False,
        },
        {
            "name": "on_match_set_properties",
            "type": "object",
            "description": "匹配到已存在节点时 SET 的属性（n += 映射）",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_merge_node"

    @property
    def description(self) -> str:
        return (
            "MERGE (n:Label {match...})；"
            "match_properties 决定幂等键；可选 on_create_properties / on_match_set_properties。"
        )

    def run(
        self,
        label: str,
        match_properties: Any,
        on_create_properties: Any = None,
        on_match_set_properties: Any = None,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            _validate_ident(str(label), "节点标签")
            mp = _coerce_param_map(match_properties, "match_properties")
            if not mp:
                raise ValueError("match_properties 不能为空")
            for k in mp:
                _validate_ident(k, "match 属性名")
            oc = _coerce_param_map(on_create_properties, "on_create_properties")
            om = _coerce_param_map(on_match_set_properties, "on_match_set_properties")
            for k in oc:
                _validate_ident(k, "on_create 属性名")
            for k in om:
                _validate_ident(k, "on_match 属性名")
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        props_str = ", ".join([f"{k}: $mp_{k}" for k in mp])
        params: Dict[str, Any] = {f"mp_{k}": v for k, v in mp.items()}
        lines = [f"MERGE (n:{label} {{{props_str}}})"]
        if oc:
            params["on_create"] = oc
            lines.append("ON CREATE SET n += $on_create")
        if om:
            params["on_match"] = om
            lines.append("ON MATCH SET n += $on_match")
        lines.append("RETURN n")
        cypher = "\n".join(lines)
        try:
            records = self._client().execute_write(cypher, params)
            if not records:
                return ToolResult(success=True, data={"node": None}, meta={"note": "无 RETURN 行"})
            row, _ = _records_to_rows(records, 1)
            first = row[0] if row else {}
            return ToolResult(
                success=True,
                data={"node": first.get("n"), "row": first},
                meta={},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jFindNodesTool(_Neo4jClientMixin, BaseTool):
    """按标签（可多标签）与可选属性相等条件查找节点。"""

    _parameters_schema = [
        {
            "name": "labels",
            "type": "array",
            "description": "节点标签列表，如 [\"Project\"]；或逗号分隔字符串",
            "required": True,
        },
        {
            "name": "where_equal",
            "type": "object",
            "description": "可选，属性相等条件（AND）；键为属性名",
            "required": False,
        },
        {
            "name": "limit",
            "type": "integer",
            "description": f"最大返回节点数，默认 {_DEFAULT_FIND_LIMIT}，上限 {_MAX_READ_ROWS_HARD}",
            "required": False,
        },
        {
            "name": "skip",
            "type": "integer",
            "description": "SKIP，默认 0",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_find_nodes"

    @property
    def description(self) -> str:
        return "MATCH (n:Label1:Label2...) 可选 WHERE 属性相等；只读，参数化 LIMIT/SKIP。"

    def run(
        self,
        labels: Any,
        where_equal: Any = None,
        limit: Any = None,
        skip: Any = None,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            labs = _coerce_labels(labels)
            for lb in labs:
                _validate_ident(lb, "节点标签")
            we = _coerce_param_map(where_equal, "where_equal")
            for k in we:
                _validate_ident(k, "where 属性名")
            lim = int(limit) if limit is not None else _DEFAULT_FIND_LIMIT
            sk = int(skip) if skip is not None else 0
            if lim < 1:
                lim = 1
            if lim > _MAX_READ_ROWS_HARD:
                lim = _MAX_READ_ROWS_HARD
            if sk < 0:
                sk = 0
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        label_expr = "".join([f":{lb}" for lb in labs])
        params: Dict[str, Any] = {"lim": lim, "sk": sk}
        if we:
            where_parts = [f"n.{k} = $w_{k}" for k in we]
            where_clause = " WHERE " + " AND ".join(where_parts)
            for k, v in we.items():
                params[f"w_{k}"] = v
        else:
            where_clause = ""
        cypher = (
            f"MATCH (n{label_expr}){where_clause} RETURN n SKIP $sk LIMIT $lim"
        )
        try:
            records = self._client().execute_read(cypher, params)
            rows, truncated = _records_to_rows(records, lim)
            return ToolResult(
                success=True,
                data={"nodes": [r.get("n") for r in rows], "rows": rows},
                meta={"truncated": truncated},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jCreateNodeTool(BaseTool):
    """创建节点（委托 Neo4jRepository.create_node）。"""

    _parameters_schema = [
        {
            "name": "label",
            "type": "string",
            "description": "节点标签",
            "required": True,
        },
        {
            "name": "properties",
            "type": "object",
            "description": "节点属性；可省略表示无属性",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_create_node"

    @property
    def description(self) -> str:
        return "CREATE (n:Label {properties...})；属性值经参数绑定。"

    @property
    def status(self) -> bool:
        return _get_repo_optional() is not None

    def run(self, label: str, properties: Any = None, **kwargs: Any) -> ToolResult:
        try:
            _validate_ident(str(label), "节点标签")
            props = _coerce_param_map(properties, "properties")
            for k in props:
                _validate_ident(k, "属性名")
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        repo = _get_repo_optional()
        if repo is None:
            return ToolResult(
                success=False,
                error="Neo4j Repository 不可用",
                error_code=ERROR_CODE_UNAVAILABLE,
            )
        try:
            node = repo.create_node(label, props or None)
            return ToolResult(success=True, data={"node": node}, meta={})
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jCreateRelationshipTool(BaseTool):
    """创建关系（委托 Neo4jRepository.create_relationship）。"""

    _parameters_schema = [
        {
            "name": "from_node",
            "type": "object",
            "description": "起点：{id} 或 {label, ...属性}",
            "required": True,
        },
        {
            "name": "to_node",
            "type": "object",
            "description": "终点：{id} 或 {label, ...属性}",
            "required": True,
        },
        {
            "name": "relationship_type",
            "type": "string",
            "description": "关系类型，如 HAS_TASK",
            "required": True,
        },
        {
            "name": "relationship_properties",
            "type": "object",
            "description": "关系上的可选属性",
            "required": False,
        },
        {
            "name": "auto_create_nodes",
            "type": "boolean",
            "description": "端点不存在时是否 MERGE 创建，默认 true",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_create_relationship"

    @property
    def description(self) -> str:
        return "在两端节点之间 MERGE 关系；端点规格与仓储层一致。"

    @property
    def status(self) -> bool:
        return _get_repo_optional() is not None

    def run(
        self,
        from_node: Any,
        to_node: Any,
        relationship_type: str,
        relationship_properties: Any = None,
        auto_create_nodes: Any = True,
        **kwargs: Any,
    ) -> ToolResult:
        try:
            fn = _coerce_param_map(from_node, "from_node")
            tn = _coerce_param_map(to_node, "to_node")
            if not fn or not tn:
                raise ValueError("from_node / to_node 须为非空对象")
            _validate_ident(str(relationship_type), "关系类型")
            rp = _coerce_param_map(relationship_properties, "relationship_properties")
            for k in rp:
                _validate_ident(k, "关系属性名")
            auto = True if auto_create_nodes is None else bool(auto_create_nodes)
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        repo = _get_repo_optional()
        if repo is None:
            return ToolResult(
                success=False,
                error="Neo4j Repository 不可用",
                error_code=ERROR_CODE_UNAVAILABLE,
            )
        try:
            rel = repo.create_relationship(
                fn,
                tn,
                str(relationship_type),
                rp or None,
                auto_create_nodes=auto,
            )
            return ToolResult(success=True, data={"relationship": rel}, meta={})
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jUpdateNodeTool(BaseTool):
    """更新节点属性（委托 Neo4jRepository.update_node）。"""

    _parameters_schema = [
        {
            "name": "node_spec",
            "type": "object",
            "description": "匹配：{id} 或 {label, ...属性}",
            "required": True,
        },
        {
            "name": "updates",
            "type": "object",
            "description": "要 SET 的属性键值",
            "required": True,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_update_node"

    @property
    def description(self) -> str:
        return "按 id 或 label+属性匹配节点并 SET 更新字段。"

    @property
    def status(self) -> bool:
        return _get_repo_optional() is not None

    def run(self, node_spec: Any, updates: Any, **kwargs: Any) -> ToolResult:
        try:
            spec = _coerce_param_map(node_spec, "node_spec")
            upd = _coerce_param_map(updates, "updates")
            if not spec:
                raise ValueError("node_spec 不能为空")
            if not upd:
                raise ValueError("updates 不能为空")
            for k in upd:
                _validate_ident(k, "更新属性名")
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        repo = _get_repo_optional()
        if repo is None:
            return ToolResult(
                success=False,
                error="Neo4j Repository 不可用",
                error_code=ERROR_CODE_UNAVAILABLE,
            )
        try:
            node = repo.update_node(spec, upd)
            return ToolResult(success=True, data={"node": node}, meta={})
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


class Neo4jDeleteNodeTool(_Neo4jClientMixin, BaseTool):
    """按 elementId 或 label+属性匹配后 DETACH DELETE。"""

    _parameters_schema = [
        {
            "name": "node_spec",
            "type": "object",
            "description": "匹配：{id: elementId} 或 {label, ...相等属性}",
            "required": True,
        },
    ]

    @property
    def name(self) -> str:
        return "neo4j_delete_node"

    @property
    def description(self) -> str:
        return "删除单个匹配节点及其关系（DETACH DELETE），条件完全参数化。"

    def run(self, node_spec: Any, **kwargs: Any) -> ToolResult:
        try:
            spec = _coerce_param_map(node_spec, "node_spec")
            if not spec:
                raise ValueError("node_spec 不能为空")
            match_clause, params = _node_spec_to_match("n", spec)
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )
        cypher = f"{match_clause}\nDETACH DELETE n"
        try:
            self._client().execute_write(cypher, params)
            return ToolResult(success=True, data={"deleted": True}, meta={})
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_INVALID_ARGUMENT,
                meta={"exception_type": type(e).__name__},
            )


def register_neo4j_tools(registry: ToolRegistry) -> None:
    """向注册表登记 Neo4j 工具；数据库未配置时工具 status 为 False。"""
    registry.register(Neo4jReadCypherTool())
    # registry.register(Neo4jWriteCypherTool())
    # registry.register(Neo4jMergeNodeTool())
    # registry.register(Neo4jFindNodesTool())
    # registry.register(Neo4jCreateNodeTool())
    # registry.register(Neo4jCreateRelationshipTool())
    registry.register(Neo4jUpdateNodeTool())
    # registry.register(Neo4jDeleteNodeTool())
