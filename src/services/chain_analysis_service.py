# -*- coding: utf-8 -*-
"""
链路分析服务层 —— ChainNode / AnalysisResult 的 Neo4j 持久化操作。

对应设计文档 Section 8 / 10 / 11：
- ChainNode：分析阶段 LLM 确认的结构化发现节点，通过 :FLOW 边串联在 chain 末端之后
  每个 ChainNode 携带 branch_id，标识它属于哪条分析分支
- AnalysisResult：链路分析的最终结论，挂在扩展链路的末尾（每个分支独立产出一个）；
  跨服务/API 引用该节点时统一使用 Neo4j **elementId**（节点仍保留业务属性 ``node_id``）
- AuditInfo：LLM record_info 产出的审计备注，通过 :HAS_AUDIT_INFO 挂在目标节点（按 elementId 匹配）上
- Knowledge：每个 RiskCategory 经 :HAS_KNOWLEDGE 关联至多一个全局知识库节点，可挂载跨链路的 AuditInfo
- :Result 标签：打在 SinkFinder 阶段的 chain 末端 SinkFlowNode 上，标记该链路所有分支均已分析完成

分支模型：
  当 LLM 发现多个调用者时，同一个扩展锚点可以分叉出多条分支，每条分支拥有独立的
  branch_id、独立的 ChainNode 序列、独立的对话上下文和独立的 AnalysisResult。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import src.storage.manager as db_manager
from src.utils.ids import generate_id


# ---------------------------------------------------------------------------
# 读取：获取 chain path 上所有 SinkFlowNode 的详细信息
# ---------------------------------------------------------------------------

def fetch_sink_flow_nodes_by_ids(sink_node_ids: List[str]) -> List[Dict[str, Any]]:
    """
    根据 sink_node_id 列表批量获取 SinkFlowNode 的完整属性。
    返回的列表顺序与输入一致（找不到的 id 不包含在结果中）。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not sink_node_ids:
        return []

    records = repo.client.execute_query(
        """
        UNWIND $ids AS sid
        MATCH (s:SinkFlowNode {sink_node_id: sid})
        RETURN s.sink_node_id AS sink_node_id,
               s.file         AS file,
               s.line         AS line,
               s.end_line     AS end_line,
               s.function     AS function,
               s.reason       AS reason,
               s.related_exec AS related_exec
        """,
        {"ids": sink_node_ids},
    )
    if not records:
        return []

    by_id = {}
    for r in records:
        d = r.data()
        by_id[d["sink_node_id"]] = d

    return [by_id[sid] for sid in sink_node_ids if sid in by_id]


def fetch_node_lines_by_element_ids(
    element_ids: List[str],
) -> Dict[str, Dict[str, Any]]:
    """
    按 Neo4j elementId 批量查询节点的 line / end_line 属性。

    返回 {elementId: {"line": ..., "end_line": ...}}，查不到的不包含。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not element_ids:
        return {}

    eids = [str(e).strip() for e in element_ids if e not in (None, "")]
    if not eids:
        return {}

    records = repo.client.execute_query(
        """
        UNWIND $eids AS eid
        MATCH (n) WHERE elementId(n) = eid
        RETURN elementId(n) AS elementId, n.line AS line, n.end_line AS end_line
        """,
        {"eids": eids},
    )
    if not records:
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    for r in records:
        d = r.data()
        eid = d.get("elementId")
        if eid:
            result[eid] = {"line": d.get("line"), "end_line": d.get("end_line")}
    return result


def update_node_status_by_element_ids(element_ids: List[str], status: str) -> int:
    """
    按 Neo4j elementId 批量更新节点 status 属性。

    Returns:
        实际更新到的节点数量。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not element_ids:
        return 0

    eids = [str(e).strip() for e in element_ids if e not in (None, "")]
    st = str(status).strip()
    if not eids or not st:
        return 0

    records = repo.client.execute_write(
        """
        UNWIND $eids AS eid
        MATCH (n) WHERE elementId(n) = eid
        SET n.status = $st
        RETURN count(n) AS n
        """,
        {"eids": eids, "st": st},
    )
    if not records:
        return 0
    return int(records[0].data().get("n", 0) or 0)


def fetch_risk_category_info(vul_node_id: str) -> Optional[Dict[str, Any]]:
    """获取 RiskCategory 节点的基本信息（category_name, risk_description 等）。"""
    repo = db_manager.neo4j_repository
    if repo is None or not vul_node_id:
        return None

    records = repo.client.execute_query(
        """
        MATCH (c:RiskCategory {node_id: $nid})
        RETURN c.category_name     AS category_name,
               c.risk_description  AS risk_description,
               c.reasoning_basis   AS reasoning_basis
        """,
        {"nid": vul_node_id},
    )
    if not records:
        return None
    return records[0].data()


def ensure_knowledge_element_id_for_risk_category(risk_category_node_id: str) -> Optional[str]:
    """
    保证 (RiskCategory.node_id)-[:HAS_KNOWLEDGE]->(:Knowledge) 存在且 Knowledge 与 rc 绑定，
    返回该 Knowledge 的 elementId。

    使用单次 MERGE 写入，避免 OPTIONAL MATCH 中显式写出尚未出现在 catalog 中的
    :Knowledge / :HAS_KNOWLEDGE 时在空库上触发的 GQL 01N50/01N51 类通知。
    """
    repo = db_manager.neo4j_repository
    nid = str(risk_category_node_id).strip() if risk_category_node_id else ""
    if repo is None or not nid:
        return None

    kid = generate_id("kb")
    ts = datetime.now().isoformat()
    wrecs = repo.client.execute_write(
        """
        MATCH (rc:RiskCategory {node_id: $nid})
        MERGE (k:Knowledge {risk_category_node_id: $nid})
        MERGE (rc)-[:HAS_KNOWLEDGE]->(k)
        ON CREATE SET k.node_id = $kid, k.created_at = $ts, k.task_id = rc.task_id
        SET k.task_id = rc.task_id
        RETURN elementId(k) AS eid
        """,
        {"nid": nid, "kid": kid, "ts": ts},
    )
    if not wrecs:
        return None
    we = wrecs[0].data().get("eid")
    if we is None:
        return None
    s = str(we).strip()
    return s or None


def fetch_audit_info_contents_by_element_ids(element_ids: List[str]) -> Dict[str, List[str]]:
    """
    按 Neo4j elementId 批量查询 (节点)-[:HAS_AUDIT_INFO]->(:AuditInfo) 的 content 列表。

    同一 elementId 下若存在多条 AuditInfo，按 created_at 升序排列；无备注时返回空列表。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not element_ids:
        return {}

    eids = []
    seen: set[str] = set()
    for raw in element_ids:
        if raw is None:
            continue
        e = str(raw).strip()
        if not e or e in seen:
            continue
        seen.add(e)
        eids.append(e)

    if not eids:
        return {}

    records = repo.client.execute_query(
        """
        UNWIND $eids AS eid
        OPTIONAL MATCH (t) WHERE elementId(t) = eid
        OPTIONAL MATCH (t)-[:HAS_AUDIT_INFO]->(a:AuditInfo)
        WITH eid, a
        ORDER BY eid, coalesce(a.created_at, '')
        WITH eid, collect(a.content) AS raw_contents
        RETURN eid, raw_contents
        """,
        {"eids": eids},
    )
    out: Dict[str, List[str]] = {}
    for rec in records or []:
        row = rec.data()
        eid = row.get("eid")
        if eid is None:
            continue
        key = str(eid).strip()
        raw_list = row.get("raw_contents") or []
        contents = [
            str(x).strip()
            for x in raw_list
            if x is not None and str(x).strip()
        ]
        out[key] = contents
    return out


def fetch_flow_chain_nodes_for_analysis_result(ar_node_id: str) -> List[Dict[str, Any]]:
    """
    根据 AnalysisResult 的 Neo4j elementId（与 resolution["_ar_node_id"]、API ``ar_node_id`` 一致），
    从图上还原挂接该结果的 FLOW 链路上全部 SinkFlowNode / ChainNode（顺序为从上游到末端 z，满足
    …-[:FLOW*]->(z)-[:HAS_RESULT]->(:AnalysisResult) 且 ``elementId(ar)`` 与入参一致）。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not str(ar_node_id).strip():
        return []

    ar_id = str(ar_node_id).strip()
    records = repo.client.execute_query(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $ar_id
        MATCH (z)-[:HAS_RESULT]->(ar)
        WHERE z:SinkFlowNode OR z:ChainNode
        RETURN z AS node, elementId(z) AS elementId, labels(z) AS labels
        ORDER BY elementId(z)
        LIMIT 1
        """,
        {"ar_id": ar_id},
    )
    if not records:
        return []

    def _row_to_dict(rec: Any) -> Dict[str, Any]:
        row = rec.data()
        node = row.get("node")
        if node is None:
            return {}
        props = dict(node)
        eid = row.get("elementId")
        labs = row.get("labels") or []
        out = {**props}
        out["elementId"] = eid
        out["labels"] = list(labs) if labs is not None else []
        return out

    tail = _row_to_dict(records[0])
    if not tail:
        return []

    chain_rev: List[Dict[str, Any]] = [tail]
    current = tail
    max_hops = 128
    for _ in range(max_hops):
        labels = current.get("labels") or []
        parents: List[Any] = []
        if "ChainNode" in labels:
            cid = current.get("node_id")
            if not cid:
                break
            parents = repo.client.execute_query(
                """
                MATCH (p)-[:FLOW]->(c:ChainNode {node_id: $cid})
                WHERE p:SinkFlowNode OR p:ChainNode
                RETURN p AS node, elementId(p) AS elementId, labels(p) AS labels
                ORDER BY elementId(p)
                LIMIT 1
                """,
                {"cid": str(cid)},
            )
        else:
            sid = current.get("sink_node_id")
            if not sid:
                break
            parents = repo.client.execute_query(
                """
                MATCH (p)-[:FLOW]->(c:SinkFlowNode {sink_node_id: $sid})
                WHERE p:SinkFlowNode OR p:ChainNode
                RETURN p AS node, elementId(p) AS elementId, labels(p) AS labels
                ORDER BY elementId(p)
                LIMIT 1
                """,
                {"sid": str(sid)},
            )
        if not parents:
            break
        parent_dict = _row_to_dict(parents[0])
        if not parent_dict:
            break
        chain_rev.append(parent_dict)
        current = parent_dict

    return list(reversed(chain_rev))


def mark_analysis_branch_completed(
    ar_node_id: str,
    publish_log: Optional[Callable[[str, str], None]] = None,
) -> None:
    """
    在产出 AnalysisResult 且（如有）二次校验结束之后调用。

    与 fetch_flow_chain_nodes_for_analysis_result 相同的 FLOW 反查路径，将链上
    每个 SinkFlowNode / ChainNode 以及对应的 AnalysisResult 的 status 设为 completed。

    参数 ``ar_node_id``：AnalysisResult 的 Neo4j elementId（与 ``_ar_node_id`` 一致）。
    参数 ``publish_log``：可选日志回调 ``(level, message) -> None``，用于输出被标记的 elementId。
    """
    repo = db_manager.neo4j_repository
    aid = str(ar_node_id).strip() if ar_node_id else ""
    if repo is None or not aid:
        return

    nodes = fetch_flow_chain_nodes_for_analysis_result(aid)
    element_ids: List[str] = []
    seen: Set[str] = set()
    for n in nodes:
        eid_raw = n.get("elementId")
        if eid_raw in (None, ""):
            continue
        eid = str(eid_raw).strip()
        if eid and eid not in seen:
            seen.add(eid)
            element_ids.append(eid)
    if aid not in seen:
        element_ids.append(aid)

    if element_ids:
        update_node_status_by_element_ids(element_ids, "completed")

    if publish_log:
        publish_log(
            "INFO",
            "[ChainAnalysis] 标记分支完成 | "
            f"ar_elementId={aid} | elementIds={element_ids}",
        )


# 与 sink_flow / inspect 子图一致：从 vul HAS_SINK 根沿 FLOW 可达的末端上的 HAS_RESULT
_VUL_FLOW_MAX_DEPTH = 150


def reset_non_completed_analysis_results_to_pending_for_vul(vul_node_id: str) -> int:
    """
    将指定漏洞节点（如 RiskCategory.node_id）下、经 HAS_SINK→FLOW* 可达末端上挂接的
    AnalysisResult 中，凡 status 非 completed 的一律标为 pending（用于恢复中断/未结案状态）。

    Returns:
        被更新的 AnalysisResult 数量（去重后）。
    """
    repo = db_manager.neo4j_repository
    vid = str(vul_node_id).strip() if vul_node_id else ""
    if repo is None or not vid:
        return 0

    records = repo.client.execute_write(
        f"""
        MATCH (v:RiskCategory {{node_id: $vid}})-[:HAS_SINK]->(root:SinkFlowNode)
        MATCH (root)-[:FLOW*0..{_VUL_FLOW_MAX_DEPTH}]->(tail)
        WHERE tail:SinkFlowNode OR tail:ChainNode
        MATCH (tail)-[:HAS_RESULT]->(ar:AnalysisResult)
        WHERE coalesce(ar.status, '') <> 'completed'
        WITH DISTINCT ar
        SET ar.status = 'pending'
        RETURN count(ar) AS n
        """,
        {"vid": vid},
    )
    if not records:
        return 0
    return int(records[0].data().get("n") or 0)


def fetch_non_completed_analysis_results_for_vul(vul_node_id: str) -> List[Dict[str, Any]]:
    """
    查询该 vul 下仍非 completed 的末端 AnalysisResult（通常表示尚未走完二次校验与结案标记）。

    返回每项含 ar_element_id（Neo4j elementId，与 resolution["_ar_node_id"] 一致）、branch_id、verdict、
    status、verification_status 等。
    """
    repo = db_manager.neo4j_repository
    vid = str(vul_node_id).strip() if vul_node_id else ""
    if repo is None or not vid:
        return []

    records = repo.client.execute_query(
        f"""
        MATCH (v:RiskCategory {{node_id: $vid}})-[:HAS_SINK]->(root:SinkFlowNode)
        MATCH (root)-[:FLOW*0..{_VUL_FLOW_MAX_DEPTH}]->(tail)
        WHERE tail:SinkFlowNode OR tail:ChainNode
        MATCH (tail)-[:HAS_RESULT]->(ar:AnalysisResult)
        WHERE coalesce(ar.status, '') <> 'completed'
        RETURN DISTINCT elementId(ar) AS ar_element_id,
               ar.branch_id AS branch_id,
               ar.verdict AS verdict,
               ar.status AS status,
               coalesce(ar.verification_status, '') AS verification_status
        ORDER BY ar_element_id
        """,
        {"vid": vid},
    )
    return [rec.data() for rec in (records or [])]


def _analysis_result_json_prop_to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def fetch_analysis_result_as_resolution_dict(ar_node_id: str) -> Optional[Dict[str, Any]]:
    """
    按 AnalysisResult 的 Neo4j elementId（与 ``_ar_node_id`` 传参一致）读取节点属性，
    组装为与链路分析 final_resolution 结构兼容的 dict，供 ChainConfirmer.maybe_confirm_resolution 等复用。
    """
    repo = db_manager.neo4j_repository
    aid = str(ar_node_id).strip() if ar_node_id else ""
    if repo is None or not aid:
        return None

    records = repo.client.execute_query(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $aid
        RETURN ar AS node
        """,
        {"aid": aid},
    )
    if not records:
        return None
    node = records[0].data().get("node")
    if node is None:
        return None
    props = dict(node)

    out: Dict[str, Any] = {
        "verdict": props.get("verdict") or "UNKNOWN",
        "confidence": props.get("confidence") or "LOW",
        "vul_name": props.get("vul_name") or "",
        "detail": props.get("detail") or "",
        "entry_points": _analysis_result_json_prop_to_list(props.get("entry_points")),
        "findings": _analysis_result_json_prop_to_list(props.get("evidence")),
        "security_boundaries": _analysis_result_json_prop_to_list(props.get("security_boundaries")),
        "branch_id": props.get("branch_id") or "",
        "analysis_rounds": props.get("analysis_rounds", 0),
        "_ar_node_id": aid,
    }
    vs = props.get("verification_status")
    if vs not in (None, ""):
        out["verification_status"] = vs
    vr = props.get("verification_reason")
    if vr not in (None, ""):
        out["verification_reason"] = vr
    var = props.get("vulnerability_analysis_report")
    if var not in (None, ""):
        out["vulnerability_analysis_report"] = var
    poc = props.get("poc")
    if poc not in (None, ""):
        out["poc"] = poc
    return out


# ---------------------------------------------------------------------------
# 利用链导出：从 AnalysisResult 沿 FLOW 反向到 RiskCategory，写入 PG JSONB
# ---------------------------------------------------------------------------

_EXP_CHAIN_MAX_PATHS = 64


def fetch_task_project_path_from_neo4j(task_id: str) -> str:
    """从 Task 节点读取项目根路径（与 orchestrator 写入的 t.path 一致）。"""
    repo = db_manager.neo4j_repository
    tid = str(task_id).strip() if task_id else ""
    if repo is None or not tid:
        return ""
    recs = repo.client.execute_query(
        """
        MATCH (t:Task {task_id: $tid})
        RETURN coalesce(t.path, '') AS path
        LIMIT 1
        """,
        {"tid": tid},
    )
    if not recs:
        return ""
    return str(recs[0].data().get("path") or "").strip()


def _neo_node_record_to_dict(rec: Any) -> Dict[str, Any]:
    row = rec.data()
    node = row.get("node")
    if node is None:
        return {}
    props = dict(node)
    eid = row.get("elementId")
    labs = row.get("labels") or []
    out = {**props}
    if eid is not None:
        out["elementId"] = eid
    out["labels"] = list(labs) if labs is not None else []
    return out


def fetch_audit_info_records_by_element_ids(
    element_ids: List[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    按 Neo4j elementId 查询 (节点)-[:HAS_AUDIT_INFO]->(:AuditInfo) 的完整属性列表，
    按 created_at 升序。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not element_ids:
        return {}

    eids: List[str] = []
    seen: set[str] = set()
    for raw in element_ids:
        if raw is None:
            continue
        e = str(raw).strip()
        if not e or e in seen:
            continue
        seen.add(e)
        eids.append(e)
    if not eids:
        return {}

    records = repo.client.execute_query(
        """
        UNWIND $eids AS eid
        OPTIONAL MATCH (t) WHERE elementId(t) = eid
        OPTIONAL MATCH (t)-[:HAS_AUDIT_INFO]->(a:AuditInfo)
        WITH eid, a
        ORDER BY eid, coalesce(a.created_at, '')
        WITH eid, collect(a) AS nodes
        RETURN eid, nodes
        """,
        {"eids": eids},
    )
    out: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records or []:
        row = rec.data()
        key = str(row.get("eid") or "").strip()
        if not key:
            continue
        nodes = row.get("nodes") or []
        audits: List[Dict[str, Any]] = []
        for node in nodes:
            if node is None:
                continue
            audits.append(dict(node))
        out[key] = audits
    return out


def _chain_node_identity(n: Dict[str, Any]) -> Tuple[str, str]:
    labs = set(n.get("labels") or [])
    if "ChainNode" in labs:
        return ("cn", str(n.get("node_id") or "").strip())
    if "SinkFlowNode" in labs:
        return ("sf", str(n.get("sink_node_id") or "").strip())
    if "AnalysisResult" in labs:
        return ("ar", str(n.get("elementId") or n.get("node_id") or "").strip())
    if "RiskCategory" in labs:
        return ("rc", str(n.get("node_id") or "").strip())
    return ("unk", str(n.get("elementId") or "").strip())


def _fetch_flow_parents(repo: Any, node: Dict[str, Any], task_id: str) -> List[Dict[str, Any]]:
    tid = str(task_id).strip() if task_id else ""
    labels = node.get("labels") or []
    records: List[Any] = []
    if "ChainNode" in labels:
        cid = node.get("node_id")
        if not cid:
            return []
        records = repo.client.execute_query(
            """
            MATCH (p)-[:FLOW]->(c:ChainNode {node_id: $cid})
            WHERE (p:SinkFlowNode OR p:ChainNode)
              AND ($tid = '' OR (coalesce(c.task_id, '') = $tid AND coalesce(p.task_id, '') = $tid))
            RETURN p AS node, elementId(p) AS elementId, labels(p) AS labels
            """,
            {"cid": str(cid), "tid": tid},
        )
    elif "SinkFlowNode" in labels:
        sid = node.get("sink_node_id")
        if not sid:
            return []
        records = repo.client.execute_query(
            """
            MATCH (p)-[:FLOW]->(s:SinkFlowNode {sink_node_id: $sid})
            WHERE (p:SinkFlowNode OR p:ChainNode)
              AND ($tid = '' OR (coalesce(s.task_id, '') = $tid AND coalesce(p.task_id, '') = $tid))
            RETURN p AS node, elementId(p) AS elementId, labels(p) AS labels
            """,
            {"sid": str(sid), "tid": tid},
        )
    out: List[Dict[str, Any]] = []
    for r in records or []:
        d = _neo_node_record_to_dict(r)
        if d:
            out.append(d)
    return out


def _fetch_risk_categories_for_sink(
    repo: Any, sink_node_id: str, task_id: str
) -> List[Dict[str, Any]]:
    tid = str(task_id).strip() if task_id else ""
    records = repo.client.execute_query(
        """
        MATCH (rc:RiskCategory)-[:HAS_SINK]->(s:SinkFlowNode {sink_node_id: $sid})
        WHERE $tid = '' OR coalesce(rc.task_id, '') = $tid
        RETURN rc AS node, elementId(rc) AS elementId, labels(rc) AS labels
        ORDER BY elementId(rc)
        """,
        {"sid": str(sink_node_id), "tid": tid},
    )
    out: List[Dict[str, Any]] = []
    for r in records or []:
        d = _neo_node_record_to_dict(r)
        if d:
            out.append(d)
    return out


def _load_analysis_result_dict(repo: Any, ar_node_id: str) -> Optional[Dict[str, Any]]:
    records = repo.client.execute_query(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $aid
        RETURN ar AS node, elementId(ar) AS elementId, labels(ar) AS labels
        """,
        {"aid": str(ar_node_id).strip()},
    )
    if not records:
        return None
    return _neo_node_record_to_dict(records[0])


def _read_source_line_context(
    project_root: str,
    rel_file: Any,
    line: Any,
    margin: int = 5,
) -> Optional[Dict[str, Any]]:
    root_s = (project_root or "").strip()
    if not root_s or rel_file is None:
        return None
    rel = str(rel_file).strip().replace("\\", "/").lstrip("/")
    if not rel:
        return None
    try:
        focus = int(line)
    except (TypeError, ValueError):
        return None
    if focus <= 0:
        return None
    try:
        root = Path(root_s).expanduser().resolve()
        fp = (root / rel).resolve()
        fp.relative_to(root)
    except (OSError, ValueError):
        return None
    if not fp.is_file():
        return None
    try:
        raw_lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    n = len(raw_lines)
    lo = max(1, focus - margin)
    hi = min(n, focus + margin)
    return {
        "relative_file": rel,
        "absolute_path": str(fp),
        "focus_line": focus,
        "start_line": lo,
        "end_line": hi,
        "lines": [{"line_no": i, "text": raw_lines[i - 1]} for i in range(lo, hi + 1)],
    }


def build_exploitation_chain_document(
    ar_node_id: str,
    *,
    project_root: str = "",
    task_id: str = "",
) -> Dict[str, Any]:
    """
    从 AnalysisResult 沿 :FLOW 反向遍历（支持分叉），经 HAS_SINK 挂上 RiskCategory；
    为每个图节点附带 HAS_AUDIT_INFO 审计记录；若存在 file/line 且 project_root 有效，
    读取源码 focus 行上下各 margin 行。

    返回结构（写入 PostgreSQL JSONB）::
        version, analysis_result_node_id（实为 Neo4j elementId）, task_id, project_root, generated_at,
        paths: [{path_id, steps: [{index, node_kind, labels, element_id, ids, properties,
            audit_infos, location, source_context}, ...]}], error?
    steps 顺序：index 0 为 AnalysisResult，递增直至 RiskCategory（若可达）。

    参数 ``ar_node_id``：AnalysisResult 的 Neo4j **elementId**（与 ``_ar_node_id`` 一致）。
    """
    aid = str(ar_node_id).strip()
    tid = str(task_id).strip() if task_id else ""
    base: Dict[str, Any] = {
        "version": 1,
        "analysis_result_node_id": aid,
        "task_id": tid,
        "project_root": (project_root or "").strip(),
        "generated_at": datetime.now().isoformat(),
        "paths": [],
        "error": None,
    }
    if not aid:
        base["error"] = "missing_ar_element_id"
        return base

    repo = db_manager.neo4j_repository
    if repo is None:
        base["error"] = "neo4j_unavailable"
        return base

    ar_dict = _load_analysis_result_dict(repo, aid)
    if not ar_dict:
        base["error"] = "analysis_result_not_found"
        return base

    records = repo.client.execute_query(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $aid
        MATCH (z)-[:HAS_RESULT]->(ar)
        WHERE z:SinkFlowNode OR z:ChainNode
        RETURN DISTINCT z AS node, elementId(z) AS elementId, labels(z) AS labels
        """,
        {"aid": aid},
    )
    tails = [_neo_node_record_to_dict(r) for r in (records or [])]
    tails = [t for t in tails if t]
    if not tails:
        base["error"] = "no_has_result_tail"
        return base

    paths_raw: List[List[Dict[str, Any]]] = []

    def dfs(current: Dict[str, Any], suffix: List[Dict[str, Any]], vis: Set[Tuple[str, str]]) -> None:
        if len(paths_raw) >= _EXP_CHAIN_MAX_PATHS:
            return
        if len(suffix) > _VUL_FLOW_MAX_DEPTH + 2:
            return
        ident = _chain_node_identity(current)
        if ident in vis:
            return
        vis2: Set[Tuple[str, str]] = set(vis)
        vis2.add(ident)
        parents = _fetch_flow_parents(repo, current, tid)
        if not parents:
            labs = current.get("labels") or []
            if "SinkFlowNode" in labs:
                sid = current.get("sink_node_id")
                rcs = _fetch_risk_categories_for_sink(repo, str(sid or ""), tid) if sid else []
                if rcs:
                    for rc in rcs:
                        paths_raw.append([ar_dict] + suffix + [rc])
                        if len(paths_raw) >= _EXP_CHAIN_MAX_PATHS:
                            return
                else:
                    paths_raw.append([ar_dict] + suffix)
            else:
                paths_raw.append([ar_dict] + suffix)
            return
        for p in parents:
            if not p:
                continue
            dfs(p, [p] + suffix, vis2)

    for tail in tails:
        if len(paths_raw) >= _EXP_CHAIN_MAX_PATHS:
            break
        dfs(tail, [tail], set())

    pr = (project_root or "").strip()
    if not pr and tid:
        pr = fetch_task_project_path_from_neo4j(tid)
    base["project_root"] = pr

    eids: set[str] = set()
    for path in paths_raw:
        for nd in path:
            e = nd.get("elementId")
            if e is not None and str(e).strip():
                eids.add(str(e).strip())
    audit_by_eid = fetch_audit_info_records_by_element_ids(sorted(eids))

    def step_for(idx: int, nd: Dict[str, Any]) -> Dict[str, Any]:
        labs = list(nd.get("labels") or [])
        eid = str(nd.get("elementId") or "").strip()
        props = {k: v for k, v in nd.items() if k not in ("labels", "elementId")}
        kind = "unknown"
        if "AnalysisResult" in labs:
            kind = "analysis_result"
        elif "ChainNode" in labs:
            kind = "chain_node"
        elif "SinkFlowNode" in labs:
            kind = "sink_flow_node"
        elif "RiskCategory" in labs:
            kind = "risk_category"

        ids: Dict[str, str] = {}
        nid = nd.get("node_id")
        if nid and ("ChainNode" in labs or "RiskCategory" in labs or "AnalysisResult" in labs):
            ids["node_id"] = str(nid)
        if "SinkFlowNode" in labs:
            sid = nd.get("sink_node_id")
            if sid:
                ids["sink_node_id"] = str(sid)

        file_v = nd.get("file")
        line_v = nd.get("line")
        loc = None
        src_ctx = None
        if file_v and str(file_v).strip():
            loc = {"file": str(file_v).strip(), "line": line_v}
            src_ctx = _read_source_line_context(pr, file_v, line_v)

        audits = list(audit_by_eid.get(eid, [])) if eid else []

        return {
            "index": idx,
            "node_kind": kind,
            "labels": labs,
            "element_id": eid or None,
            "ids": ids,
            "properties": props,
            "audit_infos": audits,
            "location": loc,
            "source_context": src_ctx,
        }

    out_paths: List[Dict[str, Any]] = []
    for pi, path in enumerate(paths_raw):
        steps = [step_for(i, n) for i, n in enumerate(path)]
        out_paths.append({"path_id": f"p{pi}", "steps": steps})

    base["paths"] = out_paths
    return base


# ---------------------------------------------------------------------------
# 写入：ChainNode 创建 + FLOW 边
# ---------------------------------------------------------------------------

_CHAIN_NODE_REASON_SEP = "\n---\n"



def find_chain_node_by_file_function_and_category(
    file: str,
    function: str,
    category_name: str,
    task_id: str = "",
) -> Optional[Dict[str, Any]]:
    """
    在同一漏洞分类（RiskCategory.category_name）可达的 FLOW 子树中，
    按 file + function 查找已存在的 ChainNode。跨 category_name 不匹配。
    """
    repo = db_manager.neo4j_repository
    if repo is None:
        return None

    file_s = str(file or "").strip()
    func_s = str(function or "").strip()
    cat_s = str(category_name or "").strip()
    tid = str(task_id or "").strip()
    if not file_s or not func_s or not cat_s:
        return None

    records = repo.client.execute_query(
        """
        MATCH (rc:RiskCategory)
        WHERE rc.category_name = $cat
          AND ($tid = '' OR coalesce(rc.task_id, '') = $tid)
        MATCH (rc)-[:HAS_SINK]->(s:SinkFlowNode)
        MATCH (s)-[:FLOW*]->(cn:ChainNode)
        WHERE cn.file = $file AND cn.function = $func
          AND ($tid = '' OR coalesce(cn.task_id, '') = $tid)
        RETURN cn AS node, elementId(cn) AS elementId, labels(cn) AS labels
        ORDER BY coalesce(cn.created_at, '')
        LIMIT 1
        """,
        {"file": file_s, "func": func_s, "cat": cat_s, "tid": tid},
    )
    if not records:
        return None
    row = _neo_node_record_to_dict(records[0])
    return row or None


def merge_existing_chain_node(
    node_id: str,
    *,
    new_line: int = 0,
    new_reason: str = "",
    task_id: str = "",
) -> Optional[Dict[str, Any]]:
    """
    合并已存在 ChainNode：原节点无 line 时写入 new_line；将 new_reason 追加到 reason 末尾（``---`` 分隔）。
    """
    repo = db_manager.neo4j_repository
    if repo is None:
        return None

    nid = str(node_id or "").strip()
    tid = str(task_id or "").strip()
    if not nid:
        return None

    records = repo.client.execute_query(
        """
        MATCH (cn:ChainNode {node_id: $nid})
        WHERE $tid = '' OR coalesce(cn.task_id, '') = $tid
        RETURN cn AS node, elementId(cn) AS elementId, labels(cn) AS labels
        """,
        {"nid": nid, "tid": tid},
    )
    if not records:
        return None

    existing = _neo_node_record_to_dict(records[0])
    if not existing:
        return None

    old_line = existing.get("line", 0)
    line_to_set = old_line
    if old_line == 0:
        line_to_set = new_line

    old_reason = str(existing.get("reason") or "")
    new_reason_s = str(new_reason or "").strip()
    if new_reason_s:
        if old_reason.strip():
            merged_reason = old_reason.rstrip() + _CHAIN_NODE_REASON_SEP + new_reason_s
        else:
            merged_reason = new_reason_s
    else:
        merged_reason = old_reason

    write_records = repo.client.execute_write(
        """
        MATCH (cn:ChainNode {node_id: $nid})
        WHERE $tid = '' OR coalesce(cn.task_id, '') = $tid
        SET cn.line = $line, cn.reason = $reason
        RETURN cn AS node, elementId(cn) AS elementId, labels(cn) AS labels
        """,
        {"nid": nid, "tid": tid, "line": line_to_set, "reason": merged_reason},
    )
    if not write_records:
        return existing
    updated = _neo_node_record_to_dict(write_records[0])
    return updated or existing


def fetch_completed_analysis_result_downstream_of_chain_node(
    node_id: str,
    task_id: str = "",
) -> Optional[str]:
    """
    从 ChainNode 沿 :FLOW* 前向查找末端上 status=completed 的 AnalysisResult。

    Returns:
        AnalysisResult 的 Neo4j elementId；未找到则 None。
    """
    repo = db_manager.neo4j_repository
    nid = str(node_id or "").strip()
    tid = str(task_id or "").strip()
    if repo is None or not nid:
        return None

    records = repo.client.execute_query(
        f"""
        MATCH (cn:ChainNode {{node_id: $nid}})
        WHERE $tid = '' OR coalesce(cn.task_id, '') = $tid
        MATCH (cn)-[:FLOW*0..{_VUL_FLOW_MAX_DEPTH}]->(tail)
        WHERE tail:ChainNode OR tail:SinkFlowNode
        MATCH (tail)-[:HAS_RESULT]->(ar:AnalysisResult)
        WHERE coalesce(ar.status, '') = 'completed'
          AND ($tid = '' OR coalesce(ar.task_id, '') = $tid)
        RETURN elementId(ar) AS ar_element_id
        ORDER BY coalesce(ar.created_at, '')
        DESC
        LIMIT 1
        """,
        {"nid": nid, "tid": tid},
    )
    if not records:
        return None
    ar_eid = records[0].data().get("ar_element_id")
    if ar_eid is None:
        return None
    s = str(ar_eid).strip()
    return s or None


def create_chain_node(
    node_type: str,
    branch_id: str = "",
    file: str = "",
    line: int = 0,
    function: str = "",
    reason: str = "",
    task_id: str = "",
) -> Dict[str, Any]:
    """
    在 Neo4j 中创建一个 ChainNode。

    Returns:
        含业务属性及 elementId、labels（与 Neo4jRepository.create_node 一致）；
        至少含 node_id；创建失败时可能缺少 elementId/labels。
    """
    repo = db_manager.neo4j_repository
    node_id = generate_id("cn")
    props = {
        "node_id": node_id,
        "branch_id": branch_id,
        "type": node_type,
        "file": file,
        "line": line,
        "function": function,
        "reason": reason,
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "task_id": task_id or "",
    }
    row = repo.create_node("ChainNode", props)
    out = dict(row)
    out["node_id"] = node_id
    labs = out.get("labels")
    out["labels"] = list(labs) if labs is not None else []
    return out


def link_trace_from_sink_flow_node(
    source_sink_node_id: str,
    target_chain_node_id: str,
    task_id: str,
) -> None:
    """创建 SinkFlowNode -[:FLOW]-> ChainNode 边。"""
    repo = db_manager.neo4j_repository
    if repo is None or not str(task_id).strip():
        return
    tid = str(task_id).strip()
    repo.client.execute_write(
        """
        MATCH (a:SinkFlowNode {sink_node_id: $src, task_id: $task_id})
        MATCH (b:ChainNode {node_id: $dst, task_id: $task_id})
        MERGE (a)-[:FLOW]->(b)
        """,
        {"src": source_sink_node_id, "dst": target_chain_node_id, "task_id": tid},
    )


def link_trace_between_chain_nodes(
    source_node_id: str,
    target_node_id: str,
    task_id: str,
) -> None:
    """创建 ChainNode -[:FLOW]-> ChainNode 边。"""
    repo = db_manager.neo4j_repository
    if repo is None or not str(task_id).strip():
        return
    tid = str(task_id).strip()
    repo.client.execute_write(
        """
        MATCH (a:ChainNode {node_id: $src, task_id: $task_id})
        MATCH (b:ChainNode {node_id: $dst, task_id: $task_id})
        MERGE (a)-[:FLOW]->(b)
        """,
        {"src": source_node_id, "dst": target_node_id, "task_id": tid},
    )


def link_trace(
    source_id: str,
    target_node_id: str,
    source_is_sink_flow: bool,
    task_id: str,
) -> None:
    """
    统一的 :FLOW 边创建入口（SinkFinder 树内与分析扩展 ChainNode 均使用 :FLOW）。
    source_is_sink_flow=True 时 source_id 是 SinkFlowNode.sink_node_id，
    否则是 ChainNode.node_id。

    注意：同一个 source 可以有多条 :FLOW 出边（分叉场景）。
    """
    if source_is_sink_flow:
        link_trace_from_sink_flow_node(source_id, target_node_id, task_id)
    else:
        link_trace_between_chain_nodes(source_id, target_node_id, task_id)


# ---------------------------------------------------------------------------
# 写入：AnalysisResult 持久化
# ---------------------------------------------------------------------------

def persist_analysis_result(
    task_id: str,
    project_id: str,
    attach_to_node_id: str,
    attach_is_sink_flow: bool,
    resolution: Dict[str, Any],
    *,
    branch_id: str = "",
    category_name: str = "",
    project_root: str = "",
) -> Tuple[str, Optional[str]]:
    """
    将 LLM 的 final_resolution 写入 Neo4j 作为 AnalysisResult 节点，
    并通过 :HAS_RESULT 边连接到该分支的扩展末端。

    每个分支独立产出一个 AnalysisResult。

    同步写入 PostgreSQL：``vulnerability.category_name`` 存风险分类名；
    ``vulnerability_details.exploitation_chain``（JSONB）存从该结果沿 FLOW 反向到
    RiskCategory 的利用链导出（含审计与源码上下文），不写入 Neo4j。
    ``project_root`` 用于读取 file/line 周边源码；若为空则尝试从 Neo4j Task.path 推断。

    Returns:
        (AnalysisResult 的 Neo4j elementId, vulnerability_id 或 None)。前者与二次校验、
        ``fetch_flow_chain_nodes_for_analysis_result``、API ``/by-ar`` 的 ``ar_node_id`` 语义一致；
        节点上的业务 ``node_id`` 属性仍保留，但不作为跨层主键传递。
    """
    repo = db_manager.neo4j_repository
    tid = str(task_id).strip() if task_id else ""
    node_id = generate_id("ar")

    entry_points = resolution.get("entry_points") or []
    findings = resolution.get("findings") or []
    security_boundaries = resolution.get("security_boundaries") or []
    verdict = resolution.get("verdict", "SAFE")
    bid = (branch_id or resolution.get("branch_id") or "") or ""
    props = {
        "node_id": node_id,
        "verdict": verdict,
        "detail": resolution.get("detail", ""),
        "confidence": resolution.get("confidence", "LOW"),
        "vul_name": resolution.get("vul_name") or "",
        "task_id": tid,
    }
    if bid:
        props["branch_id"] = bid
    created_node = repo.create_node("AnalysisResult", props)
    ar_eid = str(created_node.get("elementId") or "").strip()

    if attach_is_sink_flow:
        repo.client.execute_write(
            """
            MATCH (a:SinkFlowNode {sink_node_id: $src, task_id: $task_id})
            MATCH (b:AnalysisResult)
            WHERE elementId(b) = $ar_eid
            MERGE (a)-[:HAS_RESULT]->(b)
            """,
            {"src": attach_to_node_id, "ar_eid": ar_eid, "task_id": tid},
        )
    else:
        repo.client.execute_write(
            """
            MATCH (a:ChainNode {node_id: $src, task_id: $task_id})
            MATCH (b:AnalysisResult)
            WHERE elementId(b) = $ar_eid
            MERGE (a)-[:HAS_RESULT]->(b)
            """,
            {"src": attach_to_node_id, "ar_eid": ar_eid, "task_id": tid},
        )
    result_element_id = ar_eid
    if verdict != "SAFE":
        exploitation_chain = build_exploitation_chain_document(
            ar_eid,
            project_root=project_root,
            task_id=tid,
        )
    else:
        return result_element_id, ""
    # 同步写入 PostgreSQL：主表仅存基础字段，详情字段进入 vulnerability_details。
    vulnerability_id: Optional[str] = None
    try:
        from src.services.vulnerability_service import create_finding

        finding = create_finding(
            project_id=project_id,
            task_id=task_id,
            vul_name=props["vul_name"] or "Unknown Vulnerability",
            verdict=props["verdict"],
            confidence=props["confidence"],
            neo4j_element_id=str(created_node.get("elementId") or ""),
            category_name=category_name,
            detail={
                "detail": resolution.get("detail", ""),
                "entry_points": json.dumps(entry_points, ensure_ascii=False),
                "evidence": json.dumps(findings, ensure_ascii=False),
                "security_boundaries": json.dumps(security_boundaries, ensure_ascii=False),
                "analysis_rounds": int(resolution.get("analysis_rounds", 0) or 0),
                "exploitation_chain": exploitation_chain,
            },
        )
        vulnerability_id = finding.id
    except Exception:
        # PostgreSQL 镜像失败不阻塞主分析链路，避免影响图写入。
        pass

    return result_element_id, vulnerability_id


# ---------------------------------------------------------------------------
# 写入：更新 AnalysisResult 的验证状态（二次校验结果）
# ---------------------------------------------------------------------------

def update_analysis_result_verification(
    ar_node_id: str,
    verification_status: str,
    verification_reason: str,
    vulnerability_analysis_report: Optional[str] = None,
    poc: Optional[str] = None,
    vul_id: str = None,
    level: Optional[str] = None,
) -> bool:
    """
    将二次校验结果写回：
    - Neo4j AnalysisResult：仅 verification_status
    - PostgreSQL vulnerability：verification_status；当 level 非空时写入 severity 等级
    - PostgreSQL vulnerability_details：verification_reason /
      vulnerability_analysis_report / poc

    Args:
        ar_node_id: AnalysisResult 的 Neo4j elementId（与 ``_ar_node_id`` 一致）
        verification_status: CONFIRMED / REJECTED
        verification_reason: 判定理由
        vulnerability_analysis_report: 完整 Markdown 漏洞分析报告正文
        poc: 可运行 Python POC 源码
        level: CRITICAL / HIGH / MEDIUM / LOW / INFO 等；仅非空时更新主表

    Returns:
        是否更新成功
    """
    repo = db_manager.neo4j_repository
    if repo is None or not ar_node_id:
        return False

    report_md = vulnerability_analysis_report if isinstance(vulnerability_analysis_report, str) else ""
    poc_src = poc if isinstance(poc, str) else ""

    records = repo.client.execute_write(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $nid
        SET ar.verification_status = $status
        SET ar.level = $level
        RETURN elementId(ar) AS eid
        """,
        {
            "nid": ar_node_id,
            "status": verification_status,
            "level": level,
        },
    )
    neo4j_ok = bool(records)

    # 同步写入 PostgreSQL 的漏洞详情（按 vulnerability.id 绑定）。
    pg_ok = True
    if vul_id:
        try:
            from src.infrastructure.db import session_scope
            from src.infrastructure.db.models import Vulnerability, VulnerabilityDetail

            with session_scope() as session:
                vul_row = session.get(Vulnerability, vul_id)
                if vul_row is not None:
                    vul_row.verification_status = verification_status or ""
                    lvl = (level or "").strip() if isinstance(level, str) else ""
                    if lvl:
                        vul_row.level = lvl
                detail_row = session.get(VulnerabilityDetail, vul_id)
                if detail_row is None:
                    detail_row = VulnerabilityDetail(vulnerability_id=vul_id)
                    session.add(detail_row)
                detail_row.verification_reason = verification_reason or ""
                detail_row.vulnerability_analysis_report = report_md
                detail_row.poc = poc_src
                session.flush()
        except Exception:
            pg_ok = False

    return neo4j_ok and pg_ok


# ---------------------------------------------------------------------------
# 写入：AuditInfo（record_info）挂到任意已有图节点（按 elementId）
# ---------------------------------------------------------------------------

def attach_audit_info_record(
    target_element_id: str,
    content: str,
    branch_id: str = "",
    task_id: str = "",
) -> Dict[str, Any]:
    """
    在目标节点（通过 Neo4j elementId 匹配）上挂接一个 AuditInfo 节点。

    Returns:
        {"ok": True, "audit_node_id": str, "target_element_id": str} 或
        {"ok": False, "error": str}
    """
    repo = db_manager.neo4j_repository
    eid = (target_element_id or "").strip()
    text = (content or "").strip()
    if not eid:
        return {"ok": False, "error": "target.elementId 不能为空"}
    if not text:
        return {"ok": False, "error": "info.content 不能为空"}
    if repo is None:
        return {"ok": False, "error": "Neo4j 未初始化"}

    audit_node_id = generate_id("ai")
    tid = str(task_id).strip() if task_id else ""
    props = {
        "node_id": audit_node_id,
        "branch_id": branch_id,
        "content": text,
        "created_at": datetime.now().isoformat(),
        "task_id": tid,
    }
    records = repo.client.execute_write(
        """
        MATCH (t)
        WHERE elementId(t) = $eid
        CREATE (a:AuditInfo {
            node_id: $audit_id,
            branch_id: $branch,
            content: $content,
            created_at: $created,
            task_id: $task_id
        })
        CREATE (t)-[:HAS_AUDIT_INFO]->(a)
        RETURN a.node_id AS audit_node_id
        """,
        {
            "eid": eid,
            "audit_id": audit_node_id,
            "branch": branch_id,
            "content": text,
            "created": props["created_at"],
            "task_id": tid,
        },
    )
    if not records:
        return {"ok": False, "error": f"未找到 elementId={eid} 的节点"}
    return {
        "ok": True,
        "audit_node_id": records[0].data().get("audit_node_id", audit_node_id),
        "target_element_id": eid,
    }

