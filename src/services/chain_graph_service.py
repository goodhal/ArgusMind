# -*- coding: utf-8 -*-
"""
链路图 API：从 Neo4j 组装 React Flow 所需的 nodes / edges（见 src/doc/frontend_chain_graph_reactflow.md）。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import src.storage.manager as db_manager
from services import chain_analysis_service as cas

# 与 chain_analysis_service 中可变长 FLOW 上界一致
_MAX_FLOW_DEPTH = getattr(cas, "_VUL_FLOW_MAX_DEPTH", 150)

_PATH_LIMIT = 2500


def _repo():
    return db_manager.neo4j_repository


def verify_risk_category_for_task(vul_node_id: str, task_id: str) -> bool:
    """Neo4j 中是否存在 (RiskCategory {node_id, task_id})。"""
    repo = _repo()
    if repo is None or not vul_node_id or not task_id:
        return False
    recs = repo.client.execute_read(
        """
        MATCH (rc:RiskCategory {node_id: $nid, task_id: $tid})
        RETURN 1 AS ok
        LIMIT 1
        """,
        {"nid": str(vul_node_id).strip(), "tid": str(task_id).strip()},
    )
    return bool(recs)


def verify_analysis_result_for_task(ar_node_id: str, task_id: str) -> bool:
    """AnalysisResult（按 Neo4j elementId）是否挂在该 task 下任一 RiskCategory 的 HAS_SINK→FLOW* 子图上。"""
    repo = _repo()
    if repo is None or not ar_node_id or not task_id:
        return False
    aid = str(ar_node_id).strip()
    tid = str(task_id).strip()
    recs = repo.client.execute_read(
        f"""
        MATCH (rc:RiskCategory {{task_id: $tid}})-[:HAS_SINK]->(root:SinkFlowNode)
        MATCH (root)-[:FLOW*0..{_MAX_FLOW_DEPTH}]->(x)
        WHERE (x:SinkFlowNode OR x:ChainNode)
          AND EXISTS {{
            MATCH (x)-[:HAS_RESULT]->(ar2:AnalysisResult)
            WHERE elementId(ar2) = $aid
          }}
        RETURN 1 AS ok
        LIMIT 1
        """,
        {"tid": tid, "aid": aid},
    )
    if recs:
        return True
    # 兜底：部分环境可能给 AnalysisResult 打了 task_id
    recs2 = repo.client.execute_read(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $aid AND ar.task_id = $tid
        RETURN 1 AS ok
        LIMIT 1
        """,
        {"aid": aid, "tid": tid},
    )
    return bool(recs2)


def _element_id(n: Any) -> str:
    if hasattr(n, "element_id"):
        return str(n.element_id)
    return str(n.get("elementId") or "")


def _labels(n: Any) -> List[str]:
    if hasattr(n, "labels"):
        return list(n.labels or [])
    return list(n.get("labels") or [])


def _props(n: Any) -> Dict[str, Any]:
    if hasattr(n, "items"):
        return dict(n)
    return dict(n.get("properties") or n)


def _node_kind(labels: List[str]) -> str:
    if "AnalysisResult" in labels:
        return "result"
    if "ChainNode" in labels:
        return "chain"
    if "SinkFlowNode" in labels:
        return "sinkFlow"
    if "RiskCategory" in labels:
        return "vulnRoot"
    return "other"


def _summary_for_node(kind: str, props: Dict[str, Any]) -> Dict[str, Any]:
    if kind == "sinkFlow":
        return {
            "file": props.get("file") or "",
            "line": int(props.get("line") or 0),
            "end_line": int(props.get("end_line") or 0),
            "function": props.get("function") or "",
        }
    if kind == "chain":
        return {
            "file": props.get("file") or "",
            "line": int(props.get("line") or 0),
            "function": props.get("function") or "",
        }
    if kind == "result":
        return {
            "vul_name": props.get("vul_name") or "",
        }
    if kind == "vulnRoot":
        return {
            "category_name": props.get("category_name") or "",
        }
    return {}


def _graph_node_payload(
    *,
    element_id: str,
    labels: List[str],
    props: Dict[str, Any],
) -> Dict[str, Any]:
    kind = _node_kind(labels)
    status = props.get("status")
    if status is not None:
        status = str(status)
    out: Dict[str, Any] = {
        "id": element_id,
        "labels": labels,
        "kind": kind,
        "status": status,
        "summary": _summary_for_node(kind, props),
        "branch_id": str(props.get("branch_id") or ""),
        "chain_semantic_type": props.get("type") if kind == "chain" else None,
        "verdict": props.get("verdict") if kind == "result" else None,
        "verification_status": props.get("verification_status") if kind == "result" else None,
    }
    if kind == "result":
        out["confidence"] = props.get("confidence")
    return out


def _root_label(props: Dict[str, Any]) -> str:
    fn = props.get("function") or ""
    fp = props.get("file") or ""
    ln = int(props.get("line") or 0)
    if fn:
        return str(fn)
    if fp and ln:
        return f"{fp}:{ln}"
    return fp or props.get("sink_node_id") or ""


def _compute_graph_version(nodes: List[Dict], edges: List[Dict]) -> str:
    ids = sorted(n["id"] for n in nodes)
    ekeys = sorted(f"{e.get('source')}|{e.get('target')}|{e.get('relType')}|{e.get('id')}" for e in edges)
    raw = json.dumps({"n": ids, "e": ekeys}, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def fetch_graph_by_vul(
    vul_node_id: str,
    task_id: str,
    *,
    max_depth: int,
    include_completed_results: bool,
) -> Dict[str, Any]:
    """
    返回某 RiskCategory（漏洞上下文）下 HAS_SINK 子图 + FLOW* + HAS_RESULT（可选过滤 completed）。
    """
    repo = _repo()
    if repo is None:
        return _empty_graph()

    depth = max(1, min(int(max_depth or _MAX_FLOW_DEPTH), _MAX_FLOW_DEPTH))
    vid = str(vul_node_id).strip()
    tid = str(task_id).strip()

    rc_recs = repo.client.execute_read(
        """
        MATCH (rc:RiskCategory {node_id: $vid, task_id: $tid})
        RETURN rc AS rc
        LIMIT 1
        """,
        {"vid": vid, "tid": tid},
    )
    if not rc_recs:
        return _empty_graph()

    rc = rc_recs[0].data().get("rc")
    neo_nodes: Dict[str, Tuple[List[str], Dict[str, Any]]] = {}
    if rc is not None:
        eid_rc = _element_id(rc)
        neo_nodes[eid_rc] = (_labels(rc), _props(rc))

    root_rows = repo.client.execute_read(
        """
        MATCH (rc:RiskCategory {node_id: $vid, task_id: $tid})-[:HAS_SINK]->(root:SinkFlowNode)
        RETURN DISTINCT root AS root
        """,
        {"vid": vid, "tid": tid},
    )
    roots: List[Any] = []
    for rr in root_rows or []:
        root = rr.data().get("root")
        if root is not None:
            roots.append(root)
            eid = _element_id(root)
            neo_nodes[eid] = (_labels(root), _props(root))

    mid_recs = repo.client.execute_read(
        f"""
        MATCH (rc:RiskCategory {{node_id: $vid, task_id: $tid}})-[:HAS_SINK]->(root:SinkFlowNode)
        MATCH (root)-[:FLOW*0..{depth}]->(m)
        WHERE m:SinkFlowNode OR m:ChainNode
        RETURN DISTINCT m AS m
        LIMIT $path_limit
        """,
        {"vid": vid, "tid": tid, "path_limit": _PATH_LIMIT},
    )
    for mr in mid_recs or []:
        m = mr.data().get("m")
        if m is None:
            continue
        eid = _element_id(m)
        neo_nodes[eid] = (_labels(m), _props(m))

    if len(neo_nodes) <= 1 and not roots:
        # 仅有 rc 且无 HAS_SINK
        nodes_out = [_graph_node_payload(element_id=eid, labels=labs, props=props) for eid, (labs, props) in neo_nodes.items()]
        gv = _compute_graph_version(nodes_out, [])
        return {"graph_version": gv, "roots": [], "nodes": nodes_out, "edges": []}

    id_list = list(neo_nodes.keys())

    edges: List[Dict[str, Any]] = []
    seen_e: Set[str] = set()

    flow_recs = repo.client.execute_read(
        """
        UNWIND $ids AS eid
        MATCH (a) WHERE elementId(a) = eid
        MATCH (a)-[r:FLOW]->(b)
        WHERE elementId(b) IN $ids
        RETURN elementId(r) AS rid, type(r) AS typ, elementId(a) AS src, elementId(b) AS tgt
        """,
        {"ids": id_list},
    )
    for fr in flow_recs or []:
        d = fr.data()
        rid = str(d.get("rid") or "")
        if not rid or rid in seen_e:
            continue
        seen_e.add(rid)
        edges.append(
            {
                "id": rid,
                "source": d.get("src"),
                "target": d.get("tgt"),
                "relType": d.get("typ") or "FLOW",
            }
        )

    for fr in repo.client.execute_read(
        """
        MATCH (rc:RiskCategory {node_id: $vid, task_id: $tid})-[r:HAS_SINK]->(s:SinkFlowNode)
        RETURN elementId(rc) AS src, elementId(s) AS tgt, elementId(r) AS rid
        """,
        {"vid": vid, "tid": tid},
    ) or []:
        d = fr.data()
        rid = str(d.get("rid") or f"has_sink:{d.get('src')}:{d.get('tgt')}")
        if rid not in seen_e:
            seen_e.add(rid)
            edges.append(
                {
                    "id": rid,
                    "source": d.get("src"),
                    "target": d.get("tgt"),
                    "relType": "HAS_SINK",
                }
            )

    inc = include_completed_results
    hr_cypher = """
        UNWIND $ids AS eid
        MATCH (a) WHERE elementId(a) = eid
        MATCH (a)-[r:HAS_RESULT]->(ar:AnalysisResult)
        """
    if not inc:
        hr_cypher += " WHERE coalesce(ar.status, '') <> 'completed' "
    hr_cypher += """
        RETURN elementId(r) AS rid, elementId(a) AS src, elementId(ar) AS tgt,
               ar AS node, labels(ar) AS labels
        """
    for fr in repo.client.execute_read(hr_cypher, {"ids": id_list}) or []:
        d = fr.data()
        rid = str(d.get("rid") or "")
        if not rid or rid in seen_e:
            continue
        seen_e.add(rid)
        tgt = d.get("tgt")
        ar_node = d.get("node")
        ar_labels = list(d.get("labels") or [])
        if tgt and ar_node is not None:
            neo_nodes[str(tgt)] = (ar_labels, _props(ar_node))
        edges.append(
            {
                "id": rid,
                "source": d.get("src"),
                "target": d.get("tgt"),
                "relType": "HAS_RESULT",
            }
        )

    nodes_out = [_graph_node_payload(element_id=eid, labels=labs, props=props) for eid, (labs, props) in neo_nodes.items()]
    roots_out: List[Dict[str, Any]] = []
    for r in roots:
        eid = _element_id(r)
        _, props = neo_nodes.get(eid, ([], {}))
        roots_out.append({"id": eid, "kind": "sinkFlow", "label": _root_label(props)})

    graph_version = _compute_graph_version(nodes_out, edges)
    return {
        "graph_version": graph_version,
        "roots": roots_out,
        "nodes": nodes_out,
        "edges": edges,
    }


def fetch_graph_by_ar(
    ar_node_id: str,
    task_id: str,
) -> Dict[str, Any]:
    """单条 AnalysisResult 对应的 FLOW 链 + AR 节点 + 边。"""
    repo = _repo()
    if repo is None:
        return _empty_graph()

    chain = cas.fetch_flow_chain_nodes_for_analysis_result(str(ar_node_id).strip())
    if not chain:
        return _empty_graph()

    neo_nodes: Dict[str, Tuple[List[str], Dict[str, Any]]] = {}
    for n in chain:
        eid = str(n.get("elementId") or "").strip()
        if not eid:
            continue
        labs = list(n.get("labels") or [])
        props = {k: v for k, v in n.items() if k not in ("elementId", "labels")}
        neo_nodes[eid] = (labs, props)

    ar_recs = repo.client.execute_read(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $aid
        RETURN ar AS node, elementId(ar) AS elementId, labels(ar) AS labels
        LIMIT 1
        """,
        {"aid": str(ar_node_id).strip()},
    )
    edges: List[Dict[str, Any]] = []
    seen_e: Set[str] = set()

    # FLOW along chain order (upstream -> downstream)
    eids = [str(n.get("elementId") or "").strip() for n in chain if n.get("elementId")]
    for i in range(len(eids) - 1):
        a, b = eids[i], eids[i + 1]
        rid = f"flow:{a}:{b}"
        if rid not in seen_e:
            seen_e.add(rid)
            edges.append({"id": rid, "source": a, "target": b, "relType": "FLOW"})

    if ar_recs:
        d = ar_recs[0].data()
        ar_el = str(d.get("elementId") or "").strip()
        ar_node = d.get("node")
        ar_labels = list(d.get("labels") or [])
        if ar_el and ar_node is not None:
            neo_nodes[ar_el] = (ar_labels, _props(ar_node))
        tail = eids[-1] if eids else ""
        if tail and ar_el:
            hr = repo.client.execute_read(
                """
                MATCH (t)-[r:HAS_RESULT]->(ar:AnalysisResult)
                WHERE elementId(t) = $teid AND elementId(ar) = $aid
                RETURN elementId(r) AS rid
                LIMIT 1
                """,
                {"aid": str(ar_node_id).strip(), "teid": tail},
            )
            rid = str(hr[0].data().get("rid")) if hr else f"has_result:{tail}:{ar_el}"
            if rid not in seen_e:
                seen_e.add(rid)
                edges.append({"id": rid, "source": tail, "target": ar_el, "relType": "HAS_RESULT"})

    nodes_out = [_graph_node_payload(element_id=eid, labels=labs, props=props) for eid, (labs, props) in neo_nodes.items()]
    first_props = chain[0] if chain else {}
    if isinstance(first_props, dict):
        rlab = _root_label(first_props)
        fkind = _node_kind(list(first_props.get("labels") or []))
    else:
        rlab = ""
        fkind = "sinkFlow"
    roots_out = [{"id": eids[0], "kind": fkind, "label": rlab}] if eids else []
    gv = _compute_graph_version(nodes_out, edges)
    return {"graph_version": gv, "roots": roots_out, "nodes": nodes_out, "edges": edges}


def _empty_graph() -> Dict[str, Any]:
    return {"graph_version": "0" * 32, "roots": [], "nodes": [], "edges": []}


def element_in_task_subgraph(element_id: str, task_id: str) -> bool:
    """节点 elementId 是否落在该 task 下任一 RiskCategory 的 HAS_SINK→FLOW* 子图（含 HAS_RESULT 目标）。"""
    repo = _repo()
    if repo is None or not element_id or not task_id:
        return False
    eid = str(element_id).strip()
    tid = str(task_id).strip()
    checks = [
        (
            """
            MATCH (rc:RiskCategory {task_id: $tid})
            WHERE elementId(rc) = $eid
            RETURN 1 AS ok LIMIT 1
            """,
            {"tid": tid, "eid": eid},
        ),
        (
            f"""
            MATCH (rc:RiskCategory {{task_id: $tid}})-[:HAS_SINK]->(root:SinkFlowNode)
            MATCH (root)-[:FLOW*0..{_MAX_FLOW_DEPTH}]->(x)
            WHERE elementId(x) = $eid
            RETURN 1 AS ok LIMIT 1
            """,
            {"tid": tid, "eid": eid},
        ),
        (
            f"""
            MATCH (rc:RiskCategory {{task_id: $tid}})-[:HAS_SINK]->(root:SinkFlowNode)
            MATCH (root)-[:FLOW*0..{_MAX_FLOW_DEPTH}]->(x)-[:HAS_RESULT]->(ar:AnalysisResult)
            WHERE elementId(ar) = $eid
            RETURN 1 AS ok LIMIT 1
            """,
            {"tid": tid, "eid": eid},
        ),
    ]
    for cypher, params in checks:
        recs = repo.client.execute_read(cypher, params)
        if recs and recs[0].data().get("ok"):
            return True
    recs2 = repo.client.execute_read(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $eid AND ar.task_id = $tid
        RETURN 1 AS ok LIMIT 1
        """,
        {"eid": eid, "tid": tid},
    )
    return bool(recs2 and recs2[0].data().get("ok"))


def fetch_node_by_business_id(kind: str, business_id: str) -> Optional[Tuple[str, List[str], Dict[str, Any]]]:
    """返回 (elementId, labels, props)。"""
    repo = _repo()
    if repo is None or not business_id:
        return None
    bid = str(business_id).strip()
    k = str(kind or "").strip().lower()
    if k == "sinkflow":
        recs = repo.client.execute_read(
            """
            MATCH (s:SinkFlowNode {sink_node_id: $bid})
            RETURN s AS node, elementId(s) AS eid, labels(s) AS labels
            LIMIT 1
            """,
            {"bid": bid},
        )
    elif k == "chain":
        recs = repo.client.execute_read(
            """
            MATCH (c:ChainNode {node_id: $bid})
            RETURN c AS node, elementId(c) AS eid, labels(c) AS labels
            LIMIT 1
            """,
            {"bid": bid},
        )
    elif k == "result":
        recs = repo.client.execute_read(
            """
            MATCH (ar:AnalysisResult)
            WHERE elementId(ar) = $bid
            RETURN ar AS node, elementId(ar) AS eid, labels(ar) AS labels
            LIMIT 1
            """,
            {"bid": bid},
        )
    else:
        return None
    if not recs:
        return None
    d = recs[0].data()
    node = d.get("node")
    if node is None:
        return None
    return (str(d.get("eid")), list(d.get("labels") or []), _props(node))


def fetch_node_detail(
    *,
    task_id: str,
    element_id: Optional[str] = None,
    kind: Optional[str] = None,
    business_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    全量属性 + HAS_AUDIT_INFO 文本列表 +（若为链上节点）关联 AnalysisResult 摘要列表。
    """
    repo = _repo()
    if repo is None or not task_id:
        return None
    tid = str(task_id).strip()

    eid: Optional[str] = None
    labels: List[str] = []
    props: Dict[str, Any] = {}

    if element_id and str(element_id).strip():
        eid = str(element_id).strip()
        if not element_in_task_subgraph(eid, tid):
            return None
        recs = repo.client.execute_read(
            """
            MATCH (n) WHERE elementId(n) = $eid
            RETURN n AS node, labels(n) AS labels
            LIMIT 1
            """,
            {"eid": eid},
        )
        if not recs:
            return None
        d = recs[0].data()
        node = d.get("node")
        if node is None:
            return None
        labels = list(d.get("labels") or [])
        props = _props(node)
    elif kind and business_id:
        row = fetch_node_by_business_id(kind, business_id)
        if row is None:
            return None
        eid, labels, props = row
        if not element_in_task_subgraph(eid, tid):
            return None
    else:
        return None

    audit_map = cas.fetch_audit_info_contents_by_element_ids([eid])
    audit_list = audit_map.get(eid, [])

    related_ar: List[Dict[str, Any]] = []
    if "SinkFlowNode" in labels or "ChainNode" in labels:
        recs = repo.client.execute_read(
            """
            MATCH (n) WHERE elementId(n) = $eid
            OPTIONAL MATCH (n)-[:HAS_RESULT]->(ar:AnalysisResult)
            WITH ar WHERE ar IS NOT NULL
            RETURN DISTINCT ar.node_id AS node_id,
                   ar.verdict AS verdict,
                   ar.status AS status,
                   ar.confidence AS confidence,
                   coalesce(ar.verification_status, '') AS verification_status
            """,
            {"eid": eid},
        )
        for r in recs or []:
            dd = r.data()
            if dd.get("node_id"):
                related_ar.append(
                    {
                        "node_id": dd.get("node_id"),
                        "verdict": dd.get("verdict"),
                        "status": dd.get("status"),
                        "confidence": dd.get("confidence"),
                        "verification_status": dd.get("verification_status"),
                    }
                )

    return {
        "id": eid,
        "labels": labels,
        "kind": _node_kind(labels),
        "properties": props,
        "audit_info_contents": audit_list,
        "related_analysis_results": related_ar,
    }
