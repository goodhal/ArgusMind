# -*- coding: utf-8 -*-
"""图可视化：Neo4j 查询与结果组装（供 API 路由调用）。"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Set, Tuple

import src.storage.manager as db_manager

logger = logging.getLogger(__name__)

_FLOW_MAX_DEPTH = 128  # 仅用于主链 :FLOW* 反向展开（与 chain_analysis 一致）
_PATH_LIMIT = 50  # Language→AR 主链路径条数上限（FLOW 分叉时截断）


def fetch_task_neighborhood_graph(task_id: str) -> Dict[str, Any]:
    """
    以 ``task_id`` 定位 Neo4j ``Task`` 节点，返回与其在同一无向连通分量内的
    **全部**节点及两端均落在该集合内的**全部**关系（不在 API 层限制深度或条数）。

    说明：Cypher 使用 ``-[*1..]-`` 表示长度 ≥1 的无界路径；仅 ``Task`` 自身且无出边时
    仍返回该 ``Task`` 节点。
    """
    repo = db_manager.neo4j_repository
    if repo is None:
        return {"nodes": [], "edges": []}

    tid = str(task_id).strip()
    if not tid:
        return {"nodes": [], "edges": []}

    # 1) 连通分量内所有节点（含 Task 根 p）
    node_recs = repo.client.execute_read(
        """
        MATCH (p:Task {task_id: $task_id})
        OPTIONAL MATCH (p)-[*1..]-(m)
        WITH p, [x IN collect(DISTINCT m) WHERE x IS NOT NULL] AS reached
        WITH CASE WHEN size(reached) = 0 THEN [p] ELSE [p] + reached END AS raw
        UNWIND raw AS node
        WITH DISTINCT node
        RETURN elementId(node) AS eid,
               labels(node) AS labels,
               properties(node) AS props
        """,
        {"task_id": tid},
    )

    if not node_recs:
        return {"nodes": [], "edges": []}

    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    eids: List[str] = []
    for rec in node_recs:
        row = rec.data()
        eid = str(row.get("eid") or "").strip()
        if not eid:
            continue
        eids.append(eid)
        nodes_by_id[eid] = {
            "elementId": eid,
            "labels": list(row.get("labels") or []),
            "props": dict(row.get("props") or {}),
        }

    if not eids:
        return {"nodes": [], "edges": []}

    # 2) 两端均在分量内的所有无向关系（每条关系仅输出一次）
    edge_recs = repo.client.execute_read(
        """
        UNWIND $eids AS eid
        MATCH (a) WHERE elementId(a) = eid
        MATCH (a)-[r]-(b)
        WHERE elementId(b) IN $eids AND elementId(a) <= elementId(b)
        RETURN DISTINCT elementId(r) AS rid,
               type(r) AS typ,
               elementId(startNode(r)) AS src,
               elementId(endNode(r)) AS tgt,
               properties(r) AS rprops
        """,
        {"eids": eids},
    )

    edges: List[Dict[str, Any]] = []
    seen_rid: Set[str] = set()
    for rec in edge_recs or []:
        row = rec.data()
        rid = str(row.get("rid") or "").strip()
        if not rid or rid in seen_rid:
            continue
        seen_rid.add(rid)
        edges.append(
            {
                "elementId": rid,
                "type": row.get("typ"),
                "start": row.get("src"),
                "end": row.get("tgt"),
                "props": dict(row.get("rprops") or {}),
            }
        )

    return {"nodes": list(nodes_by_id.values()), "edges": edges}


def _map_nodes(raw: Any, seen: Set[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for n in raw or []:
        if not n or not isinstance(n, dict):
            continue
        eid = n.get("elementId")
        if not eid or eid in seen:
            continue
        seen.add(eid)
        out.append({
            "elementId": eid,
            "labels": list(n.get("labels") or []),
            "props": dict(n.get("props") or {}),
        })
    return out


def _task_id_matches(tid: str, *props: Any) -> bool:
    if not tid:
        return True
    for p in props:
        if p and str(p).strip() == tid:
            return True
    return False


def _fetch_paths_to_language_fallback(
    repo: Any, tid: str, ar_id: str
) -> Dict[str, Any]:
    """
    与 chain_analysis 导出链一致的 FLOW 反查 + RC/Language 挂载；
    Cypher 变长路径未命中时兜底（含 *0 跳 FLOW、分叉）。
    """
    from src.services.chain_analysis_service import (
        _fetch_flow_parents,
        _fetch_risk_categories_for_sink,
        _neo_node_record_to_dict,
    )

    ar_recs = repo.client.execute_read(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $ar_id
        RETURN ar AS node, elementId(ar) AS elementId, labels(ar) AS labels
        LIMIT 1
        """,
        {"ar_id": ar_id},
    )
    if not ar_recs:
        return {"nodes": [], "edges": [], "paths": []}
    ar = _neo_node_record_to_dict(ar_recs[0])
    ar_eid = str(ar.get("elementId") or "").strip()
    if not ar_eid:
        return {"nodes": [], "edges": [], "paths": []}

    tail_recs = repo.client.execute_read(
        """
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $ar_id
        MATCH (z)-[:HAS_RESULT]->(ar)
        WHERE z:SinkFlowNode OR z:ChainNode
        RETURN z AS node, elementId(z) AS elementId, labels(z) AS labels
        """,
        {"ar_id": ar_id},
    )
    tails = [_neo_node_record_to_dict(r) for r in (tail_recs or [])]
    tails = [t for t in tails if t and t.get("elementId")]

    path_eids: List[List[str]] = []
    node_by_eid: Dict[str, Dict[str, Any]] = {ar_eid: ar}

    def _remember(nd: Dict[str, Any]) -> str:
        eid = str(nd.get("elementId") or "").strip()
        if eid:
            node_by_eid[eid] = nd
        return eid

    def _chain_identity(nd: Dict[str, Any]) -> Tuple[str, str]:
        labs = nd.get("labels") or []
        if "ChainNode" in labs:
            return ("cn", str(nd.get("node_id") or "").strip())
        if "SinkFlowNode" in labs:
            return ("sf", str(nd.get("sink_node_id") or "").strip())
        return ("unk", str(nd.get("elementId") or "").strip())

    def dfs(current: Dict[str, Any], suffix: List[Dict[str, Any]], vis: Set[Tuple[str, str]]) -> None:
        if len(path_eids) >= _PATH_LIMIT:
            return
        if len(suffix) > _FLOW_MAX_DEPTH + 2:
            return
        ident = _chain_identity(current)
        if ident in vis:
            return
        vis2 = set(vis)
        vis2.add(ident)
        parents = _fetch_flow_parents(repo, current, tid)
        if not parents:
            labs = current.get("labels") or []
            if "SinkFlowNode" in labs:
                sid = current.get("sink_node_id")
                rcs = (
                    _fetch_risk_categories_for_sink(repo, str(sid or ""), tid)
                    if sid
                    else []
                )
                for rc in rcs:
                    lang_recs = repo.client.execute_read(
                        """
                        MATCH (lang:Language)-[:HAS_RISK_CATEGORY]->(rc:RiskCategory)
                        WHERE elementId(rc) = $rc_eid
                        RETURN lang AS node, elementId(lang) AS elementId, labels(lang) AS labels
                        """,
                        {"rc_eid": str(rc.get("elementId") or "").strip()},
                    )
                    for lr in lang_recs or []:
                        lang = _neo_node_record_to_dict(lr)
                        if not lang:
                            continue
                        if not _task_id_matches(
                            tid,
                            lang.get("task_id"),
                            rc.get("task_id"),
                        ):
                            continue
                        lang_eid = _remember(lang)
                        rc_eid = _remember(rc)
                        if not lang_eid or not rc_eid:
                            continue
                        mid = [_remember(n) for n in suffix]
                        mid = [e for e in mid if e]
                        path_eids.append([ar_eid] + list(reversed(mid)) + [rc_eid, lang_eid])
                        if len(path_eids) >= _PATH_LIMIT:
                            return
            return
        for p in parents:
            if not p:
                continue
            dfs(p, [p] + suffix, vis2)

    for tail in tails:
        if len(path_eids) >= _PATH_LIMIT:
            break
        _remember(tail)
        dfs(tail, [tail], set())

    if not path_eids:
        return {"nodes": [], "edges": [], "paths": []}

    path_eids.sort(key=len)
    all_eids = list({e for p in path_eids for e in p})
    node_maps: List[Dict[str, Any]] = []
    for eid in all_eids:
        nd = node_by_eid.get(eid)
        if not nd:
            continue
        node_maps.append({
            "elementId": eid,
            "labels": list(nd.get("labels") or []),
            "props": {k: v for k, v in nd.items() if k not in ("labels", "elementId")},
        })

    edge_recs = repo.client.execute_read(
        """
        UNWIND $eids AS eid
        MATCH (a) WHERE elementId(a) = eid
        MATCH (a)-[r]->(b)
        WHERE elementId(b) IN $eids
          AND type(r) IN ['FLOW', 'HAS_RESULT', 'HAS_SINK', 'HAS_RISK_CATEGORY']
        RETURN DISTINCT elementId(r) AS elementId,
               type(r) AS type,
               elementId(startNode(r)) AS start,
               elementId(endNode(r)) AS end,
               properties(r) AS props
        """,
        {"eids": all_eids},
    )
    edge_maps: List[Dict[str, Any]] = []
    for rec in edge_recs or []:
        row = rec.data()
        edge_maps.append({
            "elementId": row.get("elementId"),
            "type": row.get("type"),
            "start": row.get("start"),
            "end": row.get("end"),
            "props": dict(row.get("props") or {}),
        })

    return {"nodes": node_maps, "edges": edge_maps, "paths": path_eids}


def _fetch_canonical_paths_to_language(
    repo: Any, tid: str, ar_id: str
) -> Dict[str, Any]:
    """
    沿审计主链 Language→RC→Sink 根→FLOW*→HAS_RESULT→AR 收集路径（*0 跳 FLOW 含叶即根）。
    """
    recs = repo.client.execute_read(
        f"""
        MATCH (ar:AnalysisResult)
        WHERE elementId(ar) = $ar_id
        MATCH (z)-[:HAS_RESULT]->(ar)
        WHERE z:SinkFlowNode OR z:ChainNode
        MATCH p = (lang:Language)-[:HAS_RISK_CATEGORY]->(rc:RiskCategory)
                  -[:HAS_SINK]->(root:SinkFlowNode)
                  -[:FLOW*0..{_FLOW_MAX_DEPTH}]->(z)
                  -[:HAS_RESULT]->(ar)
        WHERE ($tid = '' OR rc.task_id = $tid OR lang.task_id = $tid)
        WITH p
        ORDER BY length(p) ASC
        LIMIT {_PATH_LIMIT}
        WITH collect(p) AS paths
        WHERE size(paths) > 0
        UNWIND paths AS p1
        UNWIND nodes(p1) AS spine_n
        WITH paths, collect(DISTINCT spine_n) AS spine_ns
        UNWIND paths AS p2
        UNWIND relationships(p2) AS spine_r
        WITH paths, spine_ns, collect(DISTINCT spine_r) AS spine_rs
        RETURN
          [n IN spine_ns | {{
            elementId: elementId(n),
            labels: labels(n),
            props: properties(n)
          }}] AS nodes,
          [r IN spine_rs | {{
            elementId: elementId(r),
            type: type(r),
            start: elementId(startNode(r)),
            end: elementId(endNode(r)),
            props: properties(r)
          }}] AS edges,
          [p IN paths | [x IN reverse(nodes(p)) | elementId(x)]] AS paths
        """,
        {"tid": tid, "ar_id": ar_id},
    )
    if not recs:
        return {"nodes": [], "edges": [], "paths": []}
    row = recs[0].data()
    paths = [list(p) for p in (row.get("paths") or []) if p]
    if paths:
        return {
            "nodes": list(row.get("nodes") or []),
            "edges": list(row.get("edges") or []),
            "paths": paths,
        }
    return _fetch_paths_to_language_fallback(repo, tid, ar_id)


def _fetch_audit_and_knowledge_extensions(
    repo: Any, spine_eids: List[str], rc_eids: List[str]
) -> Dict[str, List[Any]]:
    """按 elementId 批量拉取主链节点上的 AuditInfo 与 RiskCategory→Knowledge 支路。"""
    out: Dict[str, List[Any]] = {"nodes": [], "edges": []}
    if not spine_eids and not rc_eids:
        return out

    if spine_eids:
        audit_recs = repo.client.execute_read(
            """
            UNWIND $eids AS eid
            MATCH (n) WHERE elementId(n) = eid
            OPTIONAL MATCH (n)-[ai_rel:HAS_AUDIT_INFO]->(ai:AuditInfo)
            RETURN
              [x IN collect(DISTINCT ai) WHERE x IS NOT NULL | {
                elementId: elementId(x),
                labels: labels(x),
                props: properties(x)
              }] AS nodes,
              [x IN collect(DISTINCT ai_rel) WHERE x IS NOT NULL | {
                elementId: elementId(x),
                type: type(x),
                start: elementId(startNode(x)),
                end: elementId(endNode(x)),
                props: properties(x)
              }] AS edges
            """,
            {"eids": spine_eids},
        )
        if audit_recs:
            row = audit_recs[0].data()
            out["nodes"].extend(row.get("nodes") or [])
            out["edges"].extend(row.get("edges") or [])

    if rc_eids:
        know_recs = repo.client.execute_read(
            """
            UNWIND $rc_eids AS eid
            MATCH (rc:RiskCategory) WHERE elementId(rc) = eid
            OPTIONAL MATCH (rc)-[hk:HAS_KNOWLEDGE]->(k:Knowledge)
            OPTIONAL MATCH (k)-[kai_rel:HAS_AUDIT_INFO]->(kai:AuditInfo)
            RETURN
              [x IN collect(DISTINCT k) + collect(DISTINCT kai) WHERE x IS NOT NULL | {
                elementId: elementId(x),
                labels: labels(x),
                props: properties(x)
              }] AS nodes,
              [x IN collect(DISTINCT hk) + collect(DISTINCT kai_rel) WHERE x IS NOT NULL | {
                elementId: elementId(x),
                type: type(x),
                start: elementId(startNode(x)),
                end: elementId(endNode(x)),
                props: properties(x)
              }] AS edges
            """,
            {"rc_eids": rc_eids},
        )
        if know_recs:
            row = know_recs[0].data()
            out["nodes"].extend(row.get("nodes") or [])
            out["edges"].extend(row.get("edges") or [])

    return out


def _ensure_analysis_result_in_graph(
    repo: Any,
    ar_id: str,
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    paths: List[List[str]],
    seen_n: Set[str],
    seen_e: Set[str],
) -> None:
    """保证请求的 AnalysisResult 及其 HAS_RESULT 入边出现在 nodes/edges/paths 中。"""
    if ar_id in seen_n:
        pass
    else:
        ar_recs = repo.client.execute_read(
            """
            MATCH (ar:AnalysisResult)
            WHERE elementId(ar) = $ar_id
            RETURN elementId(ar) AS elementId,
                   labels(ar) AS labels,
                   properties(ar) AS props
            LIMIT 1
            """,
            {"ar_id": ar_id},
        )
        if ar_recs:
            row = ar_recs[0].data()
            eid = str(row.get("elementId") or "").strip()
            if eid and eid not in seen_n:
                seen_n.add(eid)
                nodes.append({
                    "elementId": eid,
                    "labels": list(row.get("labels") or []),
                    "props": dict(row.get("props") or {}),
                })

    rel_recs = repo.client.execute_read(
        """
        MATCH (z)-[r:HAS_RESULT]->(ar:AnalysisResult)
        WHERE elementId(ar) = $ar_id
          AND (z:SinkFlowNode OR z:ChainNode)
        RETURN elementId(r) AS elementId,
               elementId(z) AS src,
               elementId(ar) AS tgt,
               properties(r) AS props
        """,
        {"ar_id": ar_id},
    )
    for rec in rel_recs or []:
        row = rec.data()
        rid = str(row.get("elementId") or "").strip()
        src = str(row.get("src") or "").strip()
        tgt = str(row.get("tgt") or "").strip()
        if rid and rid not in seen_e:
            seen_e.add(rid)
            edges.append({
                "elementId": rid,
                "type": "HAS_RESULT",
                "start": src,
                "end": tgt,
                "props": dict(row.get("props") or {}),
            })

    for i, p in enumerate(paths):
        if not p or p[0] == ar_id:
            continue
        rest = [e for e in p if e != ar_id]
        paths[i] = [ar_id] + rest


def _map_edges(raw: Any, seen: Set[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for e in raw or []:
        if not e or not isinstance(e, dict):
            continue
        eid = e.get("elementId")
        if not eid or eid in seen:
            continue
        seen.add(eid)
        out.append({
            "elementId": eid,
            "type": e.get("type"),
            "start": e.get("start"),
            "end": e.get("end"),
            "props": dict(e.get("props") or {}),
        })
    return out


def fetch_result_to_language_path(task_id: str, result_node_id: str) -> Dict[str, Any]:
    """
    返回 ``AnalysisResult`` 至同 task ``Language`` 的**主链**路径并集（上限见 ``_PATH_LIMIT``）：

    - 主链：``HAS_RESULT`` ← ``FLOW*`` ← ``HAS_SINK`` ← ``HAS_RISK_CATEGORY`` ← ``Language``
    - 支路：主链节点与 Knowledge 上的 ``HAS_AUDIT_INFO``；``RiskCategory`` 的 ``HAS_KNOWLEDGE``

    ``paths`` 为多条链（AR → … → Language），``path`` 取最长一条。
    """
    empty: Dict[str, Any] = {"nodes": [], "edges": [], "paths": [], "path": []}
    repo = db_manager.neo4j_repository
    if repo is None:
        return empty

    tid = str(task_id).strip()
    ar_id = str(result_node_id).strip()
    if not tid or not ar_id:
        return empty

    spine = _fetch_canonical_paths_to_language(repo, tid, ar_id)
    paths: List[List[str]] = spine.get("paths") or []
    if not paths:
        return empty

    spine_eids: List[str] = []
    rc_eids: List[str] = []
    for n in spine.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        eid = str(n.get("elementId") or "").strip()
        if not eid:
            continue
        spine_eids.append(eid)
        if "RiskCategory" in (n.get("labels") or []):
            rc_eids.append(eid)

    ext = _fetch_audit_and_knowledge_extensions(repo, spine_eids, rc_eids)

    seen_n: Set[str] = set()
    nodes = _map_nodes(spine.get("nodes"), seen_n)
    nodes.extend(_map_nodes(ext.get("nodes"), seen_n))

    seen_e: Set[str] = set()
    edges = _map_edges(spine.get("edges"), seen_e)
    edges.extend(_map_edges(ext.get("edges"), seen_e))

    _ensure_analysis_result_in_graph(repo, ar_id, nodes, edges, paths, seen_n, seen_e)

    # 兼容旧前端：path = 最长一条主链
    path = max(paths, key=len)

    return {"nodes": nodes, "edges": edges, "paths": paths, "path": path}


def delete_task_neo4j_data(task_id: str) -> int:
    """
    删除 Neo4j 中与 ``task_id`` 相关的全部节点（含关系）。

    - 先删 ``RiskCategory`` 下 ``HAS_KNOWLEDGE`` 的 ``Knowledge`` 及其 ``AuditInfo``（无 task_id）
    - 再删所有 ``n.task_id = task_id`` 的节点（Task、AuditStage、Language、RiskCategory 等）
    """
    repo = db_manager.neo4j_repository
    tid = str(task_id).strip()
    if repo is None or not tid:
        return 0

    repo.client.execute_write(
        """
        MATCH (rc:RiskCategory {task_id: $task_id})-[:HAS_KNOWLEDGE]->(k:Knowledge)
        OPTIONAL MATCH (k)-[:HAS_AUDIT_INFO]->(ai:AuditInfo)
        DETACH DELETE k, ai
        """,
        {"task_id": tid},
    )
    records = repo.client.execute_write(
        """
        MATCH (n)
        WHERE coalesce(n.task_id, '') = $task_id
        DETACH DELETE n
        RETURN count(*) AS cnt
        """,
        {"task_id": tid},
    )
    deleted = 0
    if records:
        deleted = int(records[0].data().get("cnt") or 0)
    logger.info("[neo4j] 已删除 task_id=%s 相关节点 %d 个", tid, deleted)
    return deleted
