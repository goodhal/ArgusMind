# -*- coding: utf-8 -*-
"""
将 SinkFinder 产出的 nodes + flow（trees）写入 Neo4j。
- SinkFlowNode：按 (sink_node_id, task_id) MERGE，避免跨任务复用同一 sink 业务 id
- 树边：父 -> [:FLOW] -> 子（与 _build_flow_trees_from_sink_nodes 语义一致）；MATCH 端点均带 task_id，防止跨任务连边
- 漏洞节点：任意带 node_id 的标签，MATCH (v {node_id}) -[:HAS_SINK]-> 每棵树的根节点

链路追溯（编排器按条消费）：
- 叶节点：无指向其他 SinkFlowNode 的 :FLOW 出边
- 每次取一条：叶非 :Result、status 不为 running；且从叶沿 :FLOW 到当前末端（叶或最后一个 ChainNode）
  尚无 :HAS_RESULT→AnalysisResult
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import src.storage.manager as db_manager


def _collect_flow_edges(trees: List[dict]) -> List[Dict[str, str]]:
    edges: List[Dict[str, str]] = []

    def walk(node: dict) -> None:
        parent_id = node.get("id")
        for ch in node.get("children") or []:
            if ch.get("cycle"):
                continue
            child_id = ch.get("id")
            if parent_id and child_id:
                edges.append({"parent": str(parent_id), "child": str(child_id)})
            walk(ch)

    for t in trees or []:
        walk(t)
    return edges


def _node_rows_from_sink_nodes(nodes: List[dict], task_id: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for n in nodes or []:
        sid = n.get("sink_node_id") or n.get("sink_id")
        if not sid:
            continue
        rows.append({
            "sink_node_id": str(sid),
            "task_id": task_id,
            "file": n.get("file") or "",
            "line": int(n.get("line") or 0),
            "end_line": int(n.get("end_line") or 0),
            "function": n.get("function") or "",
            "reason": n.get("reason") or "",
            "related_exec": n.get("related_exec") or "",
            "related_exec_node": n.get("related_exec_node") or "",
        })
    return rows


def persist_sink_flow_to_neo4j(
        vul_node_id: str,
        sink_nodes: List[dict],
        flow: Dict[str, Any],
        task_id: str,
) -> None:
    """
    将 sink 节点与 FLOW 森林写入 Neo4j，并从漏洞节点连 HAS_SINK 到每棵树的根（flow['roots']）。
    使用 db_manager.neo4j_repository（未 init 则直接返回）。

    Args:
        vul_node_id: 漏洞侧节点属性 node_id（如 RiskCategory.node_id）
        sink_nodes: _postprocess_sink_res_expand_related_nodes 的输出
        flow: _build_flow_trees_from_sink_nodes 的输出（含 trees, roots）
        task_id: 当前审计任务 id；SinkFlowNode 与 FLOW 边均按任务隔离
    """
    repo = db_manager.neo4j_repository
    if not vul_node_id or not task_id or repo is None:
        return

    client = repo.client
    rows = _node_rows_from_sink_nodes(sink_nodes, task_id)
    if not rows:
        return

    client.execute_write(
        """
        UNWIND $rows AS row
        MERGE (s:SinkFlowNode {sink_node_id: row.sink_node_id, task_id: row.task_id})
        SET s.file = row.file,
            s.line = row.line,
            s.end_line = row.end_line,
            s.function = row.function,
            s.reason = row.reason,
            s.related_exec = row.related_exec,
            s.related_exec_node = row.related_exec_node,
            s.status = 'pending'
        """,
        {"rows": rows},
    )

    trees = flow.get("trees") or []
    edges = _collect_flow_edges(trees)
    if edges:
        client.execute_write(
            """
            UNWIND $edges AS e
            MATCH (a:SinkFlowNode {sink_node_id: e.parent, task_id: $task_id})
            MATCH (b:SinkFlowNode {sink_node_id: e.child, task_id: $task_id})
            MERGE (a)-[:FLOW]->(b)
            """,
            {"edges": edges, "task_id": task_id},
        )

    roots = flow.get("roots") or []
    root_ids = [str(r) for r in roots if r]
    if not root_ids:
        return

    client.execute_write(
        """
        MATCH (vuln {node_id: $vul_node_id})
        UNWIND $root_ids AS sid
        MATCH (s:SinkFlowNode {sink_node_id: sid, task_id: $task_id})
        MERGE (vuln)-[:HAS_SINK]->(s)
        """,
        {"vul_node_id": vul_node_id, "root_ids": root_ids, "task_id": task_id},
    )


SINK_FLOW_LEAF_STATUS_RUNNING = "running"
SINK_FLOW_LEAF_STATUS_PENDING = "pending"


def reset_running_sink_and_chain_nodes_to_pending_for_task(task_id: str) -> int:
    """
    将指定 task 下 SinkFlowNode、ChainNode 中 status=running 的节点改回 pending（未处理）。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not task_id:
        return 0
    records = repo.client.execute_write(
        """
        MATCH (n)
        WHERE coalesce(n.task_id, '') = $task_id
          AND coalesce(n.status, '') = $running
          AND (n:SinkFlowNode OR n:ChainNode)
        SET n.status = $pending
        RETURN count(n) AS n
        """,
        {
            "task_id": task_id,
            "running": SINK_FLOW_LEAF_STATUS_RUNNING,
            "pending": SINK_FLOW_LEAF_STATUS_PENDING,
        },
    )
    if not records:
        return 0
    return int(records[0].data().get("n") or 0)


def _assemble_sink_chain_path_dict(
    vul_node_id: str,
    raw_nodes: Any,
    leaf_sink_node_id: Any,
    tail_meta: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """将 Cypher 返回的 sink_nodes 列表与叶 id 组装为 fetch_* 系列统一结构。"""
    if not raw_nodes or not leaf_sink_node_id:
        return None

    sink_nodes: List[Dict[str, Any]] = []
    path_str: List[str] = []
    for item in raw_nodes:
        props = dict((item or {}).get("node_properties") or {})
        props["elementId"] = (item or {}).get("elementId")
        props["labels"] = list((item or {}).get("labels") or [])
        sid = props.get("sink_node_id")
        if sid is None:
            sid = props.get("node_id", "")
        sid_str = str(sid)
        path_str.append(sid_str)
        sink_nodes.append(props)

    if not sink_nodes:
        return None

    out: Dict[str, Any] = {
        "vul_node_id": vul_node_id,
        "path_sink_node_ids": path_str,
        "leaf_sink_node_id": str(leaf_sink_node_id),
        "sink_nodes": sink_nodes,
    }
    if tail_meta:
        out.update(tail_meta)
    return out


def reset_running_sink_leaves_to_pending_for_task(task_id: str) -> None:
    """
    将指定 task 下所有 RiskCategory 的 FLOW 森林中、叶 SinkFlowNode 且 status=running 的节点改回 pending。
    供编排器在本次 run 首次进入链路消费前调用，清理上次异常退出遗留的 running。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not task_id:
        return
    repo.client.execute_write(
        """
        MATCH (cat:RiskCategory {task_id: $task_id})-[:HAS_SINK]->(root:SinkFlowNode)
        MATCH (root)-[:FLOW*0..]->(leaf:SinkFlowNode)
        WHERE NOT (leaf)-[:FLOW]->(:SinkFlowNode)
          AND coalesce(leaf.status, '') = $running
        SET leaf.status = $pending
        """,
        {
            "task_id": task_id,
            "running": SINK_FLOW_LEAF_STATUS_RUNNING,
            "pending": SINK_FLOW_LEAF_STATUS_PENDING,
        },
    )


def fetch_next_pending_sink_chain_path(vul_node_id: str) -> Optional[Dict[str, Any]]:
    """
    从漏洞节点（如 RiskCategory，属性 node_id）经 HAS_SINK→FLOW 树，每次调用只返回一条
    待消费链路（查询里有 LIMIT 1）。编排器通过反复调用本函数依次处理多条候选。

    注意：下面列的是「什么样的一条 (叶, 末端) 算可消费的 pending」的过滤条件（WHERE），
    不是「一次查询返回图里全部 pending」。若要枚举某 vul 下全部候选，需去掉 LIMIT 1
    或单独写查询（如 scripts/inspect_vul_sink_subgraph.py 中的等价无 LIMIT 查询）。

    单条返回内容：根→FLOW 叶的 ``sink_node_id`` 序列及路径上各 SinkFlowNode 的
    properties + elementId + labels；另可含 analysis_tail_*（当前分析末端）。

    过滤条件（与编排器一致，且末端尚未结案）：
    - FLOW 叶：无指向其他 SinkFlowNode 的 :FLOW 出边；
    - 叶非 :Result，且 coalesce(status,'') 不为 running；
    - 从叶沿 :FLOW 到当前末端（该叶自身，或延伸后的最后一个 ChainNode），该末端尚无
      :HAS_RESULT→AnalysisResult。

    在满足条件的 (叶, 末端) 中按 leaf 的业务 id（sink_node_id、node_id）与 elementId 升序取第一条。

    调用方取到后应将叶的 status 设为 running；结束后给叶加 :Result 并视需要清空 status。
    """
    repo = db_manager.neo4j_repository
    if not vul_node_id or repo is None:
        return None

    cypher = """
    MATCH (v {node_id: $vul_node_id})-[:HAS_SINK]->(root:SinkFlowNode)
MATCH p = (root)-[:FLOW*0..]->(leaf)
WHERE (leaf:SinkFlowNode OR leaf:ChainNode)
  AND NOT (leaf)-[:FLOW]->()
  AND NOT (leaf)-[:HAS_RESULT]->(:AnalysisResult)
  AND coalesce(leaf.status, '') <> $running
  AND NOT (leaf:Result)
WITH p, leaf
ORDER BY coalesce(
  leaf.sink_node_id,
  leaf.node_id,
  elementId(leaf)
) ASC
LIMIT 1
RETURN [n IN nodes(p) | {
  node_properties: properties(n),
  elementId: elementId(n),
  labels: labels(n)
}] AS sink_nodes,
coalesce(
  leaf.sink_node_id,
  leaf.node_id,
  elementId(leaf)
) AS leaf_sink_node_id
    """
    records = repo.client.execute_write(
        cypher,
        {"vul_node_id": vul_node_id, "running": SINK_FLOW_LEAF_STATUS_RUNNING},
    )
    if not records:
        return None
    row = records[0].data()
    return _assemble_sink_chain_path_dict(
        vul_node_id,
        row.get("sink_nodes"),
        row.get("leaf_sink_node_id"),
        tail_meta={
            "analysis_tail_element_id": row.get("analysis_tail_element_id"),
            "analysis_tail_id": row.get("analysis_tail_id"),
            "analysis_tail_is_chain": row.get("analysis_tail_is_chain"),
        },
    )


def mark_sink_flow_leaf_status(sink_node_id: str, status: str) -> None:
    """更新叶 SinkFlowNode 的 status（如标 running 或完成后清空）。"""
    repo = db_manager.neo4j_repository
    if repo is None or not sink_node_id:
        return
    repo.update_node(
        {"label": "SinkFlowNode", "sink_node_id": sink_node_id},
        {"status": status},
    )
