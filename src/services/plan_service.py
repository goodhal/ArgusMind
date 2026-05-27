# -*- coding: utf-8 -*-
"""
计划持久化服务：将审计计划（final_output）写入 Neo4j。
图结构：计划制定 -[HAS_LANGUAGE]-> 语言 -[HAS_RISK_CATEGORY]-> 漏洞类型(category_name)。
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

import src.storage.manager as db_manager
from src.utils.ids import generate_id


def persist_plan(plan_stage_node_id: str, plan_data: Dict, task_id: str) -> None:
    """
    将审计计划写入 Neo4j。

    Args:
        plan_stage_node_id: 计划阶段节点的 node_id（与 create_relationship 时 to_node 的 node_id 一致）
        plan_data: final_output 字典，需包含 "project_summary" 和 "languages"。
                   languages 为列表，每项含 "language" 和 "risk_categories"；
                   risk_categories 每项含 "category_name", "risk_description", "reasoning_basis"。
    """
    if not plan_data or "languages" not in plan_data:
        return
    repo = db_manager.neo4j_repository
    plan_spec = {"label": "AuditStage", "node_id": plan_stage_node_id}
    project_summary = plan_data.get("project_summary") or {}

    for lang_item in plan_data["languages"]:
        lang_name = lang_item.get("language") or ""
        lang_id = generate_id("cn")
        repo.create_relationship(
            from_node=plan_spec,
            to_node={
                "label": "Language",
                "name": lang_name,
                "node_id": lang_id,
                "level": lang_item.get("level", 100),
                "status": "pending",
                "task_id": task_id,
                "created_at": datetime.now().isoformat(),
            },
            relationship_type="HAS_LANGUAGE",
        )
        lang_spec = {"label": "Language", "node_id": lang_id}
        for cat in lang_item.get("risk_categories") or []:
            category_name = (cat.get("category_name") or "").strip()
            if not category_name:
                continue
            cat_id = generate_id()
            repo.create_relationship(
                from_node=lang_spec,
                to_node={
                    "label": "RiskCategory",
                    "category_name": category_name,
                    "risk_description": cat.get("risk_description") or "",
                    "reasoning_basis": cat.get("reasoning_basis") or "",
                    "level": cat.get("level", 100),
                    "node_id": cat_id,
                    "status": "pending",
                    "task_id": task_id,
                    "created_at": datetime.now().isoformat(),
                },
                relationship_type="HAS_RISK_CATEGORY",
            )

    if project_summary:
        repo.update_node(plan_spec, {
            "project_type": project_summary.get("project_type") or "",
            "risk_overview": project_summary.get("risk_overview") or "",
            "audit_priority": project_summary.get("audit_priority") or [],
        })


def find_completed_plan_stage_node_id_for_task(task_id: str) -> Optional[str]:
    """
    若该 task 下已有「制定计划」阶段且 status=completed，且已通过 persist_plan 挂上至少一条 HAS_LANGUAGE，
    则返回该计划阶段节点的 node_id（取最近 end_time 的一条）；否则返回 None。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not task_id:
        return None
    cypher = """
    MATCH (s:AuditStage {task_id: $task_id, name: 'make a plan', status: 'completed'})
    WHERE EXISTS { (s)-[:HAS_LANGUAGE]->(:Language) }
    RETURN s.node_id AS plan_id
    ORDER BY coalesce(s.end_time, '') DESC, coalesce(s.created_at, '') DESC
    LIMIT 1
    """
    records = repo.client.execute_write(cypher, {"task_id": task_id})
    if not records:
        return None
    row = records[0].data()
    pid = row.get("plan_id")
    return str(pid) if pid else None


def fetch_next_pending_language_for_plan(plan_stage_node_id: str) -> Optional[Dict[str, Any]]:
    """
    在指定计划阶段下，取一个 status=pending 的 Language，按 level 升序（数值越小越优先），同级按 node_id 稳定排序。
    每次调用至多返回一行；不在此函数内改 status。
    """
    repo = db_manager.neo4j_repository
    if repo is None:
        return None
    cypher = """
    MATCH (plan:AuditStage {node_id: $plan_id})-[:HAS_LANGUAGE]->(lang:Language)
    WHERE lang.status = 'pending'
    RETURN lang.node_id AS node_id,
           lang.name AS language,
           lang.level AS level,
           lang.status AS status,
           lang.task_id AS task_id
    ORDER BY coalesce(toInteger(lang.level), 999999) ASC, lang.node_id ASC
    LIMIT 1
    """
    records = repo.client.execute_write(cypher, {"plan_id": plan_stage_node_id})
    if not records:
        return None
    return records[0].data()


def fetch_next_pending_risk_category_for_language(lang_node_id: str) -> Optional[Dict[str, Any]]:
    """
    在指定 Language 下，取一个 status=pending 的 RiskCategory，按 level 升序，同级按 node_id 排序。
    """
    repo = db_manager.neo4j_repository
    if repo is None:
        return None
    cypher = """
    MATCH (lang:Language {node_id: $lang_node_id})-[:HAS_RISK_CATEGORY]->(cat:RiskCategory)
    WHERE cat.status = 'pending'
    RETURN cat.node_id AS node_id,
           cat.category_name AS category_name,
           cat.risk_description AS risk_description,
           cat.reasoning_basis AS reasoning_basis,
           cat.level AS level,
           cat.status AS status,
           cat.task_id AS task_id,
           coalesce(cat.sink_finder_completed, false) AS sink_finder_completed
    ORDER BY coalesce(toInteger(cat.level), 999999) ASC, cat.node_id ASC
    LIMIT 1
    """
    records = repo.client.execute_write(cypher, {"lang_node_id": lang_node_id})
    if not records:
        return None
    return records[0].data()


def reset_running_audit_nodes_to_pending_for_task(task_id: str) -> int:
    """
    将指定 task 下审计编排节点（Language、RiskCategory、SinkFlowNode、
    ChainNode、AnalysisResult）里 status=running 的一律改回 pending，供任务恢复后继续消费。
    """
    repo = db_manager.neo4j_repository
    if repo is None or not task_id:
        return 0
    records = repo.client.execute_write(
        """
        MATCH (n)
        WHERE coalesce(n.task_id, '') = $task_id
          AND coalesce(n.status, '') = 'running'
          AND (
            n:Language OR n:RiskCategory OR n:SinkFlowNode
            OR n:ChainNode OR n:AnalysisResult
          )
        SET n.status = 'pending'
        RETURN count(n) AS n
        """,
        {"task_id": task_id},
    )
    if not records:
        return 0
    return int(records[0].data().get("n") or 0)


def mark_language_status(lang_node_id: str, status: str) -> None:
    repo = db_manager.neo4j_repository
    if repo is None:
        return
    repo.update_node(
        {"label": "Language", "node_id": lang_node_id},
        {"status": status},
    )


def mark_risk_category_status(cat_node_id: str, status: str) -> None:
    repo = db_manager.neo4j_repository
    if repo is None:
        return
    repo.update_node(
        {"label": "RiskCategory", "node_id": cat_node_id},
        {"status": status},
    )


def fetch_task_language_risk_status(task_id: str) -> Dict[str, Any]:
    """
    按 task_id 从 Neo4j 拉取该任务下全部 Language 及其 RiskCategory 的 status，
    用于统计审计计划执行进度。
    """
    repo = db_manager.neo4j_repository
    tid = str(task_id).strip()
    empty: Dict[str, Any] = {"task_id": tid, "languages": []}
    if repo is None or not tid:
        return empty
    cypher = """
    MATCH (lang:Language {task_id: $task_id})
    OPTIONAL MATCH (lang)-[:HAS_RISK_CATEGORY]->(cat:RiskCategory)
    RETURN lang.node_id AS lang_node_id,
           lang.name AS language,
           lang.status AS lang_status,
           lang.level AS lang_level,
           cat.node_id AS cat_node_id,
           cat.category_name AS category_name,
           cat.status AS cat_status,
           cat.level AS cat_level,
           coalesce(cat.sink_finder_completed, false) AS sink_finder_completed
    ORDER BY coalesce(toInteger(lang.level), 999999) ASC, lang.node_id ASC,
             coalesce(toInteger(cat.level), 999999) ASC, cat.node_id ASC
    """
    records = repo.client.execute_write(cypher, {"task_id": tid})
    if not records:
        return empty

    lang_map: Dict[str, Dict[str, Any]] = {}
    lang_order: List[str] = []

    for rec in records:
        row = rec.data()
        lid = row.get("lang_node_id")
        if not lid:
            continue
        lid = str(lid)
        if lid not in lang_map:
            lang_map[lid] = {
                "node_id": lid,
                "language": str(row.get("language") or ""),
                "status": str(row.get("lang_status") or "pending"),
                "level": int(row.get("lang_level") or 100),
                "risk_categories": [],
            }
            lang_order.append(lid)

        cid = row.get("cat_node_id")
        if not cid:
            continue
        lang_map[lid]["risk_categories"].append(
            {
                "node_id": str(cid),
                "category_name": str(row.get("category_name") or ""),
                "status": str(row.get("cat_status") or "pending"),
                "level": int(row.get("cat_level") or 100),
                "sink_finder_completed": bool(row.get("sink_finder_completed")),
            }
        )

    return {"task_id": tid, "languages": [lang_map[k] for k in lang_order]}


def mark_risk_category_sink_finder_completed(cat_node_id: str) -> None:
    """将 RiskCategory 标记为 SinkFinder 已成功落库，供编排器幂等跳过重复执行。"""
    repo = db_manager.neo4j_repository
    if repo is None:
        return
    repo.update_node(
        {"label": "RiskCategory", "node_id": cat_node_id},
        {"sink_finder_completed": True},
    )
