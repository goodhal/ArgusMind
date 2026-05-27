"""健康检查路由：同时探活 PostgreSQL 与 Neo4j"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from src.infrastructure.db import get_engine

router = APIRouter()


@router.get("/health", tags=["health"])
def health() -> Dict[str, Any]:
    return {"success": True, "data": {"status": "ok"}}


@router.get("/ready", tags=["health"])
def ready() -> Dict[str, Any]:
    checks: Dict[str, Dict[str, Any]] = {
        "postgres": {"ok": False, "error": None},
        "neo4j": {"ok": False, "error": None},
    }

    # PostgreSQL
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        checks["postgres"]["ok"] = True
    except Exception as ex:
        checks["postgres"]["error"] = str(ex)

    # Neo4j
    try:
        from src.storage.manager import get_neo4j_client

        client = get_neo4j_client()
        client.execute_read("RETURN 1 AS ok")
        checks["neo4j"]["ok"] = True
    except Exception as ex:
        checks["neo4j"]["error"] = str(ex)

    all_ok = all(v["ok"] for v in checks.values())
    return {
        "success": all_ok,
        "data": {"status": "ready" if all_ok else "degraded", "checks": checks},
    }
