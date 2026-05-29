"""FastAPI 应用工厂"""
from __future__ import annotations

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)

from src.api.exceptions import register_exception_handlers
from src.api.lifespan import lifespan
from src.api.middleware import register_middleware
from src.api.routers import (
    auth,
    chain_graph,
    chains,
    configs,
    events,
    vulnerabilities,
    graph,
    health,
    logs,
    projects,
    reports,
    tasks,
    tokens,
)

API_PREFIX = "/api"


def create_app() -> FastAPI:
    logger.info("[app] 创建 FastAPI 应用并注册路由")
    app = FastAPI(
        title="ArgusMind",
        description="AI 自主代码审计系统",
        version="0.1.0",
        lifespan=lifespan,
    )

    register_middleware(app)
    register_exception_handlers(app)

    app.include_router(health.router, prefix=API_PREFIX)
    app.include_router(auth.router, prefix=f"{API_PREFIX}/auth", tags=["auth"])
    app.include_router(projects.router, prefix=f"{API_PREFIX}/projects", tags=["projects"])
    app.include_router(tasks.router, prefix=f"{API_PREFIX}/tasks", tags=["tasks"])
    app.include_router(vulnerabilities.router, prefix=f"{API_PREFIX}/findings", tags=["findings"])
    app.include_router(events.router, prefix=f"{API_PREFIX}/events", tags=["events"])
    app.include_router(logs.router, prefix=f"{API_PREFIX}/logs", tags=["logs"])
    app.include_router(configs.router, prefix=f"{API_PREFIX}/configs", tags=["configs"])
    app.include_router(chains.router, prefix=f"{API_PREFIX}/chains", tags=["chains"])
    app.include_router(chain_graph.router, prefix=f"{API_PREFIX}/chain-graph", tags=["chain-graph"])
    app.include_router(graph.router, prefix=f"{API_PREFIX}/graph", tags=["graph"])
    app.include_router(reports.router, prefix=f"{API_PREFIX}/reports", tags=["reports"])
    app.include_router(tokens.router, prefix=f"{API_PREFIX}/tokens", tags=["tokens"])

    return app
