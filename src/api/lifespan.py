"""FastAPI 启停钩子"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

import src.globals as g
from src.tmp_dir import init_tmp_dir
from src.config import load_config
from src.core.event_handlers import register_default_handlers
from src.core.task_control import reload_paused_from_db
from src.infrastructure.db import dispose_engine, init_engine
from src.infrastructure.db.init_db import init_db
from src.services.config_service import ensure_jwt_secret
from src.storage import close_clients, init_clients
from src.tools.bootstrap.startup import ensure_tool_dependencies_at_startup

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动时同时初始化 PostgreSQL 与 Neo4j（幂等），关停时释放连接。"""
    config = load_config()
    app.state.config = config

    # 任务临时目录：与 src/main.py 一致；未设置时由 init_tmp_dir 统一 resolve。
    if not str(getattr(g, "TMP_DIR", "") or "").strip():
        init_tmp_dir()

    # 1) PostgreSQL：engine + 建表 + 种子
    init_engine(config.postgres)
    try:
        init_db(config)
    except Exception as ex:  # pragma: no cover - 启动失败直接抛出
        logger.exception("[lifespan] init_db 失败: %s", ex)
        raise

    # 2) Neo4j：全局客户端 + repository
    try:
        init_clients(config)
    except Exception as ex:  # pragma: no cover - Neo4j 不可达不阻断 API 启动
        logger.warning("[lifespan] Neo4j 初始化失败（将在运行期按需重试）: %s", ex)

    ensure_jwt_secret()

    register_default_handlers()
    try:
        reload_paused_from_db()
    except Exception as ex:  # pragma: no cover
        logger.warning("[lifespan] 恢复暂停任务状态失败: %s", ex)
    try:
        ensure_tool_dependencies_at_startup()
    except Exception as ex:  # pragma: no cover - 工具依赖检查失败不阻断 API 启动
        logger.warning("[lifespan] 工具依赖检查失败: %s", ex)

    try:
        yield
    finally:
        try:
            close_clients()
        except Exception as ex:  # pragma: no cover
            logger.warning("[lifespan] Neo4j 关闭异常: %s", ex)
        dispose_engine()
