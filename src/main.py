"""CLI 入口：启动 API 服务或运行一次任务审计"""
from __future__ import annotations

import sys
from pathlib import Path

# 支持 `python src/main.py`、`cd src && python main.py`、`python -m src.main`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import logging

import uvicorn
from src.config import load_config
from src.logg import setup_logging
from src.tmp_dir import init_tmp_dir

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    init_tmp_dir()
    _cfg = load_config()
    setup_logging(level=_cfg.log_level, log_file=_cfg.log_file)

    logger.info(
        "[main] 配置已加载: postgres=%s:%s/%s neo4j=%s log_level=%s",
        _cfg.postgres.host,
        _cfg.postgres.port,
        _cfg.postgres.db,
        _cfg.neo4j.uri,
        _cfg.log_level,
    )
    logger.info("[main] 即将启动 Uvicorn (factory=src.api.app:create_app, host=0.0.0.0, port=6066)")

    uvicorn.run(
        "src.api.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=6066,
        reload=False,
    )
