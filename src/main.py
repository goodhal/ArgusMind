"""CLI 入口：启动 API 服务或运行一次任务审计"""
from __future__ import annotations

import sys
from pathlib import Path

# 支持 `python src/main.py`、`cd src && python main.py`、`python -m src.main`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import uvicorn
from src.tmp_dir import init_tmp_dir

if __name__ == "__main__":
    init_tmp_dir()

    uvicorn.run(
        "src.api.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=6066,
        reload=False,
    )
