"""PostgreSQL ORM 模型 —— 统一由 src.infrastructure.db.models 导出。

本文件不再独立定义模型，避免与 infrastructure/db/models/ 下的正式定义冲突。
"""
# 所有模型请从 src.infrastructure.db.models 导入
from src.infrastructure.db.models import *  # noqa: F401,F403
