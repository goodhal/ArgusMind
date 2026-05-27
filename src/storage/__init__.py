"""存储平面"""
# 初始化相关

__all__ = [
    # 初始化
    "init_clients",
    "close_clients",
    # 全局实例
    "neo4j_repository",
    "neo4j_client",
    "postgres_client",
    "postgres_repository",
]

from src.storage.manager import init_clients, close_clients, neo4j_repository, neo4j_client, postgres_client, \
    postgres_repository
