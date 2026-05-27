"""数据库客户端和Repository管理器"""
from typing import Optional

from src.config import Config, load_config
from src.storage.neo4j.client import Neo4jClient
from src.storage.neo4j.repository import Neo4jRepository
from src.storage.postgres.client import PostgresClient
from src.storage.postgres.repository import TaskRepository

# 全局数据库客户端实例
neo4j_client: Optional[Neo4jClient] = None
postgres_client: Optional[PostgresClient] = None

# 全局Repository实例（单例）
neo4j_repository: Optional[Neo4jRepository] = None
postgres_repository: Optional[TaskRepository] = None

# 配置实例（用于自动初始化）
_config: Optional[Config] = None


def init_clients(config: Optional[Config] = None) -> None:
    """
    初始化全局数据库客户端和Repository

    PostgreSQL 若驱动不可用或连接失败会静默跳过，仅使用 Neo4j 时仍可正常 init。

    Args:
        config: 配置对象，如果为None则自动加载配置
    """
    global neo4j_client, postgres_client, neo4j_repository, postgres_repository, _config

    # 如果没有提供config，自动加载
    if config is None:
        config = load_config()
    
    _config = config

    # 初始化Neo4j客户端和Repository
    if neo4j_client is None:
        neo4j_client = Neo4jClient(config.neo4j)
        neo4j_repository = Neo4jRepository(neo4j_client)
    elif neo4j_repository is None:
        # 如果客户端已存在但Repository为None，重新创建Repository
        neo4j_repository = Neo4jRepository(neo4j_client)

    # 初始化 PostgreSQL（可选：未装驱动或仅使用 Neo4j 时跳过，不影响 Neo4j）
    if postgres_client is None:
        try:
            postgres_client = PostgresClient(config.postgres)
            postgres_repository = TaskRepository(postgres_client)
        except Exception:
            postgres_client = None
            postgres_repository = None


def _ensure_initialized() -> None:
    """确保数据库已初始化（延迟初始化）"""
    if neo4j_client is None and postgres_client is None:
        init_clients()


def get_neo4j_client() -> Neo4jClient:
    """
    获取 Neo4j 客户端实例

    Returns:
        Neo4jClient 实例

    Raises:
        RuntimeError: 如果客户端未初始化
    """
    _ensure_initialized()
    if neo4j_client is None:
        raise RuntimeError("Neo4j 客户端未初始化，请先调用 init_clients()")
    return neo4j_client


def get_postgres_client() -> PostgresClient:
    """
    获取 PostgreSQL 客户端实例

    Returns:
        PostgresClient 实例

    Raises:
        RuntimeError: 如果客户端未初始化
    """
    _ensure_initialized()
    if postgres_client is None:
        raise RuntimeError("PostgreSQL 客户端未初始化，请先调用 init_clients()")
    return postgres_client


def get_neo4j_repository() -> Neo4jRepository:
    """
    获取 Neo4j Repository 实例（单例）

    Returns:
        Neo4jRepository 实例
    """
    _ensure_initialized()
    if neo4j_repository is None:
        raise RuntimeError("Neo4j Repository 未初始化，请先调用 init_clients()")
    return neo4j_repository


def get_postgres_repository() -> TaskRepository:
    """
    获取 PostgreSQL Repository 实例（单例）

    Returns:
        TaskRepository 实例
    """
    _ensure_initialized()
    if postgres_repository is None:
        raise RuntimeError("PostgreSQL Repository 未初始化，请先调用 init_clients()")
    return postgres_repository


def close_clients() -> None:
    """关闭所有数据库连接"""
    global neo4j_client, postgres_client, neo4j_repository, postgres_repository

    if neo4j_client is not None:
        neo4j_client.close()
        neo4j_client = None
        neo4j_repository = None

    if postgres_client is not None:
        # PostgresClient 使用 SQLAlchemy，engine 会自动管理连接池
        # 如果需要显式关闭，可以在这里添加
        postgres_client = None
        postgres_repository = None

