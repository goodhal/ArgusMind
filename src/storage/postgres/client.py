"""PostgreSQL 客户端（委托给 infrastructure.db.session 统一管理 engine）"""
from src.config import PostgresConfig


class PostgresClient:
    """PostgreSQL 客户端封装

    实际 engine / SessionLocal 由 ``src.infrastructure.db.session.init_engine`` 统一管理，
    此处仅保留兼容接口。
    """

    def __init__(self, config: PostgresConfig):
        # 委托给统一会话管理器，避免创建冗余 engine
        from src.infrastructure.db.session import init_engine as _init
        _init(config)

    @property
    def engine(self):
        from src.infrastructure.db.session import get_engine
        return get_engine()

    @property
    def SessionLocal(self):
        from src.infrastructure.db.session import SessionLocal
        return SessionLocal

    def get_session(self):
        """获取数据库会话"""
        from src.infrastructure.db.session import get_session
        return get_session()
