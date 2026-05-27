"""PostgreSQL 客户端"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.config import PostgresConfig


class PostgresClient:
    """PostgreSQL 客户端封装"""
    
    def __init__(self, config: PostgresConfig):
        connection_string = (
            f"postgresql://{config.user}:{config.password}@"
            f"{config.host}:{config.port}/{config.db}"
        )
        self.engine = create_engine(connection_string)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def get_session(self):
        """获取数据库会话"""
        return self.SessionLocal()

