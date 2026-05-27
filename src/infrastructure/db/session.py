"""SQLAlchemy 会话管理"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.config import PostgresConfig

_engine: Optional[Engine] = None
SessionLocal: Optional[sessionmaker] = None


def init_engine(pg: PostgresConfig, *, echo: bool = False) -> Engine:
    """初始化全局 engine / SessionLocal，重复调用安全。"""
    global _engine, SessionLocal
    if _engine is None:
        _engine = create_engine(
            pg.sqlalchemy_url,
            echo=echo,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            future=True,
        )
        SessionLocal = sessionmaker(
            bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Engine 未初始化，请先调用 init_engine(config.postgres)")
    return _engine


def dispose_engine() -> None:
    global _engine, SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
        SessionLocal = None


def get_session() -> Session:
    if SessionLocal is None:
        raise RuntimeError("SessionLocal 未初始化")
    return SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    """事务上下文：抛异常则回滚，正常退出则提交。"""
    if SessionLocal is None:
        raise RuntimeError("SessionLocal 未初始化")
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
