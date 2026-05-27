"""Neo4j 客户端"""
import time
from typing import Any, Dict, List, Optional

import neo4j
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

from src.config import Neo4jConfig

# 连接抖动、defunct connection、瞬时服务端错误等可重试
_RETRIABLE = (ServiceUnavailable, SessionExpired, TransientError)


class Neo4jClient:
    """Neo4j 客户端封装"""

    def __init__(
        self,
        config: Neo4jConfig,
        *,
        max_retries: int = 5,
        retry_base_delay_sec: float = 0.5,
    ):
        self.driver = GraphDatabase.driver(
            config.uri,
            auth=(config.user, config.password),
        )
        self._max_retries = max(1, max_retries)
        self._retry_base_delay_sec = max(0.05, retry_base_delay_sec)

    def close(self):
        """关闭连接"""
        self.driver.close()

    def _sleep_before_retry(self, attempt_index: int) -> None:
        delay = self._retry_base_delay_sec * (2**attempt_index)
        delay = min(delay, 16.0)
        time.sleep(delay)

    def execute_query(self, query: str, parameters: dict = None) -> List[Any]:
        """
        执行查询；在 session 关闭前将结果完整拉取为 list[Record]。
        """
        params = parameters or {}
        last_error: Optional[BaseException] = None
        for attempt in range(self._max_retries):
            try:
                with self.driver.session() as session:
                    result = session.run(query, params)
                    return list(result)
            except _RETRIABLE as e:
                last_error = e
                if attempt + 1 >= self._max_retries:
                    raise
                self._sleep_before_retry(attempt)
        raise last_error  # pragma: no cover

    def execute_write(self, query: str, parameters: dict = None):
        """
        执行写入查询（自动提交事务）

        返回：记录列表（list of Record）
        """
        params = parameters or {}
        last_error: Optional[BaseException] = None
        for attempt in range(self._max_retries):
            session = self.driver.session()
            try:
                result = session.run(query, params)
                # 在 session 关闭前消费结果，避免 ResultConsumedError
                records = list(result)
                return records
            except _RETRIABLE as e:
                last_error = e
                if attempt + 1 >= self._max_retries:
                    raise
                self._sleep_before_retry(attempt)
            finally:
                session.close()
        raise last_error  # pragma: no cover

    def execute_read(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Any]:
        """
        在只读路由上执行 Cypher，结果在关闭 session 前完整拉取为 list[Record]。
        """
        params = parameters or {}
        last_error: Optional[BaseException] = None
        for attempt in range(self._max_retries):
            session = self.driver.session(default_access_mode=neo4j.READ_ACCESS)
            try:
                result = session.run(query, params)
                return list(result)
            except _RETRIABLE as e:
                last_error = e
                if attempt + 1 >= self._max_retries:
                    raise
                self._sleep_before_retry(attempt)
            finally:
                session.close()
        raise last_error  # pragma: no cover

