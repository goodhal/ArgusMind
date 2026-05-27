"""时间工具"""
from datetime import datetime, timezone


def now_utc() -> datetime:
    """获取当前 UTC 时间"""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """获取当前时间的 ISO 格式字符串"""
    return now_utc().isoformat()

