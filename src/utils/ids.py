"""ID 生成工具"""
import uuid
from typing import Optional


def generate_uuid() -> str:
    """生成 UUID 字符串"""
    return str(uuid.uuid4())


def generate_id(prefix: str = "") -> str:
    """生成带前缀的 ID"""
    if prefix:
        return f"{prefix}_{uuid.uuid4().hex[:16]}"
    return uuid.uuid4().hex

