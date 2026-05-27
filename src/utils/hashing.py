"""哈希工具"""
import hashlib


def hash_string(s: str) -> str:
    """计算字符串的 SHA256 哈希值"""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

