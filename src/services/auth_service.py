"""鉴权服务：登录 + token 解析"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import User
from src.infrastructure.security.jwt import decode_token, encode_token
from src.infrastructure.security.password import hash_password, verify_password
from src.services.config_service import ensure_jwt_secret


def authenticate(username: str, password: str) -> Optional[User]:
    with session_scope() as session:
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        session.expunge(user)
        return user


def issue_token(user: User, *, expires_in: int = 3600 * 24) -> str:
    secret = ensure_jwt_secret()
    return encode_token(
        {
            "sub": user.id,
            "username": user.username,
            "is_superuser": False,
        },
        secret,
        expires_in=expires_in,
    )


def change_password(user_id: str, old_password: str, new_password: str) -> bool:
    """修改密码；旧密码错误时返回 False。"""
    with session_scope() as session:
        user = session.get(User, user_id)
        if not user:
            return False
        if not verify_password(old_password, user.password_hash):
            return False
        user.password_hash = hash_password(new_password)
        return True


def resolve_user(token: str) -> Optional[User]:
    if not token:
        return None
    secret = ensure_jwt_secret()
    payload = decode_token(token, secret)
    if not payload:
        return None
    uid = payload.get("sub")
    if not uid:
        return None
    with session_scope() as session:
        user = session.get(User, uid)
        if not user:
            return None
        session.expunge(user)
        return user
