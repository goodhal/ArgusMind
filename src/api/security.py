"""鉴权依赖（JWT / API Key）"""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header

from src.api.exceptions import UnauthorizedError
from src.schemas.auth import CurrentUser
from src.services.auth_service import resolve_user


def _extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return authorization.strip()


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> CurrentUser:
    token = _extract_token(authorization)
    if not token:
        raise UnauthorizedError("未提供鉴权凭证")
    user = resolve_user(token)
    if not user:
        raise UnauthorizedError("凭证无效或已过期")
    return CurrentUser(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_active=True,
        is_superuser=False,
    )


CurrentUserDep = Depends(get_current_user)
