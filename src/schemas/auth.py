"""鉴权相关 schema"""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    success: bool = True
    token: str
    username: str
    display_name: str = ""


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)


class CurrentUser(BaseModel):
    id: str
    username: str
    display_name: str
    is_active: bool
    is_superuser: bool
