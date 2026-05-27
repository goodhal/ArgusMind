"""鉴权路由：登录 / 当前用户 / 修改密码"""
from __future__ import annotations

from fastapi import APIRouter

from src.api.exceptions import BadRequestError, UnauthorizedError
from src.api.security import CurrentUserDep
from src.schemas.auth import ChangePasswordRequest, CurrentUser, LoginRequest, LoginResponse
from src.schemas.common import OkResponse
from src.services.auth_service import authenticate, change_password, issue_token

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest) -> LoginResponse:
    user = authenticate(body.username, body.password)
    if user is None:
        raise UnauthorizedError("用户名或密码错误")
    token = issue_token(user)
    return LoginResponse(
        success=True, token=token, username=user.username, display_name=user.display_name
    )


@router.get("/me", response_model=OkResponse[CurrentUser])
def me(user: CurrentUser = CurrentUserDep) -> OkResponse[CurrentUser]:
    return OkResponse[CurrentUser](data=user)


@router.post("/change-password", response_model=OkResponse[None])
def change_password_route(
    body: ChangePasswordRequest,
    user: CurrentUser = CurrentUserDep,
) -> OkResponse[None]:
    if body.old_password == body.new_password:
        raise BadRequestError("新密码不能与当前密码相同")
    if not change_password(user.id, body.old_password, body.new_password):
        raise BadRequestError("当前密码错误")
    return OkResponse[None](data=None)
