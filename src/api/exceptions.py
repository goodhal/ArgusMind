"""自定义异常 + FastAPI 异常处理器"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class AppException(Exception):
    """应用层业务异常"""

    status_code: int = 400
    code: str = "bad_request"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class BadRequestError(AppException):
    status_code = 400
    code = "bad_request"


class NotFoundError(AppException):
    status_code = 404
    code = "not_found"


class UnauthorizedError(AppException):
    status_code = 401
    code = "unauthorized"


class ForbiddenError(AppException):
    status_code = 403
    code = "forbidden"


class ConflictError(AppException):
    status_code = 409
    code = "conflict"


def _error_body(success: bool, code: str, message: str, **extra: Any) -> Dict[str, Any]:
    body = {"success": success, "code": code, "message": message}
    if extra:
        body["detail"] = extra
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppException)
    async def _app_exc_handler(_: Request, exc: AppException):
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(False, exc.code, exc.message),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(_: Request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(False, f"http_{exc.status_code}", detail),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exc_handler(_: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content=_error_body(False, "validation_error", "请求参数校验失败", errors=exc.errors()),
        )

    @app.exception_handler(Exception)
    async def _uncaught_handler(_: Request, exc: Exception):  # pragma: no cover - 兜底
        logger.exception("[uncaught] %s", exc)
        return JSONResponse(
            status_code=500,
            content=_error_body(False, "internal_error", "Internal Server Error"),
        )
