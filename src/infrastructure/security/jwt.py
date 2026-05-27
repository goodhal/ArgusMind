"""
轻量 JWT 实现（HS256），不依赖 pyjwt。

注意：密钥通过 DB 配置（configs 表：jwt_secret）读取，启动期若无则自动生成一次并持久化。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

_ALGO = "HS256"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def encode_token(payload: Dict[str, Any], secret: str, expires_in: int = 3600 * 24) -> str:
    now = int(time.time())
    body: Dict[str, Any] = {"iat": now, "exp": now + expires_in}
    body.update(payload)
    header = {"alg": _ALGO, "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def decode_token(token: str, secret: str) -> Optional[Dict[str, Any]]:
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual = _b64url_decode(s_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected, actual):
        return None
    try:
        body = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    exp = body.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        return None
    return body


def generate_secret(length: int = 48) -> str:
    return base64.urlsafe_b64encode(os.urandom(length)).decode("ascii").rstrip("=")
