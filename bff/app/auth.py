"""仪表盘登录鉴权：口令哈希 + 签名令牌（仅用标准库，无新增依赖）。

- 口令用 PBKDF2-HMAC-SHA256 加盐哈希存库，不保存明文。
- 登录令牌为 HMAC 签名的短令牌：base64url(payload).sig，含用户名与过期时间。
- 单账号模型：首次启动自动 seed 默认账号（见 config）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

from fastapi import Header, HTTPException, Query, status

from .config import settings
from .db import AppUser, SessionLocal

_PBKDF2_ROUNDS = 200_000


# ----------------------------------------------------------------- 口令哈希
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    calc, _ = hash_password(password, salt)
    return hmac.compare_digest(calc, password_hash)


# ----------------------------------------------------------------- 令牌
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload_b64: str) -> str:
    sig = hmac.new(settings.auth_secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64u(sig)


def make_token(username: str) -> str:
    payload = {"u": username, "exp": int(time.time()) + settings.auth_token_ttl_hours * 3600}
    payload_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64)}"


def verify_token(token: str) -> str | None:
    """校验令牌，返回用户名；无效/过期返回 None。"""
    try:
        payload_b64, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _sign(payload_b64)):
            return None
        payload = json.loads(_b64u_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload.get("u")
    except Exception:
        return None


# ----------------------------------------------------------------- 用户读写
def get_user() -> AppUser | None:
    with SessionLocal() as s:
        return s.query(AppUser).order_by(AppUser.id.asc()).first()


def seed_default_user() -> None:
    """首次启动时创建默认账号（已存在则跳过）。"""
    with SessionLocal() as s:
        if s.query(AppUser).first():
            return
        pwd_hash, salt = hash_password(settings.default_admin_password)
        s.add(AppUser(username=settings.default_admin_user, password_hash=pwd_hash, salt=salt))
        s.commit()


def authenticate(username: str, password: str) -> bool:
    user = get_user()
    if not user or user.username != username:
        return False
    return verify_password(password, user.password_hash, user.salt)


def update_credentials(new_username: str, new_password: str) -> None:
    with SessionLocal() as s:
        user = s.query(AppUser).order_by(AppUser.id.asc()).first()
        if not user:
            pwd_hash, salt = hash_password(new_password)
            s.add(AppUser(username=new_username, password_hash=pwd_hash, salt=salt))
        else:
            pwd_hash, salt = hash_password(new_password)
            user.username = new_username
            user.password_hash = pwd_hash
            user.salt = salt
            import datetime as dt
            user.updated_at = dt.datetime.now(dt.timezone.utc)
        s.commit()


# ----------------------------------------------------------------- FastAPI 依赖
async def require_auth(
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
) -> str:
    """保护接口：从 Authorization: Bearer 头或 ?token= 查询参数取令牌。"""
    raw = ""
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    elif token:
        raw = token.strip()
    username = verify_token(raw) if raw else None
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录或登录已过期")
    return username
