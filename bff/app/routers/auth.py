"""登录鉴权 REST API：登录、获取当前用户、修改账号密码。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import (
    authenticate,
    get_user,
    make_token,
    require_auth,
    update_credentials,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class ChangeIn(BaseModel):
    old_username: str
    old_password: str
    new_username: str
    new_password: str


@router.post("/login")
async def login(body: LoginIn):
    if not authenticate(body.username, body.password):
        raise HTTPException(status_code=401, detail="账号或密码错误")
    return {"token": make_token(body.username), "username": body.username}


@router.get("/me")
async def me(username: str = Depends(require_auth)):
    return {"username": username}


@router.post("/change")
async def change(body: ChangeIn, _: str = Depends(require_auth)):
    # 用原账号+原密码校验后再修改（满足"用原账号密码验证"）
    if not authenticate(body.old_username, body.old_password):
        raise HTTPException(status_code=401, detail="原账号或原密码错误")
    new_user = body.new_username.strip()
    if not new_user or not body.new_password:
        raise HTTPException(status_code=400, detail="新账号和新密码不能为空")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密码至少 6 位")
    update_credentials(new_user, body.new_password)
    # 凭据已变，签发对应新账号的新令牌
    return {"token": make_token(new_user), "username": new_user}


@router.get("/exists")
async def exists():
    """是否已初始化账号（前端可用于判断）。"""
    return {"initialized": get_user() is not None}
