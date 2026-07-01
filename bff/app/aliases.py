"""终端显示别名：把 Wazuh 注册名映射成便于识别的自定义名称（仅影响仪表盘展示）。"""
from __future__ import annotations

import datetime as dt
import re

from .db import AgentAlias, SessionLocal

# 与安装脚本一致：显示别名只保留可读字符，去掉首尾空白，限制长度，避免脏数据。
_MAXLEN = 64


def _clean(s: str | None) -> str:
    s = (s or "").strip()
    # 折叠多余空白；保留中文/字母/数字/常用分隔符（展示用，无需像 Wazuh 注册名那样严格）
    s = re.sub(r"\s+", " ", s)
    return s[:_MAXLEN]


def get_aliases() -> dict[str, str]:
    """返回 {注册名: 别名} 映射。"""
    with SessionLocal() as s:
        return {a.name: a.alias for a in s.query(AgentAlias).all() if a.alias}


def set_alias(name: str, alias: str) -> None:
    """设置/清除某终端的显示别名。alias 为空表示恢复使用注册名（删除别名）。"""
    name = _clean(name)
    alias = _clean(alias)
    if not name:
        return
    with SessionLocal() as s:
        row = s.get(AgentAlias, name)
        if not alias:
            if row:
                s.delete(row)
                s.commit()
            return
        if row:
            row.alias = alias
            row.updated_at = dt.datetime.now(dt.timezone.utc)
        else:
            s.add(AgentAlias(name=name, alias=alias))
        s.commit()
