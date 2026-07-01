"""PostgreSQL 持久化：存储 AI 分析结论历史、趋势快照、报表记录。

注意：原始安全事件历史在 Wazuh Indexer，这里只存"压缩后的结论与趋势"，体积小、可长留。
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


class AnalysisSnapshot(Base):
    """每次后台分析的产出（按任务类型存一条）。"""
    __tablename__ = "analysis_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), index=True)
    task: Mapped[str] = mapped_column(String(64), index=True)   # overview / alert_triage / compliance
    result: Mapped[dict[str, Any]] = mapped_column(JSON)        # GuizangAI/mock 返回的结构化结论
    source: Mapped[str] = mapped_column(String(16), default="mock")  # guizang_ai / mock


class AppUser(Base):
    """仪表盘登录账号（单账号模型，通常只有一行）。"""
    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    salt: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc))


class MetricSnapshot(Base):
    """趋势快照：每次分析时把关键指标存一份，用于"风险趋势"折线图。"""
    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    alerts_total: Mapped[int] = mapped_column(Integer, default=0)
    alerts_high: Mapped[int] = mapped_column(Integer, default=0)
    endpoints_active: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON)


class GuizangAICache(Base):
    """按告警/上下文缓存按需生成的 GuizangAI 结果，避免重复推理。"""
    __tablename__ = "guizangai_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), index=True)
    cache_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(64), index=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON)


class SecurityIssue(Base):
    """高危安全问题生命周期：把一次性告警/漏洞归并成可追踪的问题。"""
    __tablename__ = "security_issues"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="alert")
    agent: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    level: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    groups: Mapped[Any] = mapped_column(JSON, default=list)
    mitre: Mapped[Any] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    timeline: Mapped[Any] = mapped_column(JSON, default=list)


class AgentAlias(Base):
    """终端显示别名，仅影响仪表盘展示，不改动 Wazuh 注册名。"""
    __tablename__ = "agent_aliases"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    alias: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc))


def init_db(retries: int = 10, delay: float = 3.0) -> None:
    """建表（带重试，等待数据库就绪）。"""
    import time
    last = None
    for _ in range(retries):
        try:
            Base.metadata.create_all(engine)
            return
        except Exception as e:  # 数据库可能还没起来
            last = e
            time.sleep(delay)
    raise RuntimeError(f"数据库初始化失败: {last}")
