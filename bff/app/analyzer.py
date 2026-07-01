"""分析编排：build_summary -> GuizangAI 预设任务 -> 落库。由调度器定时触发。"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
from typing import Any

from .config import settings
from .db import AnalysisSnapshot, GuizangAICache, MetricSnapshot, SessionLocal
from .ai.client import guizang_ai
from .ai.mock import mock_result
from .ai.perf import finish_run, record_result_perf, set_current_task, start_run
from .ai.prompts import PRESET_TASKS, PROMPT_VERSION
from .ai.text_cleaning import clean_result
from .summary import build_summary, fetch_raw_events
from .wazuh_client import wazuh

log = logging.getLogger("analyzer")
_analysis_lock = asyncio.Lock()


async def run_analysis() -> dict:
    """执行一轮完整分析：聚合 + 取原始日志 -> 逐个预设任务分析 -> 存库。返回本轮结果。"""
    if _analysis_lock.locked():
        log.info("已有分析任务在运行，本次触发跳过。")
        return {"status": "already_running", "analysis": latest_analysis()}

    async with _analysis_lock:
        start_run()
        try:
            summary = await build_summary()
            raw_events = await fetch_raw_events()
            log.info("本轮取回原始日志 %s 条", len(raw_events))
            cache_key = _analysis_cache_key(summary, raw_events)
            cached = _read_analysis_cache(cache_key)
            if cached:
                log.info("摘要未变化，复用 GuizangAI 分析缓存。")
                return {"status": "cached", "summary": summary, "analysis": cached}

            results: dict[str, dict] = {}

            async def run_task(task_key: str) -> tuple[str, dict]:
                set_current_task(task_key)
                result = clean_result(await guizang_ai.analyze(task_key, summary, raw_events))
                record_result_perf(task_key, result)
                return task_key, result

            concurrency = max(1, int(settings.guizangai_analysis_concurrency or 1))
            if concurrency <= 1:
                for task_key in PRESET_TASKS:
                    key, result = await run_task(task_key)
                    results[key] = result
            else:
                sem = asyncio.Semaphore(concurrency)

                async def guarded(task_key: str) -> tuple[str, dict]:
                    async with sem:
                        return await run_task(task_key)

                for key, result in await asyncio.gather(*(guarded(task_key) for task_key in PRESET_TASKS)):
                    results[key] = result

            _persist(summary, results)
            if _cacheable_analysis(results):
                _write_analysis_cache(cache_key, results)
            log.info("分析完成：%s 个任务", len(results))
            return {"summary": summary, "analysis": results}
        finally:
            finish_run()


def _persist(summary: dict, results: dict[str, dict]) -> None:
    sev = summary.get("alerts", {}).get("by_severity", {})
    risk = int(results.get("overview", {}).get("risk_score", 0) or 0)
    with SessionLocal() as s:
        for task, result in results.items():
            cleaned = clean_result(result)
            s.add(AnalysisSnapshot(task=task, result=cleaned, source=cleaned.get("_source", "mock")))
        s.add(MetricSnapshot(
            risk_score=risk,
            alerts_total=int(summary.get("alerts", {}).get("total", 0)),
            alerts_high=int(sev.get("high", 0)) + int(sev.get("critical", 0)),
            endpoints_active=int(summary.get("endpoints", {}).get("active", 0)),
            summary_json=summary,
        ))
        s.commit()


def latest_analysis(lang: str = "zh", summary: dict | None = None) -> dict:
    """读取每个任务的展示结论：优先最新成功 GuizangAI，失败时才兜底 mock。"""
    out: dict[str, dict] = {}
    with SessionLocal() as s:
        for task_key in PRESET_TASKS:
            row = (
                s.query(AnalysisSnapshot)
                .filter(AnalysisSnapshot.task == task_key, AnalysisSnapshot.source == "guizangai")
                .order_by(AnalysisSnapshot.created_at.desc())
                .first()
            )
            if row is None:
                row = (
                    s.query(AnalysisSnapshot)
                    .filter(AnalysisSnapshot.task == task_key)
                    .order_by(AnalysisSnapshot.created_at.desc())
                    .first()
                )
            if row:
                result = clean_result(row.result)
                if lang == "en":
                    result = _english_result(task_key, result, summary)
                out[task_key] = {
                    "result": result,
                    "source": row.source,
                    "created_at": row.created_at.isoformat(),
                }
            elif lang == "en" and summary is not None:
                out[task_key] = {
                    "result": mock_result(task_key, summary, "en"),
                    "source": "mock",
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
    return out


def _english_result(task_key: str, result: dict, summary: dict | None) -> dict:
    """Preset snapshots are generated in Chinese; localize stable dashboard fields for English UI."""
    if not summary:
        return result
    source = result.get("_source")
    english = mock_result(task_key, summary, "en")
    if task_key == "overview":
        return {
            **result,
            "risk_level": english.get("risk_level"),
            "headline": english.get("headline"),
            "summary": english.get("summary"),
            "top_actions": english.get("top_actions"),
            "_source": source or result.get("_source"),
        }
    if task_key == "alert_triage":
        return {**result, "clusters": english.get("clusters", []), "_source": source or result.get("_source")}
    if task_key == "compliance":
        return {
            **result,
            "recommendations": english.get("recommendations", []),
            "_source": source or result.get("_source"),
        }
    return result


def _trend_risk_score(alerts_total: int, alerts_high: int) -> int:
    """趋势图风险指数从实时告警聚合派生，避免旧快照和告警列表不一致。"""
    if alerts_high > 0:
        return min(85, 50 + alerts_high)
    if alerts_total > 200:
        return 40
    return 18


def _analysis_cache_key(summary: dict[str, Any], raw_events: list[dict[str, Any]]) -> str:
    payload = {
        "model": settings.guizangai_model,
        "api_style": settings.guizangai_api_style,
        "prompt_version": PROMPT_VERSION,
        "tasks": list(PRESET_TASKS.keys()),
        "summary": _stable_for_cache(summary),
        "raw_events": raw_events,
    }
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return "analysis:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def _stable_for_cache(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _stable_for_cache(v) for k, v in value.items() if k not in {"generated_at"}}
    if isinstance(value, list):
        return [_stable_for_cache(v) for v in value]
    return value


def _read_analysis_cache(cache_key: str) -> dict[str, dict] | None:
    try:
        with SessionLocal() as s:
            row = s.query(GuizangAICache).filter(GuizangAICache.cache_key == cache_key).first()
            if not row:
                return None
            ttl = int(settings.guizangai_analysis_cache_ttl_seconds or 0)
            if ttl > 0:
                created_at = row.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=dt.timezone.utc)
                age = (dt.datetime.now(dt.timezone.utc) - created_at.astimezone(dt.timezone.utc)).total_seconds()
                if age > ttl:
                    return None
            result = row.result or {}
            analysis = result.get("analysis") if isinstance(result, dict) else None
            if not isinstance(analysis, dict):
                return None
            return {str(k): clean_result(v if isinstance(v, dict) else {}) | {"_cached": True} for k, v in analysis.items()}
    except Exception:
        return None


def _write_analysis_cache(cache_key: str, results: dict[str, dict]) -> None:
    safe_results = {
        key: {k: v for k, v in value.items() if k != "_perf"}
        for key, value in results.items()
    }
    try:
        with SessionLocal() as s:
            row = s.query(GuizangAICache).filter(GuizangAICache.cache_key == cache_key).first()
            payload = {"analysis": safe_results}
            if row:
                row.result = payload
                row.purpose = "analysis"
                row.created_at = dt.datetime.now(dt.timezone.utc)
            else:
                s.add(GuizangAICache(cache_key=cache_key, purpose="analysis", result=payload))
            s.commit()
    except Exception:
        return


def _cacheable_analysis(results: dict[str, dict]) -> bool:
    return bool(results) and all(not result.get("_error") for result in results.values())


def _snapshot_risk_trend(days: int = 7) -> list[dict]:
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    with SessionLocal() as s:
        rows = (
            s.query(MetricSnapshot)
            .filter(MetricSnapshot.created_at >= since)
            .order_by(MetricSnapshot.created_at.asc())
            .all()
        )
        return [
            {
                "time": r.created_at.isoformat(),
                "risk_score": r.risk_score,
                "alerts_total": r.alerts_total,
                "alerts_high": r.alerts_high,
                "endpoints_active": r.endpoints_active,
            }
            for r in rows
        ]


async def risk_trend(days: int = 14, interval: str = "day") -> list[dict]:
    """风险趋势告警数以 Wazuh 实时数据为准，确保和安全告警页面能对上。"""
    try:
        rows = await wazuh.alerts_trend(days, interval=interval)
    except Exception:
        log.exception("读取实时告警趋势失败，回退到历史快照。")
        return _snapshot_risk_trend(days)

    return [
        {
            "time": row.get("time"),
            "risk_score": _trend_risk_score(int(row.get("alerts_total") or 0), int(row.get("alerts_high") or 0)),
            "alerts_total": int(row.get("alerts_total") or 0),
            "alerts_high": int(row.get("alerts_high") or 0),
            "endpoints_active": 0,
        }
        for row in rows
    ]
