"""AI 推理性能状态与展示数据。"""

from __future__ import annotations

import datetime as dt
from typing import Any

from ..db import AnalysisSnapshot, SessionLocal
from .prompts import PRESET_TASKS

_runtime_perf: dict[str, Any] = {
    "running": False,
    "current_task": None,
    "started_at": None,
    "per_task": {},
    "latest": None,
}


def start_run() -> None:
    _runtime_perf.update({
        "running": True,
        "current_task": None,
        "started_at": dt.datetime.now(dt.timezone.utc),
    })


def set_current_task(task_key: str | None) -> None:
    _runtime_perf["current_task"] = task_key


def finish_run() -> None:
    _runtime_perf["running"] = False
    _runtime_perf["current_task"] = None


def record_result_perf(task_key: str, result: dict[str, Any]) -> None:
    perf = result.get("_perf") or {}
    if perf:
        record_runtime_perf(task_key, perf, result.get("_source", "mock"), result.get("_error") or "")


def record_runtime_perf(task_key: str, perf: dict[str, Any], source: str = "guizangai", last_error: str = "") -> None:
    """记录任意 GuizangAI 调用的推理性能，包括定时分析和按需处理建议。"""
    if not perf:
        return
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    perf = {
        **perf,
        "task": task_key,
        "created_at": now,
        "source": source,
        "last_error": perf.get("last_error") or last_error or "",
    }
    _runtime_perf.setdefault("per_task", {})[task_key] = perf
    latest = _runtime_perf.get("latest")
    # 流式建议目前只能记录耗时，拿不到 Ollama 的 token 统计；不要用它覆盖可展示 tokens/s 的最新性能。
    if perf.get("tokens_per_second") is not None or latest is None or latest.get("tokens_per_second") is None:
        _runtime_perf["latest"] = perf


def latest_ai_perf() -> dict:
    """汇总最新 GuizangAI 推理性能，供仪表盘展示 tokens/s。"""
    per_task = dict(_runtime_perf.get("per_task") or {})
    speeds = []
    latest = _runtime_perf.get("latest")
    total_eval_count = sum(int(p.get("eval_count") or 0) for p in per_task.values())
    recent_snapshot_count = 0
    recent_error_count = 0
    recent_cached_count = 0
    for perf in per_task.values():
        if perf.get("tokens_per_second") is not None:
            speeds.append(float(perf["tokens_per_second"]))
    with SessionLocal() as s:
        for task_key in PRESET_TASKS:
            rows = (
                s.query(AnalysisSnapshot)
                .filter(AnalysisSnapshot.task == task_key)
                .order_by(AnalysisSnapshot.created_at.desc())
                .limit(20)
                .all()
            )
            recent_snapshot_count += len(rows)
            recent_error_count += sum(1 for row in rows if (row.result or {}).get("_error"))
            recent_cached_count += sum(1 for row in rows if (row.result or {}).get("_cached"))
            if task_key in per_task:
                continue
            for row in rows:
                result = row.result or {}
                perf = result.get("_perf") or {}
                if not perf:
                    continue
                perf = {
                    **perf,
                    "created_at": row.created_at.isoformat(),
                    "source": row.source,
                    "last_error": perf.get("last_error") or result.get("_error") or "",
                }
                per_task[task_key] = perf
                if perf.get("tokens_per_second") is not None:
                    speeds.append(float(perf["tokens_per_second"]))
                total_eval_count += int(perf.get("eval_count") or 0)
                if latest is None or (perf.get("created_at") or "") > (latest.get("created_at") or ""):
                    latest = perf
                break
    if latest is not None and latest.get("tokens_per_second") is None:
        latest_with_speed = [
            perf for perf in per_task.values()
            if perf.get("tokens_per_second") is not None
        ]
        if latest_with_speed:
            latest = max(latest_with_speed, key=lambda perf: perf.get("created_at") or "")
    return {
        "latest": latest,
        "per_task": per_task,
        "avg_tokens_per_second": round(sum(speeds) / len(speeds), 2) if speeds else None,
        "total_eval_count": total_eval_count,
        "recent_snapshot_count": recent_snapshot_count,
        "recent_error_count": recent_error_count,
        "recent_cached_count": recent_cached_count,
        "running": bool(_runtime_perf.get("running")),
        "current_task": _runtime_perf.get("current_task"),
        "started_at": _runtime_perf["started_at"].isoformat() if _runtime_perf.get("started_at") else None,
        "running_seconds": (
            round((dt.datetime.now(dt.timezone.utc) - _runtime_perf["started_at"]).total_seconds(), 1)
            if _runtime_perf.get("running") and _runtime_perf.get("started_at") else 0
        ),
    }
