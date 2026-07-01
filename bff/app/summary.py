"""聚合摘要构建：把 Wazuh 海量数据在数据库端聚合成几 KB 的结构化摘要。

这是"先聚合再分析"的实现核心。所有原始事件都在 Indexer 端用 aggs 分桶，
只取回统计数字；Agent / SCA 也只取汇总，不取明细。
"""
from __future__ import annotations

import asyncio
import re
from difflib import SequenceMatcher
from datetime import datetime, timezone
from typing import Any

from .config import settings
from .wazuh_client import wazuh

# 严重度分级（与 Wazuh rule.level 对应）
SEVERITY_RANGES = [
    {"key": "low", "to": 7},
    {"key": "medium", "from": 7, "to": 12},
    {"key": "high", "from": 12, "to": 15},
    {"key": "critical", "from": 15},
]

BASELINE_GROUPS = ["sca", "rootcheck"]

SECURITY_FILTER = {
    "bool": {
        "must": [{"range": {"rule.level": {"gte": 7}}}],
        "must_not": [
            {"terms": {"rule.groups": BASELINE_GROUPS}},
            {"bool": {"must": [
                {"terms": {"rule.groups": ["syscheck"]}},
                {"range": {"rule.level": {"lt": 12}}},
            ]}},
        ],
    }
}


def _alerts_agg_query() -> dict[str, Any]:
    return {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": settings.summary_window}}},
        "aggs": {
            "by_severity": {"range": {"field": "rule.level", "keyed": True, "ranges": SEVERITY_RANGES}},
            "security_total": {"filter": SECURITY_FILTER},
            "by_group": {"terms": {"field": "rule.groups", "size": 10}},
            "by_agent": {"terms": {"field": "agent.name", "size": 50}},
            "top_rules": {"terms": {"field": "rule.description", "size": 8}},
            "fim_actions": {
                "filter": {"terms": {"rule.groups": ["syscheck"]}},
                "aggs": {"actions": {"terms": {"field": "syscheck.event", "size": 5}}},
            },
            "compliance": {
                "filters": {
                    "filters": {
                        "pci_dss": {"exists": {"field": "rule.pci_dss"}},
                        "gdpr": {"exists": {"field": "rule.gdpr"}},
                        "hipaa": {"exists": {"field": "rule.hipaa"}},
                        "nist": {"exists": {"field": "rule.nist_800_53"}},
                        "mitre": {"exists": {"field": "rule.mitre.id"}},
                    }
                }
            },
        },
    }


def _bucket_to_map(buckets: list[dict]) -> dict[str, int]:
    return {b["key"]: b["doc_count"] for b in buckets}


def _recent_keepalive(value: Any, minutes: int = 10) -> bool:
    if not value:
        return False
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.year >= 9999:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - ts.astimezone(timezone.utc)
    return 0 <= age.total_seconds() <= minutes * 60


def _display_status(agent: dict[str, Any]) -> str:
    status = str(agent.get("status") or "")
    if status != "active" and _recent_keepalive(agent.get("lastKeepAlive")):
        return "active"
    return status


def _name_key(value: Any) -> str:
    text = str(value or "").lower()
    return "".join(ch for ch in text if ch.isalnum())


def _is_probable_duplicate(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if not a.get("name") or not b.get("name"):
        return False
    if a.get("id") == b.get("id"):
        return False
    if (a.get("platform") or "") != (b.get("platform") or ""):
        return False
    if a.get("ip") and b.get("ip") and a.get("ip") == b.get("ip"):
        return True
    ax, bx = _name_key(a.get("name")), _name_key(b.get("name"))
    if not ax or not bx:
        return False
    if ax in bx or bx in ax:
        return True
    return SequenceMatcher(None, ax, bx).ratio() >= 0.82


def _keepalive_sort_key(row: dict[str, Any]) -> datetime:
    value = row.get("last_keep_alive")
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _attach_duplicate_notes(rows: list[dict[str, Any]]) -> None:
    """只提示疑似旧记录，不自动删除，避免误伤真实终端。"""
    for row in rows:
        matches = [other for other in rows if _is_probable_duplicate(row, other)]
        if not matches:
            continue
        candidates = sorted(matches + [row], key=lambda item: (item.get("status") == "active", _keepalive_sort_key(item)), reverse=True)
        keeper = candidates[0]
        if keeper.get("id") == row.get("id"):
            continue
        row["duplicate_of"] = keeper.get("id")
        row["duplicate_note"] = f"疑似旧终端记录，可能已由 {keeper.get('name')}（ID:{keeper.get('id')}）替代"


async def build_summary() -> dict[str, Any]:
    """产出一份 < 几 KB 的聚合摘要，供 GuizangAI 分析与仪表盘展示。"""
    agents = await wazuh.agents()

    # 告警聚合（一次 size:0 查询拿回全部统计）
    try:
        agg = (await wazuh.indexer_search(_alerts_agg_query())).get("aggregations", {})
    except Exception:
        agg = {}

    # 严重度
    sev_buckets = agg.get("by_severity", {}).get("buckets", {})
    by_severity = {k: int(v.get("doc_count", 0)) for k, v in sev_buckets.items()} if isinstance(sev_buckets, dict) else {}

    total_alerts = sum(by_severity.values())
    security_total = int(agg.get("security_total", {}).get("doc_count", 0))
    baseline_total = max(0, total_alerts - security_total)

    # 各 Agent 的 SCA 评分（仅汇总分数，不取明细）
    real_agents = [a for a in agents if a.get("id") != "000"]
    sca_results = await asyncio.gather(*[wazuh.sca(a["id"]) for a in real_agents], return_exceptions=True)
    compliance = {}
    for a, sca in zip(real_agents, sca_results):
        if isinstance(sca, dict) and sca:
            compliance[a.get("name", a["id"])] = {
                "policy": sca.get("name"),
                "score": sca.get("score"),
                "pass": sca.get("pass"),
                "fail": sca.get("fail"),
            }

    # 系统分布
    by_os: dict[str, int] = {}
    for a in real_agents:
        plat = (a.get("os") or {}).get("platform", "unknown")
        by_os[plat] = by_os.get(plat, 0) + 1

    fim_actions = agg.get("fim_actions", {}).get("actions", {}).get("buckets", [])
    comp_buckets = agg.get("compliance", {}).get("buckets", {})

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": settings.summary_window,
        "endpoints": {
            "total": len(real_agents),
            "active": sum(1 for a in real_agents if _display_status(a) == "active"),
            "disconnected": sum(1 for a in real_agents if _display_status(a) != "active"),
            "by_os": by_os,
        },
        "alerts": {
            "total": total_alerts,
            "security_total": security_total,
            "baseline_total": baseline_total,
            "by_severity": by_severity,
            "by_group": _bucket_to_map(agg.get("by_group", {}).get("buckets", [])),
            "by_agent": _bucket_to_map(agg.get("by_agent", {}).get("buckets", [])),
            "top_rules": _bucket_to_map(agg.get("top_rules", {}).get("buckets", [])),
        },
        "fim": {b["key"]: b["doc_count"] for b in fim_actions},
        "compliance": compliance,
        "compliance_tags": {k: v.get("doc_count", 0) for k, v in comp_buckets.items()} if isinstance(comp_buckets, dict) else {},
    }
    return summary


async def fetch_raw_events() -> list[dict[str, Any]]:
    """取回时间窗内的原始告警全量明细，随摘要一起发给 GuizangAI。

    受 settings.guizangai_send_raw_logs 开关控制；条数上限 guizangai_raw_logs_max 防止超出模型上下文。
    """
    if not settings.guizangai_send_raw_logs:
        return []
    size = settings.guizangai_raw_logs_max or 10000
    fields = [f.strip() for f in (settings.guizangai_raw_logs_fields or "").split(",") if f.strip()] or None
    try:
        events = await wazuh.fetch_alerts(size, settings.summary_window, fields)
    except Exception:
        return []
    return _prepare_ai_raw_events(events, max_items=size)


def _prepare_ai_raw_events(events: list[dict[str, Any]], max_items: int = 80) -> list[dict[str, Any]]:
    """给模型的原始证据：裁字段、去低价值噪声、合并重复告警，并优先保留高风险。"""
    if not events:
        return []

    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for event in events:
        slim = _slim_ai_event(event)
        if _is_low_value_ai_event(slim):
            continue
        key = _ai_event_key(slim)
        current = grouped.get(key)
        if not current:
            grouped[key] = {**slim, "occurrences": 1}
            continue
        current["occurrences"] += 1
        if _ai_event_rank(slim) > _ai_event_rank(current):
            grouped[key] = {**slim, "occurrences": current["occurrences"]}

    prepared = sorted(grouped.values(), key=_ai_event_rank, reverse=True)
    return prepared[: max(1, min(int(max_items or 80), 200))]


def _slim_ai_event(event: dict[str, Any]) -> dict[str, Any]:
    rule = _dict_at(event, "rule")
    agent = _dict_at(event, "agent")
    syscheck = _dict_at(event, "syscheck")
    data = _dict_at(event, "data")
    mitre = _dict_at(rule, "mitre")
    return {
        "timestamp": _text(event.get("timestamp")),
        "agent": _text(agent.get("name")),
        "level": _int(rule.get("level")),
        "rule": _text(rule.get("description")),
        "groups": _string_list(rule.get("groups")),
        "mitre": _string_list(mitre.get("id") if isinstance(mitre, dict) else None),
        "path": _text(syscheck.get("path")),
        "event": _text(syscheck.get("event")),
        "srcip": _text(data.get("srcip")),
        "location": _text(event.get("location")),
    }


def _is_low_value_ai_event(event: dict[str, Any]) -> bool:
    level = int(event.get("level") or 0)
    rule = str(event.get("rule") or "").lower()
    groups = {str(g).lower() for g in event.get("groups") or []}
    if level >= 12:
        return False
    if groups & {"authentication", "syscheck", "rootcheck", "windows", "mitre"}:
        return False
    if any(token in rule for token in ("failed", "failure", "denied", "root", "malware", "trojan", "port", "agent disconnected")):
        return False
    # 屏幕锁定/解锁、Agent 心跳类事件量大但业务价值低，低等级时不送模型。
    return bool(re.search(r"screen (locked|unlocked)|agent started|agent stopped|server started", rule, re.I))


def _ai_event_key(event: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        _norm_key(event.get("agent")),
        _norm_key(event.get("rule")),
        _norm_key(event.get("path") or event.get("location")),
        _norm_key(event.get("srcip")),
    )


def _ai_event_rank(event: dict[str, Any]) -> tuple[int, int, int, str]:
    level = int(event.get("level") or 0)
    occurrences = int(event.get("occurrences") or 1)
    groups = {str(g).lower() for g in event.get("groups") or []}
    security_boost = 1 if groups & {"authentication", "syscheck", "rootcheck", "windows", "mitre"} else 0
    return (level, security_boost, occurrences, str(event.get("timestamp") or ""))


def _dict_at(value: Any, key: str | None = None) -> dict[str, Any]:
    target = value.get(key) if key and isinstance(value, dict) else value
    return target if isinstance(target, dict) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    if value:
        return [str(value)]
    return []


def _norm_key(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip().lower())
    return text[:180]


def agents_table(agents: list[dict]) -> list[dict]:
    """供仪表盘"资产/设备列表"展示的精简表格。"""
    rows = []
    for a in agents:
        if a.get("id") == "000":
            continue
        os_ = a.get("os") or {}
        rows.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "status": _display_status(a),
            "os": os_.get("name") or os_.get("platform"),
            "platform": os_.get("platform"),
            "version": a.get("version"),
            "last_keep_alive": a.get("lastKeepAlive"),
            "registered_at": a.get("dateAdd"),
        })
    _attach_duplicate_notes(rows)
    return rows
