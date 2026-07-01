"""仪表盘 REST API：供前端读取总览、资产、告警、合规、FIM、AI 结论、趋势、导出。"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import text

from ..config import settings
from ..db import SessionLocal
from ..aliases import get_aliases, set_alias
from ..ai.client import guizang_ai
from ..ai.perf import latest_ai_perf, record_runtime_perf
from ..analyzer import latest_analysis, risk_trend, run_analysis
from ..auth import require_auth
from ..issues import (
    alert_issue_target,
    fingerprint,
    get_issue_by_fingerprint,
    issue_status_map,
    list_issues,
    reconcile_issues,
    reopen_by_fingerprint,
    resolve_by_fingerprint,
)
from ..summary import agents_table, build_summary
from ..wazuh_client import wazuh

# 整个仪表盘数据接口都需要登录（令牌可走 Authorization 头或 ?token= 查询参数）
router = APIRouter(prefix="/api", tags=["dashboard"], dependencies=[Depends(require_auth)])


@router.get("/overview")
async def overview(lang: str = Query("zh")):
    """总览大屏：实时聚合摘要 + 最新 AI 结论 + 风险趋势。"""
    lang = "en" if str(lang).lower() == "en" else "zh"
    summary = await build_summary()
    return {
        "summary": summary,
        "ai": latest_analysis(lang, summary),
        "ai_perf": latest_ai_perf(),
        "trend": await risk_trend(14),
    }


@router.get("/agents")
async def agents():
    """资产/设备列表。"""
    rows = agents_table(await wazuh.agents())
    return {"items": rows, "total": len(rows)}


@router.get("/agent-aliases")
async def agent_aliases():
    """终端显示别名映射 {注册名: 别名}。"""
    return {"items": get_aliases()}


@router.post("/agents/rename")
async def agents_rename(payload: dict = Body(...)):
    """设置/清除终端显示别名，不修改 Wazuh 注册名。"""
    name = (payload.get("name") or "").strip()
    alias = (payload.get("alias") or "").strip()
    if not name:
        return {"ok": False, "error": "missing name"}
    set_alias(name, alias)
    return {"ok": True, "name": name, "alias": alias}


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """管理员确认后清理 Wazuh 旧 Agent 记录。"""
    return await wazuh.delete_agent(agent_id)


@router.get("/alerts/summary")
async def alerts_summary():
    """安全态势：告警分布（来自实时聚合）。"""
    s = await build_summary()
    return s.get("alerts", {})


@router.get("/compliance")
async def compliance():
    """合规与漏洞：各机 CIS 评分。"""
    s = await build_summary()
    return {"endpoints": s.get("compliance", {}), "tags": s.get("compliance_tags", {})}


# ---------------------------------------------------------------- 漏洞与补丁
@router.get("/vulnerabilities")
async def vulnerabilities(limit: int = Query(200, ge=1, le=2000)):
    """漏洞与补丁：总览聚合 + 明细列表（来自 Wazuh 漏洞检测）。"""
    overview = await wazuh.vulnerabilities_overview()
    items = await wazuh.vulnerabilities_list(limit)
    return {"overview": overview, "items": items}


# ---------------------------------------------------------------- 资产清点
@router.get("/assets/ports")
async def assets_ports():
    """资产清点：跨设备开放端口汇总（标注高风险端口）。"""
    return await wazuh.open_ports_overview(await wazuh.agents())


@router.get("/assets/software")
async def assets_software():
    """资产清点：跨设备已装软件汇总。"""
    return await wazuh.software_overview(await wazuh.agents())


# ---------------------------------------------------------------- 安全告警（明细 / FIM / 自动响应）
@router.get("/alerts/list")
async def alerts_list(
    limit: int = Query(200, ge=1, le=1000),
    min_level: int = Query(0, ge=0, le=16),
    group: Optional[str] = None,
    agent: Optional[str] = None,
    q: Optional[str] = None,
    exclude_fim_low: bool = Query(False),
    aggregate: bool = Query(True),
):
    """告警明细下钻：按等级 / 分组 / 设备 / 关键词过滤。"""
    rows = await wazuh.alerts_list(size=limit, min_level=min_level, group=group, agent=agent, q=q, exclude_fim_low=exclude_fim_low)
    smap = issue_status_map()
    for row in rows:
        target = alert_issue_target(row)
        row["issue_target"] = target
        fp = fingerprint("alert", row.get("agent"), row.get("rule_id"), target)
        row["fingerprint"] = fp
        info = smap.get(fp)
        row["issue_status"] = info["status"] if info else "none"
        row["resolved_at"] = info["resolved_at"] if info else None
    total = len(rows)
    if aggregate:
        rows = _aggregate_alert_rows(rows)
    return {"items": rows, "total": len(rows), "raw_total": total}


@router.get("/issues")
async def issues(status: Optional[str] = Query(None), limit: int = Query(500, ge=1, le=2000)):
    """高危问题列表：status=open/resolved。"""
    return {"items": list_issues(status=status, limit=limit)}


@router.post("/issues/reconcile")
async def issues_reconcile():
    """手动触发一次问题生命周期对账。"""
    return await reconcile_issues()


@router.post("/issues/resolve")
async def issues_resolve(payload: dict = Body(...)):
    """人工把某条告警标记为已处置。"""
    fp = (payload.get("fingerprint") or "").strip()
    if not fp:
        return {"ok": False, "error": "missing fingerprint"}
    item = resolve_by_fingerprint(
        fp,
        agent=payload.get("agent"),
        rule_id=payload.get("rule_id"),
        target=payload.get("file") or payload.get("target"),
        description=payload.get("description"),
        level=int(payload.get("level") or 0),
        note=payload.get("note"),
    )
    return {"ok": True, "item": item}


@router.post("/issues/reopen")
async def issues_reopen(payload: dict = Body(...)):
    """把已修复问题重新打开。"""
    fp = (payload.get("fingerprint") or "").strip()
    if not fp:
        return {"ok": False, "error": "missing fingerprint"}
    item = reopen_by_fingerprint(fp, note=payload.get("note"))
    return {"ok": bool(item), "item": item}


@router.get("/fim/events")
async def fim_events(limit: int = Query(200, ge=1, le=1000)):
    """文件完整性(FIM)变更明细。"""
    rows = await wazuh.fim_events(limit)
    return {"items": rows, "total": len(rows)}


@router.get("/active-response")
async def active_response(limit: int = Query(100, ge=1, le=500)):
    """自动响应(Active Response)记录。"""
    rows = await wazuh.active_responses(limit)
    return {"items": rows, "total": len(rows)}


def _alert_group_key(row: dict) -> tuple:
    target = row.get("issue_target") or alert_issue_target(row)
    return (row.get("agent") or "", str(row.get("rule_id") or ""), str(target)[:180])


def _aggregate_alert_rows(rows: list[dict]) -> list[dict]:
    """同设备、同规则、同目标在列表中合并展示，详情仍保留代表告警。"""
    buckets: dict[tuple, dict] = {}
    for row in rows:
        key = _alert_group_key(row)
        cur = buckets.get(key)
        tracking = row.get("trojan_tracking") if isinstance(row.get("trojan_tracking"), dict) else None
        row_active_tracking = bool(tracking and tracking.get("pinned") and tracking.get("status") != "cleared" and row.get("issue_status") != "resolved")
        if cur is None:
            new = dict(row)
            new["occurrence_count"] = 1
            new["first_seen"] = row.get("time")
            new["last_seen"] = row.get("time")
            new["sample_times"] = [row.get("time")] if row.get("time") else []
            new["_aggregate_has_active_tracking"] = row_active_tracking
            new["_aggregate_has_open"] = row.get("issue_status") in ("open", "none")
            buckets[key] = new
            continue
        cur["occurrence_count"] = int(cur.get("occurrence_count") or 1) + 1
        cur["_aggregate_has_active_tracking"] = bool(cur.get("_aggregate_has_active_tracking")) or row_active_tracking
        cur["_aggregate_has_open"] = bool(cur.get("_aggregate_has_open")) or row.get("issue_status") in ("open", "none")
        ts = row.get("time")
        if ts:
            cur["sample_times"] = (cur.get("sample_times") or [])[:8] + [ts]
            if not cur.get("first_seen") or ts < cur["first_seen"]:
                cur["first_seen"] = ts
            if not cur.get("last_seen") or ts > cur["last_seen"]:
                cur["last_seen"] = ts
                for field in ("time", "raw_log", "description", "level", "groups", "mitre", "trojan_tracking", "trojan_event"):
                    if row.get(field) not in (None, "", [], {}):
                        cur[field] = row.get(field)
        if row_active_tracking:
            for field in ("time", "raw_log", "description", "level", "groups", "mitre", "trojan_tracking", "trojan_event", "fingerprint"):
                if row.get(field) not in (None, "", [], {}):
                    cur[field] = row.get(field)
            cur["issue_status"] = "open"
            cur["resolved_at"] = None
        elif cur.get("_aggregate_has_open") and cur.get("issue_status") == "resolved":
            cur["issue_status"] = "open"
            cur["resolved_at"] = None
        cur["level"] = max(int(cur.get("level") or 0), int(row.get("level") or 0))
    for row in buckets.values():
        row.pop("_aggregate_has_active_tracking", None)
        row.pop("_aggregate_has_open", None)
    return sorted(buckets.values(), key=lambda x: (int(x.get("level") or 0), x.get("last_seen") or x.get("time") or ""), reverse=True)


# ---------------------------------------------------------------- 单台设备详情（点击席位进入）
@router.get("/agent/{agent_id}")
async def agent_detail(agent_id: str):
    """设备详情：系统信息 + 防火墙 + 端口 + 漏洞 + 已装软件 + 文件变更日志。"""
    info = await wazuh.agent_info(agent_id)
    name = info.get("name") or agent_id
    hw, os_, packages, ports, vuln_ov, vuln_items, fim, firewall = await asyncio.gather(
        wazuh.agent_hardware(agent_id),
        wazuh.agent_os(agent_id),
        wazuh.agent_packages(agent_id),
        wazuh.agent_ports(agent_id),
        wazuh.vulnerabilities_overview(agent=name),
        wazuh.vulnerabilities_list(size=500, agent=name),
        wazuh.fim_events(size=300, agent=name, window="now-30d"),
        wazuh.agent_firewall(name),
        return_exceptions=True,
    )

    def ok(x, default):
        return x if not isinstance(x, Exception) else default

    vuln = ok(vuln_ov, {})
    vuln["items"] = ok(vuln_items, [])

    return {
        "info": info,
        "hardware": ok(hw, {}),
        "os": ok(os_, {}),
        "firewall": ok(firewall, None),
        "ports": ok(ports, []),
        "vulnerabilities": vuln,
        "software": ok(packages, []),
        "fim": ok(fim, []),
    }


async def _tcp_check(host: str, port: int, timeout: float = 2.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"ok": True, "message": f"{host}:{port} 可连通", "message_key": "tcp_ok", "params": {"host": host, "port": port}}
    except Exception as e:
        return {"ok": False, "message": f"{host}:{port} 不通：{e.__class__.__name__}", "message_key": "tcp_failed", "params": {"host": host, "port": port, "error": e.__class__.__name__}}


@router.get("/agent/{agent_id}/self-check")
async def agent_self_check(agent_id: str):
    """在服务端汇总该 Agent 的注册、心跳、Manager 连通性，作为页面版自检结果。"""
    info = await wazuh.agent_info(agent_id)
    manager_host = settings.wazuh_api_url.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
    checks = [
        {
            "key": "registered",
            "label": "Wazuh 注册状态",
            "label_key": "agent_registered",
            "ok": bool(info.get("id")),
            "message": f"已注册：{info.get('name') or agent_id}" if info.get("id") else "未在 Wazuh API 查到该 Agent",
            "message_key": "registered_ok" if info.get("id") else "registered_missing",
            "params": {"name": info.get("name") or agent_id},
        },
        {
            "key": "running",
            "label": "Agent 在线状态",
            "label_key": "agent_running",
            "ok": info.get("status") == "active",
            "message": f"当前状态：{info.get('status') or '未知'}",
            "message_key": "agent_status",
            "params": {"status": info.get("status") or "unknown"},
        },
        {
            "key": "manager",
            "label": "Manager 地址",
            "label_key": "manager_address",
            "ok": bool(manager_host),
            "message": manager_host or "未配置 Manager 地址",
            "message_key": "manager_address_value" if manager_host else "manager_missing",
            "params": {"host": manager_host},
        },
        {
            "key": "heartbeat",
            "label": "最近心跳",
            "label_key": "last_heartbeat",
            "ok": bool(info.get("lastKeepAlive")),
            "message": info.get("lastKeepAlive") or "未读取到心跳时间",
            "message_key": "heartbeat_value" if info.get("lastKeepAlive") else "heartbeat_missing",
            "params": {"time": info.get("lastKeepAlive") or ""},
        },
    ]
    port_checks = await asyncio.gather(_tcp_check(manager_host, 1514), _tcp_check(manager_host, 1515), return_exceptions=True)
    for port, result in zip((1514, 1515), port_checks):
        if isinstance(result, Exception):
            checks.append({"key": f"port_{port}", "label": f"{port} 连通性", "label_key": "port_connectivity", "ok": False, "message": str(result), "message_key": "check_failed", "params": {"port": port, "error": str(result)}})
        else:
            checks.append({"key": f"port_{port}", "label": f"{port} 连通性", "label_key": "port_connectivity", **result})
    return {"agent": info, "manager": manager_host, "checks": checks}


@router.get("/system/health")
async def system_health():
    """系统状态卡片：Web/BFF/DB/Wazuh API/Indexer/GuizangAI 的实时健康摘要。"""
    checks: list[dict] = [{"key": "web", "label": "Web", "label_key": "web", "ok": True, "message": "前端入口已响应", "message_key": "web_ok"}]
    try:
        with SessionLocal() as s:
            s.execute(text("SELECT 1"))
        checks.append({"key": "db", "label": "DB", "label_key": "db", "ok": True, "message": "数据库可查询", "message_key": "db_ok"})
    except Exception as e:
        checks.append({"key": "db", "label": "DB", "label_key": "db", "ok": False, "message": str(e), "message_key": "check_failed", "params": {"error": str(e)}})
    try:
        info = await wazuh.manager_info()
        checks.append({"key": "wazuh_api", "label": "Wazuh API", "label_key": "wazuh_api", "ok": True, "message": info.get("name") or "API 可登录", "message_key": "wazuh_api_ok", "params": {"name": info.get("name") or ""}})
    except Exception as e:
        checks.append({"key": "wazuh_api", "label": "Wazuh API", "label_key": "wazuh_api", "ok": False, "message": str(e), "message_key": "check_failed", "params": {"error": str(e)}})
    try:
        health = await wazuh.indexer_health()
        status = str(health.get("status") or "").lower()
        checks.append({"key": "indexer", "label": "Indexer", "label_key": "indexer", "ok": status in ("green", "yellow"), "message": status or "未知", "message_key": "indexer_status", "params": {"status": status or "unknown"}})
    except Exception as e:
        checks.append({"key": "indexer", "label": "Indexer", "label_key": "indexer", "ok": False, "message": str(e), "message_key": "check_failed", "params": {"error": str(e)}})
    perf = latest_ai_perf()
    latest = perf.get("latest") or {}
    checks.append({
        "key": "guizangai",
        "label": "GuizangAI",
        "label_key": "guizangai",
        "ok": bool(guizang_ai.enabled) and not latest.get("last_error"),
        "message": "已连接" if guizang_ai.enabled else "Mock 模式",
        "message_key": "guizangai_connected" if guizang_ai.enabled else "guizangai_mock",
        "detail": latest.get("last_error") or "",
    })
    ok = all(item.get("ok") for item in checks if item.get("key") != "guizangai") and bool(checks)
    return {"ok": ok, "checks": checks}


@router.get("/ai/latest")
async def ai_latest(lang: str = Query("zh")):
    """最新 AI 预设分析结论（仪表盘卡片读这里，秒开）。"""
    lang = "en" if str(lang).lower() == "en" else "zh"
    summary = await build_summary()
    return latest_analysis(lang, summary)


@router.get("/ai/status")
async def ai_status():
    perf = latest_ai_perf()
    latest = dict(perf.get("latest") or {})
    tokens_per_second = latest.get("tokens_per_second") or perf.get("avg_tokens_per_second")
    if tokens_per_second is not None and latest.get("tokens_per_second") is None:
        latest["tokens_per_second"] = tokens_per_second
    return {
        "connected": guizang_ai.enabled,
        "mode": "GuizangAI" if guizang_ai.enabled else "Mock",
        "latest": latest,
        "latest_task": latest.get("task"),
        "latest_seconds": latest.get("total_duration_seconds"),
        "tokens_per_second": tokens_per_second,
        "avg_tokens_per_second": perf.get("avg_tokens_per_second"),
        "total_eval_count": perf.get("total_eval_count"),
        "recent_snapshot_count": perf.get("recent_snapshot_count"),
        "recent_error_count": perf.get("recent_error_count"),
        "recent_cached_count": perf.get("recent_cached_count"),
        "last_error": latest.get("last_error") or "",
        "running": perf.get("running"),
        "current_task": perf.get("current_task"),
        "running_seconds": perf.get("running_seconds"),
    }


@router.post("/ai/run")
async def ai_run():
    """手动触发一轮分析（调试用；正常由调度器定时执行）。"""
    return await run_analysis()


@router.post("/ai/advice")
async def ai_advice(payload: dict = Body(...)):
    """针对单条漏洞 / 告警，按需生成 GuizangAI 处置建议。

    body: { "kind": "vuln"|"alert", "context": {...}, "lang": "zh"|"en" }
    """
    kind = str(payload.get("kind") or "alert")
    context = payload.get("context") or {}
    lang = "en" if str(payload.get("lang")).lower() == "en" else "zh"
    debug = bool(payload.get("debug"))
    if not isinstance(context, dict):
        context = {}
    result = await guizang_ai.advise(kind, context, lang, debug=debug)
    if debug and isinstance(result.get("_debug"), dict):
        try:
            if kind == "vuln":
                result["_debug"]["source_log"] = await wazuh.raw_vuln_log(context.get("agent"), context.get("cve"))
            else:
                result["_debug"]["source_log"] = await wazuh.raw_alert_log(
                    context.get("agent"), context.get("description"), context.get("time")
                )
        except Exception as e:
            result["_debug"]["source_log"] = {"_error": str(e)}
    record_runtime_perf(f"advice_{kind}", result.get("_perf") or {}, result.get("_source", "guizangai"), result.get("_error") or "")
    return result


@router.post("/ai/advice/stream")
async def ai_advice_stream(payload: dict = Body(...)):
    """流式生成 AI 处置建议：SSE delta + final。"""
    kind = str(payload.get("kind") or "alert")
    context = payload.get("context") or {}
    lang = "en" if str(payload.get("lang")).lower() == "en" else "zh"
    debug = bool(payload.get("debug"))
    if not isinstance(context, dict):
        context = {}

    async def events():
        final_result: dict | None = None
        async for event in guizang_ai.advise_stream(kind, context, lang, debug=debug):
            if event.get("type") == "final":
                final_result = event.get("result") or {}
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        if final_result is not None:
            record_runtime_perf(f"advice_{kind}", final_result.get("_perf") or {}, final_result.get("_source", "guizangai"), final_result.get("_error") or "")

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/ai/alert-description")
async def ai_alert_description(payload: dict = Body(...)):
    """按需美化单条告警描述，避免列表批量刷新时频繁调用模型。"""
    context = payload.get("context") or {}
    lang = "en" if str(payload.get("lang")).lower() == "en" else "zh"
    if not isinstance(context, dict):
        context = {}
    result = await guizang_ai.polish_alert_description(context, lang)
    record_runtime_perf("alert_description", result.get("_perf") or {}, result.get("_source", "guizangai"), result.get("_error") or "")
    return result


def _extract_affected_files(src: dict | None) -> list[str]:
    files: list[str] = []

    def add(value: object) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text and text not in files:
                files.append(text)

    src = src or {}
    add((src.get("syscheck") or {}).get("path") if isinstance(src.get("syscheck"), dict) else None)
    data = src.get("data") if isinstance(src.get("data"), dict) else {}
    audit = data.get("audit") if isinstance(data.get("audit"), dict) else {}
    af = audit.get("file") if isinstance(audit.get("file"), dict) else {}
    add(af.get("name"))
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    ev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    for key in ("targetFilename", "image", "objectName", "processPath", "targetObject"):
        add(ev.get(key))
    for key in ("file", "path", "target_file"):
        add(data.get(key))
    return files


def _parse_alert_factual(src: dict | None, agent: str, description: str, ts: str | None) -> dict:
    src = src or {}
    rule = src.get("rule") if isinstance(src.get("rule"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    full_log = src.get("full_log") if isinstance(src.get("full_log"), str) else None
    factual = {
        "time": src.get("timestamp") or ts,
        "agent": (src.get("agent") or {}).get("name") if isinstance(src.get("agent"), dict) else agent,
        "level": rule.get("level"),
        "description": rule.get("description") or description,
        "rule_id": rule.get("id"),
        "groups": rule.get("groups") or [],
        "mitre": mitre.get("technique") or [],
        "location": src.get("location"),
        "decoder": (src.get("decoder") or {}).get("name") if isinstance(src.get("decoder"), dict) else None,
        "full_log": full_log[:1500] if full_log else None,
        "affected_files": _extract_affected_files(src),
        "found": bool(src),
    }
    factual["trigger_explain"] = _build_trigger_explain(factual, src)
    return factual


def _build_trigger_explain(factual: dict, src: dict | None) -> dict:
    src = src or {}
    level = int(factual.get("level") or 0)
    groups = factual.get("groups") or []
    files = factual.get("affected_files") or []
    data = src.get("data") if isinstance(src.get("data"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    ev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    reasons: list[str] = []
    reason_items: list[dict] = []
    if factual.get("rule_id"):
        text_value = f"命中 Wazuh 规则 {factual.get('rule_id')}：{factual.get('description') or '无描述'}"
        reasons.append(text_value)
        reason_items.append({"key": "trigger_rule", "text": text_value, "params": {"rule_id": factual.get("rule_id"), "description": factual.get("description") or ""}})
    if level >= 15:
        reasons.append("规则等级 ≥15，按严重告警处理。")
        reason_items.append({"key": "trigger_level_critical", "text": "规则等级 ≥15，按严重告警处理。", "params": {"level": level}})
    elif level >= 12:
        reasons.append("规则等级 ≥12，按高危告警处理。")
        reason_items.append({"key": "trigger_level_high", "text": "规则等级 ≥12，按高危告警处理。", "params": {"level": level}})
    elif level >= 7:
        reasons.append("规则等级 ≥7，按中危及以上安全告警展示。")
        reason_items.append({"key": "trigger_level_medium", "text": "规则等级 ≥7，按中危及以上安全告警展示。", "params": {"level": level}})
    if groups:
        value = "、".join(str(x) for x in groups[:5])
        reasons.append("规则分类包含：" + value)
        reason_items.append({"key": "trigger_groups", "text": "规则分类包含：" + value, "params": {"groups": value}})
    if factual.get("mitre"):
        value = "、".join(str(x) for x in factual.get("mitre")[:5])
        reasons.append("关联 MITRE 技术：" + value)
        reason_items.append({"key": "trigger_mitre", "text": "关联 MITRE 技术：" + value, "params": {"mitre": value}})
    if files:
        value = "、".join(files[:3])
        reasons.append("原始日志包含受影响文件/进程路径：" + value)
        reason_items.append({"key": "trigger_files", "text": "原始日志包含受影响文件/进程路径：" + value, "params": {"files": value}})
    for key in ("targetFilename", "image", "processPath", "commandLine", "parentImage"):
        if ev.get(key):
            text_value = f"Windows 事件字段 {key}={ev.get(key)}"
            reasons.append(text_value)
            reason_items.append({"key": "trigger_win_field", "text": text_value, "params": {"field": key, "value": ev.get(key)}})
            break
    if data.get("srcip"):
        text_value = f"来源 IP：{data.get('srcip')}"
        reasons.append(text_value)
        reason_items.append({"key": "trigger_src_ip", "text": text_value, "params": {"ip": data.get("srcip")}})
    highlighted = level >= 12 or any(str(g).lower() in {"sysmon", "windows", "syscheck", "trojan"} for g in groups)
    return {
        "summary": "；".join(reasons[:3]) if reasons else "未在原始日志中解析到完整规则字段，建议查看原始日志。",
        "reasons": reasons,
        "reason_items": reason_items,
        "highlighted": highlighted,
        "highlight_reason": "高危等级或命中重点安全规则，因此在列表中优先展示/标红。" if highlighted else "未达到高危标红条件。",
        "highlight_reason_key": "trigger_highlighted" if highlighted else "trigger_not_highlighted",
        "summary_key": "trigger_summary",
    }


@router.get("/alerts/detail")
async def alert_detail(
    agent: str = Query(...),
    description: str = Query(...),
    ts: Optional[str] = Query(None),
    lang: str = "zh",
    fingerprint: Optional[str] = Query(None),
):
    """单条告警详情：事实字段 + GuizangAI 详情 + 原始日志 + 问题生命周期。"""
    lang = "en" if str(lang).lower() == "en" else "zh"
    try:
        raw = await wazuh.raw_alert_log(agent, description, ts)
    except Exception:
        raw = None
    factual = _parse_alert_factual(raw, agent, description, ts)
    context = {
        "description": factual["description"],
        "level": factual["level"],
        "groups": factual["groups"],
        "mitre": factual["mitre"],
        "agent": factual["agent"],
        "time": factual["time"],
        "affected_files": factual["affected_files"],
        "raw_log": factual["full_log"],
    }
    ai = await guizang_ai.polish_alert_description(context, lang)
    issue = get_issue_by_fingerprint(fingerprint) if fingerprint else None
    return {"factual": factual, "ai": ai, "raw": raw, "issue": issue}


@router.get("/trend")
async def trend(days: int = Query(7, ge=1, le=90), interval: str = Query("day", pattern="^(hour|day)$")):
    return {"items": await risk_trend(days, interval)}


@router.get("/export/agents.csv")
async def export_agents_csv():
    """数据导出示例：设备清单 CSV（在客户侧生成，不出网）。"""
    rows = agents_table(await wazuh.agents())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "id", "name", "ip", "status", "os", "platform", "version",
        "last_keep_alive", "registered_at", "duplicate_of", "duplicate_note",
    ])
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=agents.csv"},
    )
