"""高危安全问题的生命周期对账：把一次性告警/漏洞归并成有状态的「问题」。

- 高危告警(level≥issue_min_level) → kind="alert" 问题；受影响文件作为清除判定依据。
- 严重/高危漏洞(Critical/High)     → kind="vuln"  问题；CVE 不再被检出即判定清除。
- 清除信号：FIM 文件删除事件 / CVE 消失；并把自动响应动作记入时间轴。

对账由调度器周期调用 reconcile_issues()，结果落 PostgreSQL（SecurityIssue 表）。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re

from .config import settings
from .db import SecurityIssue, SessionLocal
from .wazuh_client import wazuh

log = logging.getLogger("issues")

_TL_CAP = 60  # 单条问题时间轴最多保留多少条，防止无限增长


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_ts(s: str | None) -> dt.datetime:
    """把 Wazuh 的 ISO 时间戳解析成带时区的 datetime；失败回退当前时间。"""
    if not s:
        return _now()
    try:
        t = s.strip().replace("Z", "+00:00")
        t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)  # +0000 -> +00:00
        d = dt.datetime.fromisoformat(t)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return _now()


def fingerprint(kind: str, agent: str | None, key: str | None, target: str | None = "") -> str:
    """问题指纹：同一(类型, 设备, 规则/CVE, 受影响目标)视为同一个问题。"""
    raw = f"{kind}|{agent or ''}|{key or ''}|{target or ''}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def alert_issue_target(row: dict) -> str:
    """告警问题目标：木马追踪必须按 tracking_id 隔离，避免旧处置污染新事件。"""
    tracking = row.get("trojan_tracking") if isinstance(row.get("trojan_tracking"), dict) else {}
    event = row.get("trojan_event") if isinstance(row.get("trojan_event"), dict) else {}
    text = f"{row.get('description') or ''}\n{row.get('raw_log') or ''}"
    tracking_id = (
        tracking.get("tracking_id")
        or event.get("tracking_id")
        or (re.search(r"\bid=([A-Za-z0-9._:-]+)", text).group(1) if re.search(r"\bid=([A-Za-z0-9._:-]+)", text) else "")
    )
    if tracking_id and str(tracking_id).startswith("guizang-attack-sim-"):
        return f"tracking:{tracking_id}"
    target = row.get("file") or row.get("target") or row.get("path")
    if target:
        return str(target)
    port = row.get("port") or row.get("dst_port") or row.get("src_port")
    if port:
        return f"port:{port}"
    return str(row.get("description") or "")[:180]


def _norm_path(p: str | None) -> str:
    """统一路径形态用于比较：小写 + 把任意连续的 \\ 或 / 折叠成单个 /。

    Sysmon 的 targetFilename 在索引里是双反斜杠(C:\\\\Users\\\\..)，FIM 删除路径是单反斜杠且小写，
    不归一化就匹配不上，导致文件删除后无法自动清除。
    """
    return re.sub(r"[\\/]+", "/", (p or "").strip().lower())


def _sev_from_level(level: int) -> str:
    if level >= 15:
        return "Critical"
    if level >= 12:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"


def _append_tl(iss: SecurityIssue, ts: dt.datetime, typ: str, detail: str) -> None:
    tl = list(iss.timeline or [])
    tl.append({"ts": ts.isoformat(), "type": typ, "detail": detail})
    iss.timeline = tl[-_TL_CAP:]


def _has_tl_type(iss: SecurityIssue, typ: str) -> bool:
    return any(item.get("type") == typ for item in (iss.timeline or []))


async def reconcile_issues() -> dict:
    """执行一轮对账。返回简单统计，便于日志/调试。"""
    win = settings.issue_window
    alerts = await wazuh.security_events(min_level=settings.issue_min_level, window=win)
    dels = await wazuh.fim_deletions(window=win)
    try:
        vulns = await wazuh.vulnerabilities_list(size=2000)
    except Exception:
        vulns = []
    try:
        ars = await wazuh.active_responses(size=300)
    except Exception:
        ars = []

    stats = {"alerts": len(alerts), "deletions": len(dels), "vulns": len(vulns), "opened": 0, "resolved": 0, "reviewed": 0}

    with SessionLocal() as s:
        existing: dict[str, SecurityIssue] = {i.fingerprint: i for i in s.query(SecurityIssue).all()}

        # ---- 1) 高危告警 → 问题（按指纹归并；已清除的若再次出现则重新打开） ----
        for a in alerts:
            target = alert_issue_target(a)
            # 降噪：PowerShell 执行策略临时测试文件是系统正常行为，不纳入问题追踪
            if "__PSScriptPolicyTest_" in target:
                continue
            ts = _parse_ts(a.get("time"))
            agent = a.get("agent") or "-"
            rid = a.get("rule_id")
            fp = fingerprint("alert", agent, rid, target)
            iss = existing.get(fp)
            if iss is None:
                iss = SecurityIssue(
                    fingerprint=fp, kind="alert", agent=agent, rule_id=rid,
                    level=int(a.get("level") or 0), severity=_sev_from_level(int(a.get("level") or 0)),
                    description=a.get("description") or "", target=target or None,
                    groups=a.get("groups") or [], mitre=a.get("mitre") or [],
                    status="open", first_seen=ts, last_seen=ts, occurrences=1,
                    timeline=[{"ts": ts.isoformat(), "type": "detected", "detail": a.get("description") or "首次发现"}],
                )
                s.add(iss)
                existing[fp] = iss
                stats["opened"] += 1
            else:
                if iss.status == "resolved":
                    # 仅当出现「晚于清除时间」的新发生才重开；旧的历史告警(早于清除时间)不重开，
                    # 以尊重「已处置/已清除」的判定（无论人工还是自动），避免反复弹回。
                    if iss.resolved_at and ts <= iss.resolved_at:
                        continue
                    iss.status = "open"
                    iss.resolved_at = None
                    iss.resolution = None
                    _append_tl(iss, ts, "reopened", "问题再次出现，已重新置顶追踪")
                    stats["opened"] += 1
                if ts > iss.last_seen:
                    iss.last_seen = ts
                iss.occurrences = (iss.occurrences or 0) + 1
                iss.level = max(iss.level or 0, int(a.get("level") or 0))
                if not iss.target and target:  # 回填受影响文件，便于后续按删除自动清除
                    iss.target = target

        # ---- 2) 漏洞 → 问题（仅 Critical/High）；记录当前仍存在的指纹用于清除判定 ----
        present_vuln_fps: set[str] = set()
        for v in vulns:
            sev = (v.get("severity") or "").lower()
            if sev not in ("critical", "high"):
                continue
            agent = v.get("agent") or "-"
            cve = v.get("cve") or ""
            if not cve:
                continue
            fp = fingerprint("vuln", agent, cve, v.get("package") or "")
            present_vuln_fps.add(fp)
            ts = _parse_ts(v.get("detected_at"))
            iss = existing.get(fp)
            if iss is None:
                desc = f"{v.get('package') or '组件'} 存在 {cve}（{v.get('severity')}）"
                iss = SecurityIssue(
                    fingerprint=fp, kind="vuln", agent=agent, cve=cve,
                    level=15 if sev == "critical" else 13,
                    severity=v.get("severity"), description=desc,
                    target=v.get("package") or None, groups=["vulnerability"], mitre=[],
                    status="open", first_seen=ts, last_seen=ts, occurrences=1,
                    timeline=[{"ts": ts.isoformat(), "type": "detected", "detail": desc}],
                )
                s.add(iss)
                existing[fp] = iss
                stats["opened"] += 1
            elif iss.status == "resolved":
                iss.status = "open"
                iss.resolved_at = None
                iss.resolution = None
                _append_tl(iss, _now(), "reopened", "该漏洞再次被检出")
                stats["opened"] += 1

        # ---- 3) 清除判定 A：文件被删除 → 对应「文件类」开放问题转入已修复 ----
        for d in dels:
            agent = d.get("agent")
            path = (d.get("path") or "").strip()
            if not agent or not path:
                continue
            path_n = _norm_path(path)
            ts = _parse_ts(d.get("time"))
            for iss in existing.values():
                if iss.status != "open" or iss.kind != "alert" or iss.agent != agent:
                    continue
                tgt = _norm_path(iss.target)  # 归一化：大小写 + 反斜杠数量(Sysmon 双反斜杠 vs FIM 单反斜杠)
                if tgt and (tgt == path_n or tgt in path_n or path_n in tgt):
                    iss.status = "resolved"
                    iss.resolved_at = ts
                    iss.resolution = "file_removed"
                    _append_tl(iss, ts, "cleared", f"受影响文件已删除：{path}")
                    stats["resolved"] += 1

        # ---- 4) 清除判定 B：CVE 不再被检出 → 漏洞问题转入已修复 ----
        for fp, iss in existing.items():
            if iss.kind == "vuln" and iss.status == "open" and fp not in present_vuln_fps:
                ts = _now()
                iss.status = "resolved"
                iss.resolved_at = ts
                iss.resolution = "cve_cleared"
                _append_tl(iss, ts, "cleared", "该漏洞已不再被检出（已修复/打补丁）")
                stats["resolved"] += 1

        # ---- 5) 自动响应动作记入同设备开放问题的时间轴（按时间就近关联，去重） ----
        for ar in ars:
            agent = ar.get("agent")
            if not agent:
                continue
            ts = _parse_ts(ar.get("time"))
            note = f"自动响应：{ar.get('command') or ar.get('description') or '已执行处置'}"
            for iss in existing.values():
                if iss.status != "open" or iss.agent != agent:
                    continue
                if abs((ts - iss.last_seen).total_seconds()) > 3600:
                    continue
                if any(e.get("type") == "active_response" and e.get("ts") == ts.isoformat() for e in (iss.timeline or [])):
                    continue
                _append_tl(iss, ts, "active_response", note)

        # ---- 6) 人工处置后的自动复核：5/15/30 分钟无新同指纹事件则逐步确认稳定 ----
        now = _now()
        review_marks = [(5, "review_5m"), (15, "review_15m"), (30, "review_30m")]
        for iss in existing.values():
            if iss.status != "resolved" or not iss.resolved_at:
                continue
            if iss.resolution not in ("manual", "file_removed", "cve_cleared"):
                continue
            elapsed_min = (now - iss.resolved_at).total_seconds() / 60
            for minute, typ in review_marks:
                if elapsed_min >= minute and not _has_tl_type(iss, typ):
                    _append_tl(iss, now, typ, f"自动复核：处置后 {minute} 分钟内未发现同类复发")
                    stats["reviewed"] += 1

        s.commit()

    log.info("[issues] 对账完成 %s", stats)
    return stats


def _to_dict(i: SecurityIssue) -> dict:
    return {
        "id": i.id,
        "fingerprint": i.fingerprint,
        "kind": i.kind,
        "agent": i.agent,
        "rule_id": i.rule_id,
        "cve": i.cve,
        "level": i.level,
        "severity": i.severity,
        "description": i.description,
        "target": i.target,
        "groups": i.groups or [],
        "mitre": i.mitre or [],
        "status": i.status,
        "first_seen": i.first_seen.isoformat() if i.first_seen else None,
        "last_seen": i.last_seen.isoformat() if i.last_seen else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "resolution": i.resolution,
        "occurrences": i.occurrences,
        "timeline": i.timeline or [],
    }


def list_issues(status: str | None = None, limit: int = 500) -> list[dict]:
    with SessionLocal() as s:
        q = s.query(SecurityIssue)
        if status in ("open", "resolved"):
            q = q.filter(SecurityIssue.status == status)
        if status == "resolved":
            q = q.order_by(SecurityIssue.resolved_at.desc())
        else:
            q = q.order_by(SecurityIssue.level.desc(), SecurityIssue.last_seen.desc())
        return [_to_dict(i) for i in q.limit(limit).all()]


def issue_status_map() -> dict[str, dict]:
    """fingerprint → {status, resolved_at, id}，供告警明细标注「已修复/未修复」。"""
    out: dict[str, dict] = {}
    with SessionLocal() as s:
        for i in s.query(SecurityIssue).all():
            out[i.fingerprint] = {
                "status": i.status,
                "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
                "id": i.id,
            }
    return out


def get_issue_by_fingerprint(fp: str) -> dict | None:
    with SessionLocal() as s:
        i = s.query(SecurityIssue).filter(SecurityIssue.fingerprint == fp).first()
        return _to_dict(i) if i else None


def resolve_by_fingerprint(
    fp: str,
    *,
    agent: str | None = None,
    rule_id: str | None = None,
    target: str | None = None,
    description: str | None = None,
    level: int = 0,
    note: str | None = None,
) -> dict:
    """人工标记某条告警「已处置」。问题已存在则转入已修复；不存在则按行为类告警新建为已修复。

    用于无可删除文件目标的行为类告警（如可疑进程/编码 PowerShell），让用户能主动消除。
    """
    ts = _now()
    detail = note or "已人工确认处置"
    with SessionLocal() as s:
        iss = s.query(SecurityIssue).filter(SecurityIssue.fingerprint == fp).first()
        if iss is None:
            iss = SecurityIssue(
                fingerprint=fp, kind="alert", agent=agent, rule_id=rule_id,
                level=int(level or 0), severity=_sev_from_level(int(level or 0)),
                description=description or "", target=target or None,
                groups=[], mitre=[], status="resolved",
                first_seen=ts, last_seen=ts, occurrences=1,
                resolved_at=ts, resolution="manual",
                timeline=[
                    {"ts": ts.isoformat(), "type": "detected", "detail": description or "首次发现"},
                    {"ts": ts.isoformat(), "type": "cleared", "detail": detail},
                ],
            )
            s.add(iss)
        else:
            iss.status = "resolved"
            iss.resolved_at = ts
            iss.resolution = "manual"
            _append_tl(iss, ts, "cleared", detail)
        s.commit()
        return _to_dict(iss)


def reopen_by_fingerprint(fp: str, note: str | None = None) -> dict | None:
    """把「已修复」重新打开（误判处置时使用）。"""
    ts = _now()
    with SessionLocal() as s:
        iss = s.query(SecurityIssue).filter(SecurityIssue.fingerprint == fp).first()
        if iss is None:
            return None
        iss.status = "open"
        iss.resolved_at = None
        iss.resolution = None
        _append_tl(iss, ts, "reopened", note or "已人工重新打开追踪")
        s.commit()
        return _to_dict(iss)
