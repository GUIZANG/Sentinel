"""Wazuh 数据访问层：封装 Server API（55000）与 Indexer（9200）。

设计原则：尽量用聚合/汇总接口，只取回"统计数字"，绝不取回海量原始日志。
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
import time
from typing import Any

import httpx

from .config import settings


class WazuhClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._token_ts: float = 0.0
        self._token_ttl = 600  # Wazuh JWT 默认 15 分钟，这里保守 10 分钟刷新

    # ---------------------------------------------------------------- Server API
    async def _get_token(self) -> str:
        if self._token and (time.time() - self._token_ts) < self._token_ttl:
            return self._token
        url = f"{settings.wazuh_api_url}/security/user/authenticate"
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=20) as c:
            r = await c.post(url, auth=(settings.wazuh_api_user, settings.wazuh_api_password))
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self._token_ts = time.time()
        return self._token

    async def api(self, path: str, params: dict | None = None) -> dict[str, Any]:
        token = await self._get_token()
        url = f"{settings.wazuh_api_url}{path}"
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=30) as c:
            r = await c.get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
            if r.status_code == 401:
                # Manager 重启会让旧 token 失效，清掉缓存后重登一次。
                self._token = None
                token = await self._get_token()
                r = await c.get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
            r.raise_for_status()
            return r.json()

    async def api_delete(self, path: str, params: dict | None = None) -> dict[str, Any]:
        token = await self._get_token()
        url = f"{settings.wazuh_api_url}{path}"
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=30) as c:
            r = await c.delete(url, headers={"Authorization": f"Bearer {token}"}, params=params)
            if r.status_code == 401:
                self._token = None
                token = await self._get_token()
                r = await c.delete(url, headers={"Authorization": f"Bearer {token}"}, params=params)
            r.raise_for_status()
            return r.json()

    # ---------------------------------------------------------------- Indexer
    async def indexer_search(self, body: dict[str, Any], index: str | None = None) -> dict[str, Any]:
        idx = index or settings.alerts_index
        url = f"{settings.indexer_url}/{idx}/_search"
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=30) as c:
            r = await c.post(
                url,
                auth=(settings.indexer_user, settings.indexer_password),
                headers={"Content-Type": "application/json"},
                json=body,
            )
            r.raise_for_status()
            return r.json()

    async def indexer_health(self) -> dict[str, Any]:
        url = f"{settings.indexer_url}/_cluster/health"
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=10) as c:
            r = await c.get(url, auth=(settings.indexer_user, settings.indexer_password))
            r.raise_for_status()
            return r.json()

    async def fetch_alerts(self, size: int, window: str, fields: list[str] | None = None) -> list[dict]:
        """取回原始告警明细(整条 _source)。size 受 OpenSearch max_result_window(默认1万)限制。"""
        size = max(1, min(int(size), 10000))
        body: dict[str, Any] = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"timestamp": {"gte": window}}},
        }
        if fields:
            body["_source"] = fields
        data = await self.indexer_search(body)
        hits = data.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    async def alerts_trend(self, days: int = 14, interval: str = "day") -> list[dict[str, Any]]:
        """实时聚合告警趋势，口径与安全告警列表同源。"""
        days = max(1, min(int(days or 14), 90))
        hourly = interval == "hour"
        min_bound = "now-23h/h" if hourly else ("now/d" if days <= 1 else f"now-{days - 1}d/d")
        histogram: dict[str, Any] = {
            "field": "timestamp",
            "time_zone": settings.timezone,
            "min_doc_count": 0,
            "extended_bounds": {"min": min_bound, "max": "now/h" if hourly else "now/d"},
        }
        if hourly:
            histogram["fixed_interval"] = "1h"
        else:
            histogram["calendar_interval"] = "day"
        body: dict[str, Any] = {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": min_bound}}},
            "aggs": {
                "by_day": {
                    "date_histogram": histogram,
                    "aggs": {
                        "high": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                    },
                }
            },
        }
        data = await self.indexer_search(body)
        buckets = data.get("aggregations", {}).get("by_day", {}).get("buckets", [])
        rows: list[dict[str, Any]] = []
        for bucket in buckets:
            rows.append({
                "time": bucket.get("key_as_string"),
                "alerts_total": int(bucket.get("doc_count") or 0),
                "alerts_high": int((bucket.get("high") or {}).get("doc_count") or 0),
            })
        return rows

    async def delete_agent(self, agent_id: str) -> dict[str, Any]:
        return await self.api_delete("/agents", params={"agents_list": agent_id, "status": "all", "older_than": "0s"})

    # ---------------------------------------------------------------- 高层封装
    async def agents(self, select: str = "id,name,ip,status,os.platform,os.name,version,lastKeepAlive,dateAdd") -> list[dict]:
        data = await self.api("/agents", params={"select": select, "sort": "id", "limit": 500})
        return data.get("data", {}).get("affected_items", [])

    async def agents_status_summary(self) -> dict:
        data = await self.api("/agents/summary/status")
        return data.get("data", {})

    async def syscollector_total(self, agent_id: str, resource: str) -> int:
        try:
            data = await self.api(f"/syscollector/{agent_id}/{resource}", params={"limit": 1})
            return int(data.get("data", {}).get("total_affected_items", 0))
        except Exception:
            return 0

    async def sca(self, agent_id: str) -> dict | None:
        try:
            data = await self.api(f"/sca/{agent_id}")
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else None
        except Exception:
            return None

    async def manager_info(self) -> dict:
        data = await self.api("/manager/info")
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    # ---------------------------------------------------------------- 漏洞检测（Wazuh 4.8+ 存于 Indexer）
    async def vulnerabilities_overview(self, agent: str | None = None) -> dict[str, Any]:
        """漏洞总览：总数 + 按严重度 + Top CVE + 按设备 + Top 受影响软件。"""
        body: dict[str, Any] = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "top_cves": {
                    "terms": {"field": "vulnerability.id", "size": 10},
                    "aggs": {
                        "sample": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "vulnerability.id",
                                    "vulnerability.severity",
                                    "vulnerability.score.base",
                                    "vulnerability.description",
                                    "vulnerability.scanner.condition",
                                    "vulnerability.scanner.reference",
                                    "vulnerability.reference",
                                    "package.name",
                                    "package.version",
                                ],
                            }
                        }
                    },
                },
                "by_agent": {"terms": {"field": "agent.name", "size": 10}},
                "top_packages": {"terms": {"field": "package.name", "size": 10}},
            },
        }
        if agent:
            body["query"] = {"term": {"agent.name": agent}}
        try:
            data = await self.indexer_search(body, index=settings.vuln_index)
        except Exception:
            return {"total": 0, "by_severity": {}, "top_cves": {}, "top_cve_details": [], "by_agent": {}, "top_packages": {}}
        agg = data.get("aggregations", {})
        total = data.get("hits", {}).get("total", {})
        total_n = total.get("value", 0) if isinstance(total, dict) else int(total or 0)

        def _terms(name: str) -> dict[str, int]:
            return {b["key"]: b["doc_count"] for b in agg.get(name, {}).get("buckets", [])}

        return {
            "total": total_n,
            "by_severity": _terms("by_severity"),
            "top_cves": _terms("top_cves"),
            "top_cve_details": _top_cve_details(agg),
            "by_agent": _terms("by_agent"),
            "top_packages": _terms("top_packages"),
        }

    async def vulnerabilities_list(self, size: int = 200, agent: str | None = None) -> list[dict]:
        """漏洞明细表：设备 / CVE / 严重度 / 软件 / 版本 / CVSS 评分。"""
        size = max(1, min(int(size), 2000))
        body: dict[str, Any] = {
            "size": size,
            "sort": [{"vulnerability.score.base": {"order": "desc", "missing": "_last"}}],
            "_source": [
                "agent.name", "vulnerability.id", "vulnerability.severity",
                "vulnerability.score.base", "package.name", "package.version",
                "vulnerability.detected_at", "vulnerability.description",
                "vulnerability.scanner.condition", "vulnerability.scanner.reference",
                "vulnerability.reference",
            ],
        }
        if agent:
            body["query"] = {"term": {"agent.name": agent}}
        try:
            data = await self.indexer_search(body, index=settings.vuln_index)
        except Exception:
            return []
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            vuln = src.get("vulnerability", {}) or {}
            pkg = src.get("package", {}) or {}
            score = vuln.get("score", {}) or {}
            rows.append({
                "agent": (src.get("agent", {}) or {}).get("name"),
                "cve": vuln.get("id"),
                "severity": vuln.get("severity"),
                "score": score.get("base") if isinstance(score, dict) else None,
                "package": pkg.get("name"),
                "version": pkg.get("version"),
                "detected_at": vuln.get("detected_at"),
                "condition": (vuln.get("scanner", {}) or {}).get("condition"),
                "description": _shorten_vuln_description(vuln.get("description")),
                "reference": _vuln_reference(vuln),
            })
        return rows

    # ---------------------------------------------------------------- 资产清点（Syscollector，跨设备聚合）
    async def _syscollector(self, agent_id: str, resource: str, select: str, limit: int = 500) -> list[dict]:
        try:
            data = await self.api(
                f"/syscollector/{agent_id}/{resource}",
                params={"select": select, "limit": limit},
            )
            return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    async def open_ports_overview(self, agents: list[dict], max_agents: int = 100) -> dict[str, Any]:
        """跨设备汇总监听端口：哪些端口在多少台机器上开放，并标注高风险端口。"""
        targets = [a for a in agents if a.get("id") != "000"][:max_agents]
        results = await asyncio.gather(
            *[self._syscollector(a["id"], "ports", "local.port,protocol,process,state") for a in targets],
            return_exceptions=True,
        )
        agg: dict[str, dict] = {}
        for a, ports in zip(targets, results):
            if not isinstance(ports, list):
                continue
            seen: set = set()
            for p in ports:
                if (p.get("state") or "").lower() not in ("listening", "open", ""):
                    continue
                local = p.get("local", {}) or {}
                port = local.get("port")
                proto = p.get("protocol", "")
                if port is None:
                    continue
                key = f"{port}/{proto}"
                if key in seen:
                    continue
                seen.add(key)
                e = agg.setdefault(key, {"port": port, "protocol": proto, "process": p.get("process"), "agents": 0})
                e["agents"] += 1
        rows = sorted(agg.values(), key=lambda x: x["agents"], reverse=True)
        for r in rows:
            r["risky"] = RISKY_PORTS.get(int(r["port"]) if str(r["port"]).isdigit() else -1)
        return {"items": rows, "scanned_agents": len(targets)}

    async def software_overview(self, agents: list[dict], max_agents: int = 100) -> dict[str, Any]:
        """跨设备汇总已装软件：每个软件装在多少台机器上。"""
        targets = [a for a in agents if a.get("id") != "000"][:max_agents]
        results = await asyncio.gather(
            *[self._syscollector(a["id"], "packages", "name,version,vendor") for a in targets],
            return_exceptions=True,
        )
        agg: dict[str, dict] = {}
        for pkgs in results:
            if not isinstance(pkgs, list):
                continue
            seen: set = set()
            for p in pkgs:
                name = p.get("name")
                if not name or name in seen:
                    continue
                seen.add(name)
                e = agg.setdefault(name, {"name": name, "vendor": p.get("vendor"), "version": p.get("version"), "agents": 0})
                e["agents"] += 1
        rows = sorted(agg.values(), key=lambda x: x["agents"], reverse=True)
        return {"items": rows, "scanned_agents": len(targets)}

    # ---------------------------------------------------------------- 告警明细 / FIM / 自动响应（来自 Indexer）
    async def alerts_list(
        self,
        size: int = 200,
        min_level: int = 0,
        group: str | None = None,
        agent: str | None = None,
        q: str | None = None,
        exclude_baseline: bool = True,
        exclude_fim_low: bool = False,
    ) -> list[dict]:
        """告警明细下钻：可按最低等级 / 分组 / 设备 / 关键词过滤。"""
        size = max(1, min(int(size), 1000))
        must: list[dict] = [{"range": {"timestamp": {"gte": settings.summary_window}}}]
        must_not: list[dict] = []
        if min_level:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if group:
            must.append({"term": {"rule.groups": group}})
        elif exclude_baseline:
            must_not.append({"terms": {"rule.groups": ["sca", "rootcheck"]}})
        if exclude_fim_low:
            must_not.append({"bool": {"must": [
                {"terms": {"rule.groups": ["syscheck"]}},
                {"range": {"rule.level": {"lt": 12}}},
            ]}})
        if agent:
            must.append({"term": {"agent.name": agent}})
        if q:
            must.append({
                "bool": {
                    "should": [
                        {
                            "multi_match": {
                                "query": q,
                                "type": "phrase",
                                "fields": [
                                    "rule.description",
                                    "full_log",
                                    "previous_output",
                                    "previous_log",
                                    "agent.name",
                                    "rule.id",
                                    "location",
                                    "data.command",
                                ],
                            }
                        },
                        {
                            "simple_query_string": {
                                "query": q,
                                "fields": [
                                    "rule.description",
                                    "full_log",
                                    "previous_output",
                                    "previous_log",
                                    "agent.name",
                                    "rule.id",
                                    "location",
                                    "data.command",
                                ],
                                "default_operator": "and",
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            })
        bool_q: dict[str, Any] = {"must": must}
        if must_not:
            bool_q["must_not"] = must_not
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": [
                "timestamp",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.description",
                "rule.groups",
                "rule.mitre.technique",
                "data.srcip",
                "data.dstip",
                "data.srcport",
                "data.dstport",
                "data.src_port",
                "data.dst_port",
                "data.sport",
                "data.dport",
                "data.port",
                "data.protocol",
                "full_log",
                "previous_output",
                "previous_log",
                "location",
                "syscheck.port",
                "syscheck.protocol",
                "syscheck.path",
                "syscheck.event",
                "data.win.eventdata.targetFilename",
                "data.win.eventdata.image",
            ],
            "query": {"bool": bool_q},
        }
        data = await self.indexer_search(body)
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            rule = src.get("rule", {}) or {}
            alert_data = src.get("data", {}) or {}
            syscheck = src.get("syscheck", {}) or {}
            win = alert_data.get("win") if isinstance(alert_data.get("win"), dict) else {}
            ev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
            file_target = syscheck.get("path") or ev.get("targetFilename") or ev.get("image")
            mitre = (rule.get("mitre", {}) or {}).get("technique") if isinstance(rule.get("mitre"), dict) else None
            src_port = _first_value(alert_data, "srcport", "src_port", "sport")
            dst_port = _first_value(alert_data, "dstport", "dst_port", "dport")
            log_text = "\n".join(str(src.get(k) or "") for k in ("full_log", "previous_output", "previous_log"))
            listened_ports = _extract_listened_ports(log_text)
            primary_port = _primary_listened_port(listened_ports)
            port = dst_port or src_port or alert_data.get("port") or syscheck.get("port") or (primary_port or {}).get("port")
            protocol = alert_data.get("protocol") or syscheck.get("protocol") or (primary_port or {}).get("protocol")
            description = rule.get("description")
            rows.append({
                "time": src.get("timestamp"),
                "agent": (src.get("agent", {}) or {}).get("name"),
                "rule_id": rule.get("id"),
                "level": rule.get("level"),
                "description": description,
                "groups": rule.get("groups"),
                "mitre": mitre,
                "src_ip": alert_data.get("srcip"),
                "dst_ip": alert_data.get("dstip"),
                "src_port": src_port,
                "dst_port": dst_port,
                "port": port,
                "protocol": protocol,
                "listen_ip": (primary_port or {}).get("address"),
                "process": (primary_port or {}).get("process"),
                "file": file_target,
                "listened_ports": listened_ports[:20],
                "raw_log": log_text[:2000],
                "_description_base": description,
            })
        _attach_changed_listened_ports(rows)
        _attach_trojan_tracking(rows)
        await self._enrich_alert_port_processes(rows)
        await self._mark_cleared_trojan_tracking(rows)
        return _sort_tracked_alerts(rows)

    async def _enrich_alert_port_processes(self, rows: list[dict[str, Any]]) -> None:
        """端口变化规则的 full_log 不一定带 PID/进程；用 syscollector 当前端口清单补齐。"""
        target_agents = {
            row.get("agent")
            for row in rows
            if row.get("agent") and _is_listened_ports_alert(row)
        }
        if not target_agents:
            return
        agents = await self.agents()
        id_by_name = {
            a.get("name"): a.get("id")
            for a in agents
            if a.get("name") in target_agents and a.get("id")
        }
        if not id_by_name:
            return
        port_results = await asyncio.gather(
            *[self.agent_ports(agent_id) for agent_id in id_by_name.values()],
            return_exceptions=True,
        )
        ports_by_agent: dict[str, list[dict[str, Any]]] = {}
        for name, result in zip(id_by_name.keys(), port_results):
            ports_by_agent[name] = result if isinstance(result, list) else []

        for row in rows:
            agent_ports = ports_by_agent.get(row.get("agent") or "") or []
            if not agent_ports or not _is_listened_ports_alert(row):
                continue
            _enrich_port_items(row.get("listened_ports") or [], agent_ports)
            _enrich_port_items(row.get("changed_ports") or [], agent_ports)
            if not row.get("process"):
                matched = _find_matching_agent_port(row, agent_ports)
                if matched:
                    row["process"] = matched.get("process")
                    row["protocol"] = row.get("protocol") or matched.get("protocol")
                    row["changed_ports"] = _apply_row_process_to_changed(row)

    async def _mark_cleared_trojan_tracking(self, rows: list[dict[str, Any]]) -> None:
        """清除后取消追踪置顶：若追踪端口已不在当前端口清单，视为已清除。"""
        tracked = [row for row in rows if row.get("trojan_tracking")]
        if not tracked:
            return
        target_agents = {row.get("agent") for row in tracked if row.get("agent")}
        agents = await self.agents()
        id_by_name = {
            a.get("name"): a.get("id")
            for a in agents
            if a.get("name") in target_agents and a.get("id")
        }
        if not id_by_name:
            return
        port_results = await asyncio.gather(
            *[self.agent_ports(agent_id) for agent_id in id_by_name.values()],
            return_exceptions=True,
        )
        current_ports_by_agent: dict[str, set[str]] = {}
        for name, result in zip(id_by_name.keys(), port_results):
            ports = result if isinstance(result, list) else []
            current_ports_by_agent[name] = {
                str(port.get("port") or "")
                for port in ports
                if port.get("port") not in (None, "")
            }

        cleared_ids: set[str] = set()
        for row in tracked:
            tracking = row.get("trojan_tracking") or {}
            if tracking.get("status") == "cleared":
                if tracking.get("tracking_id"):
                    cleared_ids.add(str(tracking["tracking_id"]))
                continue
            # 端口清单由 Wazuh 周期采集，新开的监听端口可能尚未同步。
            # 不能因为“当前清单里暂时没有”就立刻判定清除，否则运行中的模拟木马会被误降级。
            if not _tracking_event_is_stale(str(tracking.get("last_seen") or ""), minutes=10):
                continue
            ports = [str(port) for port in (tracking.get("ports") or []) if str(port)]
            if not ports:
                continue
            current_ports = current_ports_by_agent.get(row.get("agent") or "")
            if current_ports is None:
                continue
            if all(port not in current_ports for port in ports):
                if tracking.get("tracking_id"):
                    cleared_ids.add(str(tracking["tracking_id"]))

        for row in tracked:
            tracking = row.get("trojan_tracking") or {}
            if str(tracking.get("tracking_id") or "") not in cleared_ids:
                continue
            tracking["status"] = "cleared"
            tracking["pinned"] = False
            stages = list(tracking.get("stages") or [])
            if "cleared" not in stages:
                stages.append("cleared")
            tracking["stages"] = stages
            row["trojan_tracking"] = tracking

    async def fim_events(self, size: int = 200, agent: str | None = None, window: str | None = None) -> list[dict]:
        """文件完整性(FIM)变更明细：哪台机、哪个文件、增/改/删。"""
        size = max(1, min(int(size), 1000))
        must: list[dict] = [
            {"range": {"timestamp": {"gte": window or settings.summary_window}}},
            {"term": {"rule.groups": "syscheck"}},
        ]
        if agent:
            must.append({"term": {"agent.name": agent}})
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp", "agent.name", "syscheck.path", "syscheck.event", "rule.description"],
            "query": {"bool": {"must": must}},
        }
        data = await self.indexer_search(body)
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            sc = src.get("syscheck", {}) or {}
            rows.append({
                "time": src.get("timestamp"),
                "agent": (src.get("agent", {}) or {}).get("name"),
                "path": sc.get("path"),
                "event": sc.get("event"),
                "description": (src.get("rule", {}) or {}).get("description"),
            })
        return rows

    async def security_events(self, min_level: int = 12, window: str | None = None, size: int = 800) -> list[dict]:
        """取高危告警，供问题生命周期对账。"""
        size = max(1, min(int(size), 5000))
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "_source": [
                "timestamp", "agent.name", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre.technique", "syscheck.path", "syscheck.event",
                "data.win.eventdata.targetFilename", "data.win.eventdata.image",
                "full_log", "previous_output", "previous_log", "data.port", "data.srcport", "data.dstport",
            ],
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": window or settings.summary_window}}},
                {"range": {"rule.level": {"gte": min_level}}},
            ]}},
        }
        try:
            data = await self.indexer_search(body)
        except Exception:
            return []
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            rule = src.get("rule", {}) or {}
            sc = src.get("syscheck", {}) or {}
            alert_data = src.get("data", {}) or {}
            win = alert_data.get("win") if isinstance(alert_data.get("win"), dict) else {}
            ev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
            mitre = (rule.get("mitre", {}) or {}).get("technique") if isinstance(rule.get("mitre"), dict) else None
            log_text = "\n".join(str(src.get(k) or "") for k in ("full_log", "previous_output", "previous_log"))
            rows.append({
                "time": src.get("timestamp"),
                "agent": (src.get("agent", {}) or {}).get("name"),
                "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
                "level": rule.get("level"),
                "description": rule.get("description"),
                "groups": rule.get("groups") or [],
                "mitre": mitre or [],
                "file": sc.get("path") or ev.get("targetFilename") or ev.get("image"),
                "event": sc.get("event"),
                "raw_log": log_text[:2000],
                "port": alert_data.get("port") or alert_data.get("dstport") or alert_data.get("srcport"),
            })
        return rows

    async def fim_deletions(self, window: str | None = None, size: int = 800) -> list[dict]:
        """取文件删除 FIM 事件，作为问题自动清除信号。"""
        size = max(1, min(int(size), 5000))
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "_source": ["timestamp", "agent.name", "syscheck.path"],
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": window or settings.summary_window}}},
                {"term": {"rule.groups": "syscheck"}},
                {"term": {"syscheck.event": "deleted"}},
            ]}},
        }
        try:
            data = await self.indexer_search(body)
        except Exception:
            return []
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            rows.append({
                "time": src.get("timestamp"),
                "agent": (src.get("agent", {}) or {}).get("name"),
                "path": (src.get("syscheck", {}) or {}).get("path"),
            })
        return rows

    async def active_responses(self, size: int = 100) -> list[dict]:
        """自动响应(Active Response)记录：触发了哪些自动处置动作。"""
        size = max(1, min(int(size), 500))
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp", "agent.name", "rule.description", "data.command", "command"],
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "active_response"}},
                {"exists": {"field": "data.command"}},
                {"exists": {"field": "command"}},
            ], "minimum_should_match": 1, "must": [
                {"range": {"timestamp": {"gte": settings.summary_window}}},
            ]}},
        }
        try:
            data = await self.indexer_search(body)
        except Exception:
            return []
        rows = []
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            cmd = src.get("command") or (src.get("data", {}) or {}).get("command")
            rows.append({
                "time": src.get("timestamp"),
                "agent": (src.get("agent", {}) or {}).get("name"),
                "command": cmd,
                "description": (src.get("rule", {}) or {}).get("description"),
            })
        return rows

    async def raw_alert_log(self, agent: str | None = None, description: str | None = None, ts: str | None = None) -> dict | None:
        """取单条告警在 Indexer 中的原始 _source。"""
        must: list[dict] = []
        if agent:
            must.append({"term": {"agent.name": agent}})
        if description:
            must.append({"match_phrase": {"rule.description": description}})
        if not must:
            return None
        for extra in ([{"term": {"timestamp": ts}}] if ts else [], []):
            body = {
                "size": 1,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must + extra}},
            }
            try:
                data = await self.indexer_search(body)
            except Exception:
                return None
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_source")
        return None

    async def raw_vuln_log(self, agent: str | None = None, cve: str | None = None) -> dict | None:
        """取单条漏洞在 Indexer 中的原始 _source。"""
        must: list[dict] = []
        if agent:
            must.append({"term": {"agent.name": agent}})
        if cve:
            must.append({"term": {"vulnerability.id": cve}})
        if not must:
            return None
        body = {"size": 1, "query": {"bool": {"must": must}}}
        try:
            data = await self.indexer_search(body, index=settings.vuln_index)
        except Exception:
            return None
        hits = data.get("hits", {}).get("hits", [])
        return hits[0].get("_source") if hits else None

    # ---------------------------------------------------------------- 单台设备详情
    async def agent_info(self, agent_id: str) -> dict:
        data = await self.api("/agents", params={
            "agents_list": agent_id,
            "select": "id,name,ip,status,os.platform,os.name,os.version,version,lastKeepAlive,dateAdd,group,manager,node_name",
        })
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    async def agent_hardware(self, agent_id: str) -> dict:
        items = await self._syscollector(agent_id, "hardware", "cpu.name,cpu.cores,ram.total,board_serial", limit=1)
        return items[0] if items else {}

    async def agent_os(self, agent_id: str) -> dict:
        items = await self._syscollector(agent_id, "os", "os.name,os.version,architecture,hostname,sysname", limit=1)
        return items[0] if items else {}

    async def agent_packages(self, agent_id: str, limit: int = 2000) -> list[dict]:
        items = await self._syscollector(agent_id, "packages", "name,version,vendor,architecture", limit)
        return [
            {"name": p.get("name"), "version": p.get("version"), "vendor": p.get("vendor"), "arch": p.get("architecture")}
            for p in items if p.get("name")
        ]

    async def agent_ports(self, agent_id: str) -> list[dict]:
        items = await self._syscollector(agent_id, "ports", "local.port,protocol,process,state")
        rows, seen = [], set()
        for p in items:
            if (p.get("state") or "").lower() not in ("listening", "open", ""):
                continue
            local = p.get("local", {}) or {}
            port = local.get("port")
            if port is None:
                continue
            key = f"{port}/{p.get('protocol')}"
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "port": port,
                "protocol": p.get("protocol"),
                "process": p.get("process"),
                "risky": RISKY_PORTS.get(int(port) if str(port).isdigit() else -1),
            })
        rows.sort(key=lambda x: (x["risky"] is None, int(x["port"]) if str(x["port"]).isdigit() else 0))
        return rows

    async def agent_firewall(self, agent_name: str) -> dict | None:
        """读取该设备最近一次上报的防火墙状态（来自 Agent 自定义采集 + 规则 100100）。"""
        body = {
            "size": 1,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp", "data"],
            "query": {"bool": {"must": [
                {"term": {"agent.name": agent_name}},
                {"term": {"rule.id": "100100"}},
            ]}},
        }
        try:
            data = await self.indexer_search(body)
        except Exception:
            return None
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return None
        src = hits[0].get("_source", {})
        d = src.get("data", {}) or {}

        def norm(v: Any) -> str | None:
            if v is None:
                return None
            s = str(v).strip().lower()
            if s in ("on", "1", "true", "enabled", "active", "yes"):
                return "on"
            if s in ("off", "0", "false", "disabled", "inactive", "no"):
                return "off"
            return s  # na / unknown 原样返回

        return {
            "enabled": norm(d.get("fw_enabled")),
            "domain": norm(d.get("fw_domain")),
            "private": norm(d.get("fw_private")),
            "public": norm(d.get("fw_public")),
            "realtime": norm(d.get("fw_realtime")),
            "platform": d.get("fw_platform"),
            "time": src.get("timestamp"),
        }


def _top_cve_details(agg: dict[str, Any]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for bucket in agg.get("top_cves", {}).get("buckets", []):
        hits = bucket.get("sample", {}).get("hits", {}).get("hits", [])
        src = hits[0].get("_source", {}) if hits else {}
        vuln = src.get("vulnerability", {}) or {}
        pkg = src.get("package", {}) or {}
        scanner = vuln.get("scanner", {}) or {}
        score = vuln.get("score", {}) or {}
        details.append({
            "cve": bucket.get("key") or vuln.get("id"),
            "count": bucket.get("doc_count", 0),
            "severity": vuln.get("severity"),
            "score": score.get("base") if isinstance(score, dict) else None,
            "package": pkg.get("name"),
            "version": pkg.get("version"),
            "condition": scanner.get("condition"),
            "description": _shorten_vuln_description(vuln.get("description")),
            "reference": _vuln_reference(vuln),
        })
    return details


def _vuln_reference(vuln: dict[str, Any]) -> str | None:
    scanner = vuln.get("scanner", {}) or {}
    ref = scanner.get("reference") or vuln.get("reference")
    if isinstance(ref, str) and ref.strip():
        return ref.split(",", 1)[0].strip()
    return None


def _shorten_vuln_description(text: Any, limit: int = 120) -> str:
    value = " ".join(str(text or "").split())
    if not value:
        return ""
    first_sentence = re.split(r"(?<=[.!?])\s+", value, maxsplit=1)[0]
    value = first_sentence or value
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def _first_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _append_port_to_description(description: Any, port: Any, protocol: Any = None) -> str:
    text = str(description or "")
    if port in (None, ""):
        return text
    port_text = str(port)
    if port_text in text:
        return text
    proto_text = f"/{protocol}" if protocol else ""
    return f"{text}（端口：{port_text}{proto_text}）"


def _extract_listened_ports(text: str) -> list[dict[str, Any]]:
    """从 Wazuh netstat full_log 中提取监听端口清单。"""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or not re.match(r"^(tcp|udp)", line, re.I):
            continue
        parts = line.split()
        protocol = parts[0].lower()
        address, port = _parse_netstat_endpoint(parts[1] if len(parts) > 1 else "")
        if not port:
            continue
        process = parts[-1] if len(parts) >= 4 and "/" in parts[-1] else None
        key = (str(port), protocol, address or "")
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "port": port,
            "protocol": protocol,
            "address": address,
            "process": process,
            "risky": RISKY_PORTS.get(int(port) if str(port).isdigit() else -1),
        })
    return rows


def _parse_netstat_endpoint(value: str) -> tuple[str | None, str | None]:
    value = (value or "").strip()
    if not value:
        return None, None
    if value.startswith("*."):
        return "*", value.rsplit(".", 1)[-1]
    if "." in value:
        host, port = value.rsplit(".", 1)
        if port.isdigit():
            return host or None, port
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host or None, port or None
    return None, value if value.isdigit() else None


def _primary_listened_port(ports: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not ports:
        return None

    def score(row: dict[str, Any]) -> tuple[int, int, int, int]:
        port = int(row["port"]) if str(row.get("port", "")).isdigit() else 0
        risky = 1 if row.get("risky") else 0
        exposed = 1 if row.get("address") in ("*", "0.0.0.0", "::") else 0
        common_service = 1 if 0 < port < 10000 else 0
        return (risky, exposed, common_service, -port)

    return sorted(ports, key=score, reverse=True)[0]


def _attach_changed_listened_ports(rows: list[dict[str, Any]]) -> None:
    for i, row in enumerate(rows):
        listened = row.get("listened_ports") or []
        if not listened or not _is_listened_ports_alert(row):
            _finalize_alert_description(row)
            continue

        previous = next(
            (
                other for other in rows[i + 1:]
                if other.get("agent") == row.get("agent")
                and _is_listened_ports_alert(other)
                and other.get("listened_ports")
            ),
            None,
        )
        if previous:
            current_set = {_port_key(p): p for p in listened}
            previous_set = {_port_key(p): p for p in previous.get("listened_ports", [])}
            opened = [current_set[k] for k in current_set.keys() - previous_set.keys()]
            closed = [previous_set[k] for k in previous_set.keys() - current_set.keys()]
            changed = opened or closed
            if changed:
                primary = _primary_listened_port(changed) or changed[0]
                row["changed_ports"] = changed
                row["port_change"] = "opened" if opened else "closed"
                row["port"] = primary.get("port")
                row["protocol"] = primary.get("protocol")
                row["listen_ip"] = primary.get("address")
                row["process"] = primary.get("process")

        _finalize_alert_description(row)


def _finalize_alert_description(row: dict[str, Any]) -> None:
    row["description"] = _append_port_to_description(
        row.get("_description_base") or row.get("description"),
        row.get("port"),
        row.get("protocol"),
    )
    row.pop("_description_base", None)


def _is_listened_ports_alert(row: dict[str, Any]) -> bool:
    return "Listened ports status" in str(row.get("_description_base") or row.get("description") or "")


def _attach_trojan_tracking(rows: list[dict[str, Any]]) -> None:
    """把测试木马模拟相关事件按追踪 ID 汇总，供前端持续展示行为链和清除状态。"""
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        info = _trojan_event_info(row)
        if not info:
            continue
        row["trojan_event"] = info
        by_id.setdefault(info["tracking_id"], []).append(row)

    for tracking_id, items in by_id.items():
        events = [_trojan_event_info(item) for item in items]
        events = [event for event in events if event]
        stages = {str(event.get("stage") or "") for event in events}
        ports = sorted({str(event.get("port") or "") for event in events if event.get("port")})
        cleared = any(stage in {"cleared", "cleanup", "removed", "restored"} for stage in stages)
        latest_time = max((str(item.get("time") or "") for item in items), default="")
        first_time = min((str(item.get("time") or "") for item in items), default="")
        if not ports and _tracking_event_is_stale(latest_time):
            cleared = True
            stages.add("cleared")
        tracking = {
            "tracking_id": tracking_id,
            "status": "cleared" if cleared else "active",
            "pinned": not cleared,
            "severity": "high",
            "first_seen": first_time,
            "last_seen": latest_time,
            "stages": sorted(stage for stage in stages if stage),
            "ports": ports,
            "events_count": len(events),
        }
        for item in items:
            item["trojan_tracking"] = tracking


def _trojan_event_info(row: dict[str, Any]) -> dict[str, Any] | None:
    raw = str(row.get("raw_log") or "")
    desc = str(row.get("description") or "")
    rule_id = str(row.get("rule_id") or "")
    text = f"{desc}\n{raw}"
    if rule_id not in {"100120", "100121"} and "GUIZANG_WAZUH_HIGH_ALERT_TEST" not in text and "attack-sim" not in text:
        return None
    tracking_id = _regex_group(r"\bid=([A-Za-z0-9._:-]+)", text)
    if not tracking_id:
        return None
    # guizang-alert-test-* 是单次链路/高危测试，不作为“木马”持续追踪对象。
    if not tracking_id.startswith("guizang-attack-sim-"):
        return None
    return {
        "tracking_id": tracking_id,
        "stage": _regex_group(r"\bstage=([A-Za-z0-9._:-]+)", text) or "sudo_bruteforce",
        "port": _regex_group(r"\bport=([0-9]+)", text) or row.get("port"),
        "rule_id": row.get("rule_id"),
        "time": row.get("time"),
    }


def _regex_group(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text or "")
    return match.group(1) if match else None


def _tracking_event_is_stale(value: str, minutes: int = 20) -> bool:
    if not value:
        return False
    try:
        seen = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return False
    return (dt.datetime.now(dt.timezone.utc) - seen.astimezone(dt.timezone.utc)) > dt.timedelta(minutes=minutes)


def _sort_tracked_alerts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(row: dict[str, Any]) -> tuple[int, int, str]:
        tracking = row.get("trojan_tracking") or {}
        pinned = 1 if tracking.get("pinned") else 0
        level = int(row.get("level") or 0)
        return (pinned, level, str(row.get("time") or ""))

    return sorted(rows, key=key, reverse=True)


def _port_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (str(row.get("port") or ""), str(row.get("protocol") or ""), str(row.get("address") or ""))


def _enrich_port_items(items: list[dict[str, Any]], agent_ports: list[dict[str, Any]]) -> None:
    for item in items:
        if not isinstance(item, dict) or item.get("process"):
            continue
        matched = _find_matching_agent_port(item, agent_ports)
        if matched:
            item["process"] = matched.get("process")
            item["protocol"] = item.get("protocol") or matched.get("protocol")
            item["risky"] = item.get("risky") or matched.get("risky")


def _find_matching_agent_port(item: dict[str, Any], agent_ports: list[dict[str, Any]]) -> dict[str, Any] | None:
    port = str(item.get("port") or "")
    protocol = str(item.get("protocol") or "")
    if not port:
        return None
    candidates = [p for p in agent_ports if str(p.get("port") or "") == port]
    if not candidates:
        return None
    for candidate in candidates:
        if _protocol_matches(protocol, str(candidate.get("protocol") or "")):
            return candidate
    return candidates[0]


def _protocol_matches(alert_protocol: str, agent_protocol: str) -> bool:
    alert = (alert_protocol or "").lower()
    agent = (agent_protocol or "").lower()
    if not alert or not agent:
        return True
    if alert == agent:
        return True
    if alert.startswith("tcp") and agent.startswith("tcp"):
        return True
    if alert.startswith("udp") and agent.startswith("udp"):
        return True
    return False


def _apply_row_process_to_changed(row: dict[str, Any]) -> list[dict[str, Any]] | None:
    changed = row.get("changed_ports")
    if not isinstance(changed, list):
        return changed
    for item in changed:
        if isinstance(item, dict) and str(item.get("port") or "") == str(row.get("port") or ""):
            item["process"] = item.get("process") or row.get("process")
    return changed


# 常见高风险/敏感端口（用于资产清点标注，给客户直观提示）
RISKY_PORTS: dict[int, str] = {
    21: "FTP 明文传输", 22: "SSH 远程登录", 23: "Telnet 明文", 25: "SMTP", 53: "DNS 服务",
    135: "Windows RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS/SMB",
    445: "SMB 文件共享", 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL",
    3389: "远程桌面 RDP", 5432: "PostgreSQL", 5900: "VNC 远程桌面", 6379: "Redis",
    9200: "Elasticsearch", 27017: "MongoDB",
}


wazuh = WazuhClient()
