"""AI 兜底结果：无模型、解析失败或输出太泛时使用。"""

from __future__ import annotations

import re
from typing import Any


def mock_result(task_key: str, summary: dict, lang: str = "zh") -> dict[str, Any]:
    alerts = summary.get("alerts", {})
    sev = alerts.get("by_severity", {})
    eps = summary.get("endpoints", {})
    high = int(sev.get("high", 0)) + int(sev.get("critical", 0))
    total = int(alerts.get("total", 0))

    if task_key == "overview":
        if high > 0:
            level, score = ("Warning" if lang == "en" else "警告"), min(85, 50 + high)
        elif total > 200:
            level, score = ("Attention" if lang == "en" else "关注"), 40
        else:
            level, score = ("Safe" if lang == "en" else "安全"), 18
        if lang == "en":
            return {
                "_source": "mock",
                "risk_level": level,
                "risk_score": score,
                "headline": f"{eps.get('active', 0)} online · {high} high-risk pending",
                "summary": (
                    f"In the past {summary.get('window','24h')}, {total} alerts were observed, including {high} high-risk alerts. "
                    f"Online endpoints: {eps.get('active',0)}/{eps.get('total',0)}. Overall status: {level}."
                ),
                "top_actions": mock_actions(summary, lang),
            }
        return {
            "_source": "mock",
            "risk_level": level,
            "risk_score": score,
            "headline": f"{eps.get('active', 0)}台在线 · {high}条高危待处理",
            "summary": (
                f"过去 {summary.get('window','24h')} 内共 {total} 条告警，其中高危 {high} 条。"
                f"在线设备 {eps.get('active',0)}/{eps.get('total',0)} 台，整体处于「{level}」状态。"
            ),
            "top_actions": mock_actions(summary, lang),
        }
    if task_key == "alert_triage":
        groups = alerts.get("by_group", {})
        clusters = [
            {"category": cat, "count": cnt, "meaning": group_meaning(cat, lang), "severity": ("High" if lang == "en" else "高") if cat in ("rootcheck",) else ("Medium" if lang == "en" else "中")}
            for cat, cnt in list(groups.items())[:4]
        ]
        return {"_source": "mock", "clusters": clusters}
    if task_key == "compliance":
        comp = summary.get("compliance", {})
        worst, worst_score = None, 101
        for name, c in comp.items():
            score = c.get("score") or 100
            if score < worst_score:
                worst, worst_score = name, score
        return {
            "_source": "mock",
            "worst_endpoint": worst or "—",
            "worst_score": worst_score if worst else 0,
            "recommendations": (
                ["Disable unencrypted remote access", "Enable disk encryption (BitLocker/FileVault)", "Install system patches promptly"]
                if lang == "en"
                else ["关闭未加密远程访问", "开启磁盘加密(BitLocker/FileVault)", "及时安装系统补丁"]
            ),
        }
    return {"_source": "mock"}


def mock_actions(summary: dict, lang: str = "zh") -> list[str]:
    actions = []
    for name, c in (summary.get("compliance", {}) or {}).items():
        if (c.get("score") or 100) < 50:
            actions.append(f"Harden {name} (compliance score {c.get('score')})" if lang == "en" else f"加固 {name}（合规仅 {c.get('score')} 分）")
    if not actions:
        actions.append("Maintain current protection and review regularly" if lang == "en" else "保持当前防护，定期复查")
    return actions[:3]


def group_meaning(group: str, lang: str = "zh") -> str:
    en = {
        "sca": "Security baseline finding",
        "syscheck": "Critical file change",
        "rootcheck": "Host anomaly or suspicious behavior",
        "windows": "Windows system event",
        "ossec": "Agent/system-level event",
        "authentication": "Authentication event",
        "sudo": "Privilege escalation action",
    }
    zh = {
        "sca": "安全基线检查未达标项",
        "syscheck": "关键文件被改动",
        "rootcheck": "主机异常/可疑行为",
        "windows": "Windows 系统事件",
        "ossec": "Agent 自身/系统级事件",
        "authentication": "登录认证相关",
        "sudo": "提权操作",
    }
    return (en if lang == "en" else zh).get(group, "Security event" if lang == "en" else "安全事件")


def mock_advice(kind: str, context: dict[str, Any], lang: str) -> dict[str, Any]:
    sev = str(context.get("severity") or "").lower()
    level = int(context.get("level") or 0)
    high = sev in ("critical", "high") or level >= 12
    priority = "immediate" if high else ("soon" if (sev == "medium" or level >= 7) else "scheduled")

    result = _mock_vuln_advice(context, lang, priority) if kind == "vuln" else _mock_alert_advice(context, lang, priority)
    result.setdefault("runbook", _runbook_from_steps(result.get("steps") or [], context, lang))
    return result


def _mock_vuln_advice(context: dict[str, Any], lang: str, priority: str) -> dict[str, Any]:
    cve = context.get("cve") or "该漏洞"
    pkg = context.get("package") or "受影响组件"
    version = context.get("version") or "未知版本"
    condition = context.get("condition") or "升级到官方修复版本"
    agent = context.get("agent") or "受影响设备"
    package_check_en = _os_package_check(context, pkg, "en")
    package_check_zh = _os_package_check(context, pkg, "zh")
    if lang == "en":
        return {
            "_source": "mock",
            "summary": f"{agent} has {pkg} {version} affected by {cve}.",
            "steps": [
                f"Confirm scope on {agent}: {package_check_en}; verify {pkg} is still {version}.",
                f"Check the vendor advisory for {cve} and record the fixed-version requirement: {condition}.",
                f"Plan remediation for {agent}: upgrade {pkg} to the fixed version; if no patch is available, restrict network exposure for the dependent service.",
                f"After upgrade, restart only the service that loads {pkg}; if unknown, schedule a controlled reboot for {agent}.",
                f"Run a Wazuh vulnerability rescan and verify {cve} no longer appears for {pkg} on {agent}.",
                "Document the old version, new version, operator, and scan result for audit closure.",
            ],
            "impact": f"Attackers may exploit {cve} to compromise the device.",
            "priority": priority,
        }
    return {
        "_source": "mock",
        "summary": f"{agent} 上的 {pkg} {version} 命中 {cve}，需要按修复版本要求处置。",
        "steps": [
            f"确认影响范围：在 {agent} 上执行 {package_check_zh}，核对 {pkg} 当前版本是否仍为 {version}。",
            f"核对修复条件：打开厂商公告或 CVE 页面确认 {cve} 的修复版本要求，当前记录为“{condition}”。",
            f"执行修复：将 {agent} 上的 {pkg} 升级到修复版本；如暂时不能升级，先限制依赖该组件的服务对外访问。",
            f"处理运行中服务：升级后只重启加载 {pkg} 的业务进程；无法确认进程时安排 {agent} 维护窗口重启。",
            f"复扫验证：触发 Wazuh 漏洞检测或等待下一轮扫描，确认 {cve} 不再出现在 {agent}/{pkg} 明细中。",
            "闭环记录：保存升级前版本、升级后版本、操作人、复扫结果，作为审计和回滚依据。",
        ],
        "impact": f"攻击者可能利用 {cve} 危害该设备。",
        "priority": priority,
    }


def _mock_alert_advice(context: dict[str, Any], lang: str, priority: str) -> dict[str, Any]:
    desc = context.get("display_description") or context.get("description") or "该告警"
    port_label = advice_port_label(context)
    agent = context.get("agent") or "该设备"
    process = context.get("process") or advice_changed_value(context, "process") or "未知进程"
    listen_ip = context.get("listen_ip") or advice_changed_value(context, "address") or "未知监听地址"
    tracking = context.get("trojan_tracking") if isinstance(context.get("trojan_tracking"), dict) else None
    if tracking:
        return _mock_trojan_tracking_advice(context, lang, agent, desc, port_label, tracking)
    desc_lower = str(desc).lower()
    is_software_protection = "software protection" in desc_lower or "license activation" in desc_lower or "spp" in desc_lower
    is_auth = any(key in desc_lower for key in ("login", "logon", "authentication", "sshd", "pam", "failed password"))
    if lang == "en":
        return _mock_alert_advice_en(context, agent, desc, port_label, process, listen_ip, priority, is_software_protection, is_auth)
    return _mock_alert_advice_zh(context, agent, desc, port_label, process, listen_ip, priority, is_software_protection, is_auth)


def _mock_trojan_tracking_advice(
    context: dict[str, Any],
    lang: str,
    agent: str,
    desc: str,
    port_label: str,
    tracking: dict[str, Any],
) -> dict[str, Any]:
    tracking_id = tracking.get("tracking_id") or "unknown"
    status = str(tracking.get("status") or "").lower()
    pinned = bool(tracking.get("pinned"))
    stages = ", ".join(str(x) for x in (tracking.get("stages") or []) if x) or "unknown"
    ports = ", ".join(str(x) for x in (tracking.get("ports") or []) if x) or port_label or "unknown"
    cleared = status == "cleared" or not pinned
    listener_check_en = _os_listener_check(context, ports, "en")
    listener_check_zh = _os_listener_check(context, ports, "zh")
    firewall_en = _os_firewall_action(context, ports, "en")
    firewall_zh = _os_firewall_action(context, ports, "zh")
    log_en = _os_log_source(context, "en")
    log_zh = _os_log_source(context, "zh")
    if lang == "en":
        return {
            "_source": "mock",
            "summary": (
                f"{agent} has a cleared trojan-simulation incident {tracking_id}; verify cleanup and recurrence controls."
                if cleared else
                f"{agent} has an active highlighted trojan-simulation incident {tracking_id} on port(s) {ports}; contain before cleanup."
            ),
            "steps": (
                [
                    f"Confirm closure evidence: search Wazuh for tracking ID {tracking_id} and verify a cleared event exists after stages {stages}.",
                    f"Verify no listener remains on {agent}: {listener_check_en}; if any listener is still present, identify the process and reopen the incident.",
                    f"Review collected Wazuh raw logs, process evidence, and target OS logs ({log_en}) to decide whether the activity was only the approved simulation or an unexpected real event.",
                    "Check the next monitoring window for the same tracking ID, port, or repeated sudo brute-force pattern; no new active event should appear.",
                    "Harden after closure: keep the high-risk rule enabled, document the operator/time/result, and add firewall/service baseline controls for unexpected listeners.",
                ]
                if cleared else
                [
                    f"Treat {tracking_id} as ongoing: isolate {agent} from untrusted networks or restrict the exposed port(s) immediately with target OS controls: {firewall_en}.",
                    f"Before cleanup, collect evidence: Wazuh raw log, listener process, command line, parent process, recent authentication events, file changes, and target OS logs from {log_en}.",
                    f"Validate the behavior chain in Wazuh: confirm stages {stages} and whether a cleared stage is still missing.",
                    f"Identify and stop only the confirmed malicious listener on {agent}: first run {listener_check_en}, record the process details, then stop that specific process or service using the target OS service/process manager.",
                    f"Keep refreshing the alert view for {tracking_id} until a cleared event appears and the tracking state changes to unpinned.",
                ]
            ),
            "impact": f"Tracking status={status or 'active'}, highlighted={pinned}, ports={ports}.",
            "priority": "soon" if cleared else "immediate",
        }
    return {
        "_source": "mock",
        "summary": (
            f"{agent} 的测试木马追踪 {tracking_id} 已清除，需要做清理确认、复发检查和加固闭环。"
            if cleared else
            f"{agent} 存在正在标红追踪的测试木马事件 {tracking_id}，涉及端口 {ports}，应先隔离阻断再清理。"
        ),
        "steps": (
            [
                f"确认清除证据：在安全告警中搜索追踪 ID {tracking_id}，确认最后阶段包含 cleared，且已取消置顶标红。",
                f"核验端口关闭：在 {agent} 上执行 {listener_check_zh}；如仍有监听，记录进程并重新按活跃事件处置。",
                f"复核原始日志：检查 Wazuh 原始日志、进程记录和目标系统日志 {log_zh}，确认这是预期测试模拟，不是额外真实异常。",
                f"观察复发：下一个监控周期继续搜索 {tracking_id}、端口 {ports} 和相同 sudo 暴力尝试模式，确认没有新的 active 事件。",
                "加固闭环：保留高危规则、记录操作人/时间/结果，并把异常监听端口纳入主机防火墙或服务基线检查。",
            ]
            if cleared else
            [
                f"按正在发生的事件处理：先将 {agent} 从非可信网络隔离，或立即按目标系统方式限制端口访问：{firewall_zh}。",
                f"清理前先取证：保存 Wazuh 原始日志、监听进程、命令行、父进程、近期登录/提权事件、文件变更记录，以及目标系统日志 {log_zh}。",
                f"核对行为链：在告警中确认追踪 ID {tracking_id} 的阶段为 {stages}，重点检查是否还没有 cleared 清除事件。",
                f"定位并停止已确认的恶意监听：先在 {agent} 上执行 {listener_check_zh}，记录进程信息后，只停止该明确进程或对应服务；不要使用 `kill -9 PID` 这类占位命令。",
                f"保持追踪：继续刷新 {tracking_id}，直到出现 cleared 阶段且告警状态变为取消置顶标红后，再进入复盘加固。",
            ]
        ),
        "impact": f"追踪状态={status or 'active'}，置顶标红={pinned}，端口={ports}，阶段={stages}。",
        "priority": "soon" if cleared else "immediate",
    }


def _mock_alert_advice_en(context: dict[str, Any], agent: str, desc: str, port_label: str, process: str, listen_ip: str, priority: str, is_sp: bool, is_auth: bool) -> dict[str, Any]:
    listener_check = _os_listener_check(context, port_label, "en")
    log_source = _os_log_source(context, "en")
    firewall_action = _os_firewall_action(context, port_label, "en")
    if is_sp:
        return {
            "_source": "mock",
            "summary": f"{agent} triggered a Software Protection/license activation event.",
            "steps": [
                f"Open Event Viewer on {agent}, filter Application/System logs around the alert time, and confirm the provider is Software Protection Platform Service or SPP.",
                "Run `slmgr /dlv` or check Windows activation settings to verify whether the activation state, KMS server, or license channel changed.",
                "Confirm whether the activation action matches a planned OS image, domain join, KMS renewal, or license maintenance window.",
                "If it is unauthorized, isolate the endpoint from user networks, collect the Wazuh raw log and Windows event details, and check recent admin logons.",
                "Verify closure by confirming no repeated Software Protection/license events appear in Wazuh after the maintenance window.",
            ],
            "impact": f"May indicate Windows activation/KMS changes on {agent}.",
            "priority": priority,
        }
    if is_auth:
        return {
            "_source": "mock",
            "summary": f"{agent} triggered an authentication-related alert: {desc}.",
            "steps": [
                f"Identify the affected account, source IP, and login method from the Wazuh raw log; if missing, query the target OS logs: {log_source}.",
                "Compare the source IP and time with approved admin activity; mark it abnormal if it comes from an unknown network or outside the maintenance window.",
                f"For repeated failures, temporarily block the source IP using the target OS firewall or VPN control: {firewall_action}; enforce password reset or MFA review for the targeted account.",
                "For a successful suspicious login, disable the account or revoke sessions first, then collect process, network, and file-change evidence on the endpoint.",
                "Verify that new failed/successful login alerts for the same account or source IP stop for at least one monitoring window.",
            ],
            "impact": "May indicate password guessing, stolen credentials, or unauthorized remote access.",
            "priority": priority,
        }
    return {
        "_source": "mock",
        "summary": f"Investigate the alert{' on ' + port_label if port_label else ''}: {desc}.",
        "steps": [
            f"On {agent}, identify the listener: {listener_check}; expected process={process}, listen address={listen_ip}." if port_label else f"Open Wazuh raw log for {agent} and identify the exact affected port, process, and source event time.",
            "Check whether the service start/stop or configuration change matches an approved change ticket or maintenance window.",
            f"If unauthorized, stop the confirmed process/service first; for externally reachable listeners, restrict access with target OS controls: {firewall_action}.",
            f"Collect evidence before cleanup: Wazuh raw log, process command line, parent process, service name, recent account logons, and target OS logs from {log_source}.",
            "Verify remediation by rescanning listening ports and confirming the same alert does not recur in the next monitoring window.",
        ],
        "impact": "May indicate intrusion, brute force, or unauthorized change.",
        "priority": priority,
    }


def _mock_alert_advice_zh(context: dict[str, Any], agent: str, desc: str, port_label: str, process: str, listen_ip: str, priority: str, is_sp: bool, is_auth: bool) -> dict[str, Any]:
    listener_check = _os_listener_check(context, port_label, "zh")
    log_source = _os_log_source(context, "zh")
    firewall_action = _os_firewall_action(context, port_label, "zh")
    if is_sp:
        return {
            "_source": "mock",
            "summary": f"{agent} 触发软件保护/许可证激活事件，需要确认是否为授权的 Windows 激活或 KMS 续期。",
            "steps": [
                f"在 {agent} 打开事件查看器，按告警时间过滤“应用程序/系统”日志，确认来源是否为 Software Protection Platform Service、SPP 或许可证激活。",
                "执行 `slmgr /dlv` 或查看“设置 > 系统 > 激活”，核对激活状态、KMS 地址、许可证通道是否发生变化。",
                "和变更记录核对：确认该时间点是否存在系统镜像部署、加入域、KMS 续期或许可证维护任务。",
                f"如果不是授权操作，先将 {agent} 从普通办公网隔离，保留 Wazuh 原始日志和 Windows 事件 ID，再核查近期管理员登录记录。",
                "确认无异常后关闭事件：观察一个监控周期，确保同一设备不再反复出现软件保护/许可证激活告警。",
            ],
            "impact": f"该事件影响 {agent} 的 Windows 激活/授权状态。",
            "priority": priority,
        }
    if is_auth:
        return {
            "_source": "mock",
            "summary": f"{agent} 触发登录/认证相关告警：{desc}。",
            "steps": [
                f"先从 Wazuh 原始日志定位账号、来源 IP、登录协议和失败/成功时间；字段缺失时回查目标系统日志：{log_source}。",
                "将来源 IP、时间段和账号与运维变更/值班记录比对；未知来源、非工作时间或高频失败应判定为异常。",
                f"如果是连续失败，先用目标系统防火墙或 VPN 控制临时阻断来源 IP：{firewall_action}；同时要求目标账号重置密码、检查 MFA 状态。",
                "如果出现可疑成功登录，优先禁用账号或注销会话，再采集该设备进程、网络连接、文件变更和最近提权记录。",
                "复核验证：观察至少一个监控周期，确认相同账号或来源 IP 不再产生新的失败/成功登录告警。",
            ],
            "impact": "可能涉及密码爆破、凭据泄露或未授权远程登录。",
            "priority": priority,
        }
    return {
        "_source": "mock",
        "summary": f"建议核查该告警{'（' + port_label + '）' if port_label else ''}：{desc}。",
        "steps": [
            f"在 {agent} 上核验监听信息：{listener_check}；预期进程={process}，监听地址={listen_ip}。" if port_label else f"先打开 {agent} 的 Wazuh 原始日志，补齐具体端口、进程、来源事件时间和触发规则。",
            "核对变更来源：检查该服务启动/停止是否对应变更单、软件安装、系统更新或管理员操作记录。",
            f"如果无授权依据，先停止已确认的进程或服务；对外暴露端口要用目标系统方式限制到可信来源 IP：{firewall_action}。",
            f"留存证据：保存 Wazuh 原始日志、进程命令行、父进程、服务名、最近登录账号，以及目标系统日志 {log_source}。",
            "验证闭环：重新采集监听端口并观察一个监控周期，确认同类告警不再复发。",
        ],
        "impact": "可能涉及入侵、爆破或未授权变更。",
        "priority": priority,
    }


def _target_os_kind(context: dict[str, Any]) -> str:
    value = str(context.get("target_os") or context.get("os") or context.get("target_platform") or context.get("platform") or "").lower()
    if "windows" in value or value in {"win", "win32"}:
        return "windows"
    if "mac" in value or "darwin" in value:
        return "macos"
    if "linux" in value or value in {"ubuntu", "debian", "centos", "rhel", "fedora", "alpine"}:
        return "linux"
    return "unknown"


def _first_port(value: str) -> str:
    text = str(value or "")
    match = re.search(r"\d+", text)
    return match.group(0) if match else "<port>"


def _os_listener_check(context: dict[str, Any], port_label: str, lang: str) -> str:
    os_kind = _target_os_kind(context)
    port = _first_port(port_label)
    if lang == "en":
        if os_kind == "windows":
            return f"PowerShell `$c=Get-NetTCPConnection -LocalPort {port}; $c | Select-Object LocalAddress,LocalPort,State,OwningProcess; Get-Process -Id $c.OwningProcess`"
        if os_kind == "macos":
            return f"`lsof -nP -iTCP:{port} -sTCP:LISTEN`"
        if os_kind == "linux":
            return f"`ss -ltnp 'sport = :{port}'` or `lsof -nP -iTCP:{port} -sTCP:LISTEN`"
        return "use the endpoint's native network-connection tool or Wazuh syscollector port inventory"
    if os_kind == "windows":
        return f"PowerShell `$c=Get-NetTCPConnection -LocalPort {port}; $c | Select-Object LocalAddress,LocalPort,State,OwningProcess; Get-Process -Id $c.OwningProcess`"
    if os_kind == "macos":
        return f"`lsof -nP -iTCP:{port} -sTCP:LISTEN`"
    if os_kind == "linux":
        return f"`ss -ltnp 'sport = :{port}'` 或 `lsof -nP -iTCP:{port} -sTCP:LISTEN`"
    return "使用该终端系统原生网络连接工具或 Wazuh syscollector 端口清单"


def _os_log_source(context: dict[str, Any], lang: str) -> str:
    os_kind = _target_os_kind(context)
    if lang == "en":
        if os_kind == "windows":
            return "Event Viewer > Windows Logs > Security/System or PowerShell `Get-WinEvent`"
        if os_kind == "macos":
            return "`log show --predicate 'process == \"sudo\"' --last 1h` and `sudo cat /var/log/system.log` if the legacy log file exists"
        if os_kind == "linux":
            return "`journalctl --since -1h`, `sudo cat /var/log/auth.log`, or `sudo cat /var/log/secure` depending on distribution"
        return "Wazuh raw log and the endpoint's native security/system logs"
    if os_kind == "windows":
        return "事件查看器 > Windows 日志 > 安全/系统，或 PowerShell `Get-WinEvent`"
    if os_kind == "macos":
        return "`log show --predicate 'process == \"sudo\"' --last 1h`，必要时执行 `sudo cat /var/log/system.log` 查看旧版日志文件"
    if os_kind == "linux":
        return "`journalctl --since -1h`、`sudo cat /var/log/auth.log` 或 `sudo cat /var/log/secure`（按发行版选择）"
    return "Wazuh 原始日志和该终端系统原生安全/系统日志"


def _os_firewall_action(context: dict[str, Any], port_label: str, lang: str) -> str:
    os_kind = _target_os_kind(context)
    port = _first_port(port_label)
    if lang == "en":
        if os_kind == "windows":
            return f"Windows Defender Firewall advanced rules or PowerShell `New-NetFirewallRule` scoped to port {port}"
        if os_kind == "macos":
            return f"macOS Application Firewall or `pfctl` rules scoped to port {port}"
        if os_kind == "linux":
            return f"`firewall-cmd`, `ufw`, `nft`, or `iptables` rules scoped to port {port}, depending on the distribution"
        return "the endpoint's native firewall or network access control"
    if os_kind == "windows":
        return f"Windows Defender 防火墙高级规则，或 PowerShell `New-NetFirewallRule` 针对端口 {port} 设置来源范围"
    if os_kind == "macos":
        return f"macOS 应用防火墙，或使用 `pfctl` 针对端口 {port} 设置限制规则"
    if os_kind == "linux":
        return f"按发行版使用 `firewall-cmd`、`ufw`、`nft` 或 `iptables` 针对端口 {port} 设置限制规则"
    return "该终端系统原生防火墙或网络访问控制"


def _os_package_check(context: dict[str, Any], package: str, lang: str) -> str:
    os_kind = _target_os_kind(context)
    pkg = package or "<package>"
    if lang == "en":
        if os_kind == "windows":
            return f"PowerShell `Get-Package -Name \"{pkg}\"` or `winget list --name \"{pkg}\"`"
        if os_kind == "macos":
            return f"`brew list --versions {pkg}` or `pkgutil --pkgs | grep -i {pkg}` depending on how it was installed"
        if os_kind == "linux":
            return f"`dpkg -l | grep -i {pkg}` on Debian/Ubuntu or `rpm -qa | grep -i {pkg}` on RHEL/CentOS/Fedora"
        return "Wazuh software inventory or the endpoint's native package inventory"
    if os_kind == "windows":
        return f"PowerShell `Get-Package -Name \"{pkg}\"` 或 `winget list --name \"{pkg}\"`"
    if os_kind == "macos":
        return f"`brew list --versions {pkg}`，或按安装方式用 `pkgutil --pkgs | grep -i {pkg}`"
    if os_kind == "linux":
        return f"Debian/Ubuntu 用 `dpkg -l | grep -i {pkg}`，RHEL/CentOS/Fedora 用 `rpm -qa | grep -i {pkg}`"
    return "Wazuh 软件清单或该终端系统原生软件包清单"


def advice_port_label(context: dict[str, Any]) -> str:
    port = context.get("dst_port") or context.get("src_port") or context.get("port")
    protocol = context.get("protocol")
    changed = context.get("changed_ports")
    if isinstance(changed, list) and changed:
        item = changed[0] if isinstance(changed[0], dict) else {}
        port = item.get("port") or port
        protocol = item.get("protocol") or protocol
    if not port:
        listened = context.get("listened_ports")
        if isinstance(listened, list) and listened:
            item = listened[0] if isinstance(listened[0], dict) else {}
            port = item.get("port")
            protocol = protocol or item.get("protocol")
    if not port:
        return ""
    return f"{port}/{protocol}" if protocol else str(port)


def advice_changed_value(context: dict[str, Any], key: str) -> Any:
    changed = context.get("changed_ports")
    if isinstance(changed, list) and changed and isinstance(changed[0], dict):
        return changed[0].get(key)
    listened = context.get("listened_ports")
    if isinstance(listened, list) and listened and isinstance(listened[0], dict):
        return listened[0].get(key)
    return None


def _runbook_from_steps(steps: list[str], context: dict[str, Any], lang: str) -> list[dict[str, Any]]:
    agent = context.get("agent") or ("target endpoint" if lang == "en" else "目标终端")
    phases = ["check", "check", "contain", "remediate", "verify", "rollback"]
    runbook: list[dict[str, Any]] = []
    for i, step in enumerate(steps[:6]):
        commands = _extract_commands(step)
        risk = _command_risk("\n".join(commands))
        runbook.append({
            "phase": phases[min(i, len(phases) - 1)],
            "goal": step,
            "where": str(agent),
            "commands": commands,
            "expected_result": "Expected output confirms the affected object is identified or remediated." if lang == "en" else "预期输出能确认受影响对象已定位或已处置。",
            "if_abnormal": "Keep the issue open, preserve evidence, and continue investigation." if lang == "en" else "保持问题未修复，先保留证据并继续排查。",
            "risk": risk,
            "requires_confirmation": risk in {"modify", "danger"},
        })
    return runbook


def _extract_commands(text: str) -> list[str]:
    return [m.strip() for m in re.findall(r"`([^`\n]+)`", text or "") if m.strip()][:4]


def _command_risk(text: str) -> str:
    low = (text or "").lower()
    if re.search(r"\b(rm\s+-rf|mkfs|dd\s+|shutdown|reboot|taskkill|remove-item|pfctl\s+-f)\b", low):
        return "danger"
    if re.search(r"\b(rm|mv|chmod|chown|kill|pkill|systemctl\s+(stop|restart|disable)|launchctl\s+(bootout|remove|unload)|iptables|nft|ufw|firewall-cmd|new-netfirewallrule|net\s+stop)\b", low):
        return "modify"
    return "read"
