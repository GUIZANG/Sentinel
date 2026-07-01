"""按需 AI 处理建议：提示词、事实提取和质量规则。"""

from __future__ import annotations

import json
from typing import Any

from .text_cleaning import clean_advice_steps, steps_are_too_generic

ADVICE_SCHEMA = {
    "summary": "一句话风险概述，必须包含具体设备/软件/端口/账户/CVE",
    "steps": ["5-7 条详细处置步骤；每条必须包含具体对象、执行动作、判断标准或验证结果"],
    "runbook": [{
        "phase": "check / contain / remediate / verify / rollback 之一",
        "goal": "这一步要完成的目标",
        "where": "在哪台设备、哪个页面、哪条日志或哪个终端执行",
        "commands": ["可直接复制执行的命令；没有命令则空数组"],
        "expected_result": "正常或成功时应该看到什么",
        "if_abnormal": "异常或失败时下一步做什么",
        "risk": "read / modify / danger 之一",
        "requires_confirmation": "布尔值，修改系统或危险操作必须为 true",
    }],
    "impact": "影响范围/危害，必须说明可能影响哪台设备、软件、端口、账户或业务",
    "priority": "处置优先级：immediate / soon / scheduled 之一",
}

ADVICE_OVERVIEW_SCHEMA = {
    "summary": "一句话风险概述",
    "impact": "影响范围/危害的简短说明",
    "priority": "处置优先级：immediate / soon / scheduled 之一",
}

ADVICE_SUMMARY_SCHEMA = {
    "summary": "一句话风险概述，必须包含具体对象",
    "priority": "immediate / soon / scheduled 之一",
}

ADVICE_STEPS_SCHEMA = {
    "steps": ["5-7 条详细处置步骤；每条必须包含具体对象、执行动作、判断标准或验证结果"],
}

ADVICE_FAST_SCHEMA = {
    "summary": "一句话风险概述，必须包含具体对象",
    "steps": ["可操作处置步骤，恰好 3 条，每条包含具体对象、执行动作和验证方式"],
    "runbook": [{
        "phase": "check / contain / verify 之一",
        "goal": "具体目标",
        "where": "执行位置",
        "commands": ["可复制命令"],
        "expected_result": "成功判断",
        "if_abnormal": "异常下一步",
        "risk": "read / modify / danger",
        "requires_confirmation": "布尔值",
    }],
    "priority": "immediate / soon / scheduled 之一",
}


def build_advice_prompt(kind: str, context: dict[str, Any], lang: str, part: str = "full") -> str:
    persona = (
        "You are an enterprise endpoint security incident responder. Based on the single "
        "vulnerability or alert below, give detailed, specific, directly executable remediation advice "
        "for an IT administrator. Reply ALL in English."
        if lang == "en"
        else
        "你是一名企业终端安全应急响应专家。请基于下面这一条漏洞或告警，给出详细、具体、"
        "可直接执行的处置建议，面向 IT 管理员。所有输出必须是简体中文。"
    )
    kind_label = {"vuln": "vulnerability" if lang == "en" else "漏洞", "alert": "security alert" if lang == "en" else "安全告警"}.get(kind, kind)
    instruction, schema = _advice_instruction(part, lang)
    fact_rules = _advice_fact_rules(kind, lang)
    facts = advice_facts(kind, context, lang)
    state_rule = _alert_state_rule(kind, context, lang)
    os_rule = _os_advice_rule(context, lang)
    parts = [
        persona,
        instruction,
        *fact_rules,
        *([state_rule] if state_rule else []),
        os_rule,
        "",
        (f"Type: {kind_label}" if lang == "en" else f"类型：{kind_label}"),
        (f"Required facts: {facts}" if lang == "en" else f"必须引用的事实：{facts}"),
        (f"Details: {json.dumps(context, ensure_ascii=False)}" if lang == "en" else f"明细：{json.dumps(context, ensure_ascii=False)}"),
        "",
        (
            "Every step must be actionable: include where to check, what command/menu/log to use when possible, what result means normal/abnormal, and what to do next."
            if lang == "en"
            else "每条步骤都必须可执行：尽量写清检查位置、命令/菜单/日志来源、正常/异常判断标准，以及下一步动作。"
        ),
        (
            "Also return runbook as structured executable steps. Each runbook item must include phase, goal, where, commands, expected_result, if_abnormal, risk, and requires_confirmation. Use commands=[] when the action is a GUI/log review step."
            if lang == "en"
            else "同时返回 runbook 结构化可执行步骤。每个 runbook 项必须包含 phase、goal、where、commands、expected_result、if_abnormal、risk、requires_confirmation。图形界面或日志人工核查步骤可用 commands=[]。"
        ),
        (
            "If a command modifies state, stops a service/process, deletes a file, or changes firewall policy, risk must be modify/danger, requires_confirmation must be true, and the same or next runbook item must include a verification command or verification method."
            if lang == "en"
            else "如果命令会修改系统、停止服务/进程、删除文件或修改防火墙，risk 必须是 modify/danger，requires_confirmation 必须为 true，并且当前或下一步必须包含验证命令或验证方法。"
        ),
        (
            "Do NOT use vague phrases such as 'check the system', 'handle promptly', 'strengthen security', 'monitor continuously' unless followed by a concrete object and verification method."
            if lang == "en"
            else "禁止只写“检查系统”“及时处理”“加强安全”“持续监控”等泛话；如果出现，必须跟具体对象和验证方式。"
        ),
        (
            "If a fact is missing, say exactly which fact is missing and where to obtain it; do not invent IPs, ports, users, or versions."
            if lang == "en"
            else "缺少事实时要明确缺少哪项、从哪里补查；不要编造 IP、端口、用户或版本。"
        ),
        (
            "Do NOT output placeholder commands such as `kill -9 PID` or `Get-Process -Id <PID>`. If a PID is needed, include the command that obtains it first or provide a complete script command."
            if lang == "en"
            else "不要输出 `kill -9 PID`、`Get-Process -Id <PID>` 这类占位命令。需要 PID 时，必须先给出获取 PID 的命令，或给出完整可执行脚本命令。"
        ),
        (
            "Do NOT use placeholders or demo values such as <PID>, <PORT>, <IP>, your_server, example.com, 1.2.3.4, or project test scripts. If the exact value is unknown, tell the user which log or command can obtain it."
            if lang == "en"
            else "不要使用 <PID>、<PORT>、<IP>、your_server、example.com、1.2.3.4 或项目测试脚本等占位/演示内容。具体值未知时，要说明从哪条日志或哪条命令获取。"
        ),
        (
            "Do NOT put a plain file path such as `/var/log/system.log` or `/var/log/auth.log` in a command/code block. If it should be copied as a command, output a runnable command such as `sudo cat /var/log/system.log`, `journalctl --since -1h`, or `log show --predicate 'process == \"sudo\"' --last 1h`."
            if lang == "en"
            else "不要把 `/var/log/system.log`、`/var/log/auth.log` 这类单独文件路径放进命令/代码块。需要复制执行时，必须输出可运行命令，例如 `sudo cat /var/log/system.log`、`journalctl --since -1h` 或 `log show --predicate 'process == \"sudo\"' --last 1h`。"
        ),
        "",
        ("Return ONLY a JSON object with this structure:" if lang == "en" else "只返回如下结构的 JSON 对象，不要任何额外文字："),
        json.dumps(schema, ensure_ascii=False),
        ("Avoid generic steps. Do not start every step with the same verb." if lang == "en" else "避免泛泛而谈；不要每条都用同一个动词开头。"),
    ]
    return "\n".join(parts)


def _advice_instruction(part: str, lang: str) -> tuple[str, dict]:
    if part == "overview":
        return ("Focus ONLY on risk summary, impact, and remediation priority." if lang == "en" else "只生成风险概述、影响范围和处置优先级。", ADVICE_OVERVIEW_SCHEMA)
    if part == "summary":
        return ("Return ONLY a one-sentence risk summary and priority. Do not generate steps." if lang == "en" else "只生成一句风险概述和优先级，不要生成处理步骤。", ADVICE_SUMMARY_SCHEMA)
    if part == "steps":
        return ("Focus ONLY on concrete remediation steps. Do not include summary or impact." if lang == "en" else "只生成具体处置步骤，不要包含风险概述或影响范围。", ADVICE_STEPS_SCHEMA)
    if part == "fast":
        return ("Fast mode: return only the necessary facts and exactly 3 short steps." if lang == "en" else "快速模式：只返回必要事实和恰好 3 条短步骤。", ADVICE_FAST_SCHEMA)
    return ("Generate the full remediation advice." if lang == "en" else "生成完整处置建议。步骤必须结合明细变化，不能套固定模板；每条开头尽量不同。", ADVICE_SCHEMA)


def _advice_fact_rules(kind: str, lang: str) -> list[str]:
    if kind == "alert":
        return [
            "If context contains changed_ports, port, dst_port, src_port, listened_ports, raw_log, you MUST name the exact port/protocol in the summary."
            if lang == "en" else "如果上下文包含 changed_ports、port、dst_port、src_port、listened_ports、raw_log，必须在概述中点名具体端口/协议。",
            "Prefer changed_ports and port_change as the actual changed listener. If only listened_ports exists, choose the most security-relevant exposed or risky port; do not describe it generically as 'some port'."
            if lang == "en" else "优先使用 changed_ports 和 port_change 作为实际变化的监听端口。只有 listened_ports 时，选择暴露面最大或高风险的端口，不要泛称“某个端口”或“有端口”。",
            "If no exact port can be found in context, say the port detail is missing and recommend checking raw Wazuh logs/syscollector; never invent a port."
            if lang == "en" else "如果上下文找不到确定端口，要明确说缺少端口明细并建议查看 Wazuh 原始日志/端口采集，禁止编造端口。",
            "For steps, include: process/service verification, exposure scope check, containment action, log evidence collection, and recurrence verification."
            if lang == "en" else "处置步骤要覆盖：进程/服务核验、暴露范围检查、隔离或限制动作、日志证据留存、复发验证。",
            "If trojan_tracking.status is active or trojan_tracking.pinned is true, treat it as an ongoing highlighted incident: advise immediate containment, evidence capture before cleanup, blocking exposure, and repeated status checks until a cleared event appears."
            if lang == "en" else "如果 trojan_tracking.status 为 active 或 trojan_tracking.pinned 为 true，必须按正在标红追踪的事件处理：建议立即隔离/阻断、清理前取证、限制暴露面，并持续复核直到出现 cleared 清除事件。",
            "Never present project test scripts such as simulate-wazuh-attack.sh as malware cleanup commands. Cleanup advice must describe real endpoint actions: identify the listener/process, preserve evidence, stop the confirmed process/service, remove the confirmed dropped file only after recording path/hash, and verify that the listener and alert recurrence stop."
            if lang == "en" else "不要把 simulate-wazuh-attack.sh 等项目测试脚本当成木马清除命令写给用户。清除建议必须是真实终端处置：定位监听端口/进程、保留证据、停止已确认的进程或服务、记录路径和哈希后删除已确认落地文件，并复核监听和告警不再复发。",
            "If trojan_tracking.status is cleared or trojan_tracking.pinned is false, treat it as a historical cleared incident: do NOT tell the user to keep it pinned or keep emergency containment running; focus on verifying cleanup, recurrence checks, root-cause review, and hardening."
            if lang == "en" else "如果 trojan_tracking.status 为 cleared 或 trojan_tracking.pinned 为 false，必须按已清除历史事件处理：不要建议继续置顶或维持应急隔离；重点写清理确认、复发检查、根因复盘和加固。"
        ]
    if kind == "vuln":
        return [
            "You MUST mention the exact CVE, affected package, installed version, and fixed-version condition if present."
            if lang == "en" else "必须点名具体 CVE、受影响软件、当前版本，以及修复版本条件（如果上下文存在）。",
            "For steps, include: confirm installed version, identify affected host, check vendor advisory/fixed version, upgrade or isolate, restart if needed, and rescan verification."
            if lang == "en" else "处置步骤要覆盖：确认当前版本、定位受影响设备、查询厂商公告/修复版本、升级或隔离、必要时重启服务、复扫验证。",
        ]
    return []


def _os_advice_rule(context: dict[str, Any], lang: str) -> str:
    os_name = _target_os(context)
    if lang == "en":
        return (
            f"Target operating system: {os_name or 'unknown'}. All commands, menu paths, log locations, and firewall instructions MUST match this target OS. "
            "For Windows use PowerShell/Event Viewer/Windows Defender Firewall examples; do not use Linux/macOS commands such as iptables, systemctl, journalctl, lsof, launchctl, or pfctl. "
            "For macOS use lsof, log show, launchctl, and pfctl/Application Firewall examples; do not use iptables, systemctl, or Windows Event Viewer. "
            "For Linux use ss/lsof, journalctl, systemctl, iptables/nftables/firewalld as appropriate; do not use Windows Event Viewer or macOS-only pfctl unless the target is macOS."
        )
    return (
        f"目标操作系统：{os_name or '未知'}。所有命令、菜单路径、日志位置、防火墙处置必须匹配该目标系统。"
        "Windows 设备只给 PowerShell、事件查看器、Windows Defender 防火墙等做法，不要给 iptables、systemctl、journalctl、lsof、launchctl、pfctl。"
        "macOS 设备可给 lsof、log show、launchctl、pfctl/应用防火墙等做法，不要给 iptables、systemctl 或 Windows 事件查看器。"
        "Linux 设备可给 ss/lsof、journalctl、systemctl、iptables/nftables/firewalld 等做法，不要给 Windows 事件查看器或 macOS 专用 pfctl。"
    )


def _alert_state_rule(kind: str, context: dict[str, Any], lang: str) -> str:
    if kind != "alert":
        return ""
    tracking = context.get("trojan_tracking")
    if not isinstance(tracking, dict):
        return ""
    status = str(tracking.get("status") or "").lower()
    pinned = bool(tracking.get("pinned"))
    stages = ", ".join(str(x) for x in (tracking.get("stages") or []) if x)
    ports = ", ".join(str(x) for x in (tracking.get("ports") or []) if x)
    if status == "cleared" or not pinned:
        return (
            f"Current incident state: cleared/unpinned. Tracking ID={tracking.get('tracking_id')}; stages={stages}; ports={ports}. Advice must be post-cleanup verification and hardening, not emergency isolation."
            if lang == "en"
            else f"当前事件状态：已清除/已取消标红置顶。追踪 ID={tracking.get('tracking_id')}；阶段={stages}；端口={ports}。建议必须偏向清理后确认和加固，不要按仍在爆发的事件写应急隔离。"
        )
    return (
        f"Current incident state: active highlighted tracking. Tracking ID={tracking.get('tracking_id')}; stages={stages}; ports={ports}. Advice must prioritize immediate containment before cleanup and continuous verification until cleared."
        if lang == "en"
        else f"当前事件状态：正在标红置顶追踪。追踪 ID={tracking.get('tracking_id')}；阶段={stages}；端口={ports}。建议必须优先写立即阻断/隔离、清理前取证，并持续验证直到清除。"
    )


def advice_facts(kind: str, context: dict[str, Any], lang: str) -> str:
    if kind == "vuln":
        parts = [
            _fact("target_os" if lang == "en" else "目标系统", _target_os(context)),
            _fact("CVE", context.get("cve")),
            _fact("software" if lang == "en" else "软件", context.get("package")),
            _fact("installed_version" if lang == "en" else "当前版本", context.get("version")),
            _fact("severity" if lang == "en" else "严重度", context.get("severity")),
            _fact("CVSS", context.get("score")),
            _fact("fix_condition" if lang == "en" else "修复条件", context.get("condition")),
        ]
        desc = str(context.get("description") or "").strip()
        if desc:
            parts.append(_fact("description" if lang == "en" else "漏洞说明", desc[:140]))
        return "；".join(p for p in parts if p)

    changed = context.get("changed_ports")
    port_item = changed[0] if isinstance(changed, list) and changed and isinstance(changed[0], dict) else {}
    port = port_item.get("port") or context.get("dst_port") or context.get("src_port") or context.get("port")
    protocol = port_item.get("protocol") or context.get("protocol")
    address = port_item.get("address") or context.get("listen_ip")
    process = port_item.get("process") or context.get("process")
    tracking = context.get("trojan_tracking") if isinstance(context.get("trojan_tracking"), dict) else {}
    event = context.get("trojan_event") if isinstance(context.get("trojan_event"), dict) else {}
    display_desc = str(context.get("display_description") or "").strip()
    parts = [
        _fact("target_os" if lang == "en" else "目标系统", _target_os(context)),
        _fact("agent" if lang == "en" else "设备", context.get("agent")),
        _fact("alert" if lang == "en" else "告警", display_desc or context.get("description")),
        _fact("port" if lang == "en" else "端口", f"{port}/{protocol}" if port and protocol else port),
        _fact("listen_ip" if lang == "en" else "监听地址", address),
        _fact("process" if lang == "en" else "进程", process),
        _fact("change" if lang == "en" else "变化", context.get("port_change")),
        _fact("tracking_id" if lang == "en" else "追踪ID", tracking.get("tracking_id")),
        _fact("tracking_status" if lang == "en" else "追踪状态", tracking.get("status")),
        _fact("highlighted" if lang == "en" else "是否标红置顶", tracking.get("pinned")),
        _fact("stages" if lang == "en" else "阶段", ",".join(str(x) for x in tracking.get("stages", []) if x)),
        _fact("event_stage" if lang == "en" else "当前事件阶段", event.get("stage")),
    ]
    return "；".join(p for p in parts if p)


def _fact(label: str, value: Any) -> str:
    if value in (None, ""):
        return ""
    return f"{label}={value}"


def _target_os(context: dict[str, Any]) -> str:
    value = str(context.get("target_os") or context.get("os") or context.get("target_platform") or context.get("platform") or "").strip()
    low = value.lower()
    if "windows" in low or low in {"win32", "win"}:
        return "Windows"
    if "mac" in low or "darwin" in low:
        return "macOS"
    if "linux" in low or low in {"ubuntu", "debian", "centos", "rhel", "fedora", "alpine"}:
        return "Linux"
    return value


__all__ = ["build_advice_prompt", "clean_advice_steps", "steps_are_too_generic"]
