"""AI 输出解析与文本清理工具。"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

STEP_TEXT_KEYS = ("step", "text", "action", "content", "suggestion", "建议", "处理步骤")


def extract_json(text: str) -> dict | None:
    """从模型输出中尽量稳健地提取第一个 JSON 对象。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _extract_step_text(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in STEP_TEXT_KEYS:
            item = value.get(key)
            if item not in (None, "", [], {}):
                return clean_text(item)
        if len(value) == 1:
            item = next(iter(value.values()))
            if item not in (None, "", [], {}):
                return clean_text(item)
    if isinstance(value, list) and len(value) == 1:
        return clean_text(value[0])
    return None


def _strip_code_fences(text: str) -> str:
    return re.sub(
        r"```[A-Za-z0-9_-]*\s*\n?(.*?)```",
        lambda match: match.group(1).strip(),
        text,
        flags=re.DOTALL,
    )


def clean_text(value: Any) -> str:
    extracted = _extract_step_text(value)
    if extracted is not None:
        return extracted

    text = str(value).strip().lstrip("、，,;；。 ")
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        try:
            extracted = _extract_step_text(ast.literal_eval(text))
            if extracted is not None:
                return extracted
        except (SyntaxError, ValueError):
            pass
    step_match = re.match(
        r"""^\{\s*['"](?:step|text|action|content|suggestion|建议|处理步骤)['"]\s*:\s*(['"])(?P<body>.*)\1\s*\}$""",
        text,
        flags=re.DOTALL,
    )
    if step_match:
        return clean_text(step_match.group("body").replace("\\n", "\n").replace("\\'", "'").replace('\\"', '"'))
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list) and len(parsed) == 1:
                return clean_text(str(parsed[0]))
        except (SyntaxError, ValueError):
            pass
    if (text.startswith("['") and text.endswith("']")) or (text.startswith('["') and text.endswith('"]')):
        text = text[2:-2]
    text = _strip_code_fences(text)
    return text.strip().strip("'\"").lstrip("、，,;；。 ").strip()


def clean_result(value: Any) -> Any:
    """递归清理模型输出里的空项和多余符号。"""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, list):
        cleaned = [clean_result(item) for item in value]
        return [item for item in cleaned if item not in ("", None, [], {})]
    if isinstance(value, dict):
        return {key: clean_result(item) for key, item in value.items()}
    return value


def clean_advice_steps(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := clean_text(item or ""))]


def steps_are_too_generic(steps: list[str]) -> bool:
    if len(steps) < 4:
        return True
    generic_hits = 0
    generic_patterns = [
        r"及时处理", r"加强安全", r"检查系统", r"持续监控", r"定期检查",
        r"采取措施", r"进行修复", r"联系管理员", r"follow best practices",
        r"monitor continuously", r"check the system", r"take action",
    ]
    for step in steps:
        if len(step.strip()) < 12:
            generic_hits += 1
        if any(re.search(pattern, step, re.IGNORECASE) for pattern in generic_patterns):
            generic_hits += 1
    return generic_hits >= 2


def steps_conflict_with_target_os(steps: list[str], context: dict[str, Any]) -> bool:
    if not steps:
        return False
    text = "\n".join(steps).lower()
    forbidden_tokens = [
        "simulate-wazuh-attack.sh",
        "test-wazuh-alert.sh",
        "your_server",
        "your-server",
        "your server",
        "your_ip",
        "your-ip",
        "example.com",
        "example.org",
        "example.net",
        "1.2.3.4",
        "x.x.x.x",
        "kill -9 pid",
        "taskkill /pid <pid>",
        "get-process -id <pid>",
    ]
    if any(token in text for token in forbidden_tokens):
        return True
    if re.search(r"<\s*(pid|process|process_id|port|ip|host|hostname|server|username|user|path|file)\s*>", text):
        return True

    os_name = str(
        context.get("target_os")
        or context.get("os")
        or context.get("target_platform")
        or context.get("platform")
        or ""
    ).lower()
    if not os_name:
        return False
    is_windows = "windows" in os_name or os_name in {"win", "win32"}
    is_macos = "mac" in os_name or "darwin" in os_name
    is_linux = "linux" in os_name or os_name in {"ubuntu", "debian", "centos", "rhel", "fedora", "alpine"}
    windows_only = [
        "findstr", "whoami /all", "netstat -ano", "tasklist", "get-nettcpconnection",
        "get-winevent", "event viewer", "事件查看器", "windows defender",
        "new-netfirewallrule",
    ]
    unix_only = ["iptables", "nft ", "firewall-cmd", "ufw ", "systemctl", "journalctl"]
    mac_only = ["pfctl", "launchctl", "log show"]
    if is_windows:
        return any(token in text for token in unix_only + mac_only + ["lsof "])
    if is_macos:
        return any(token in text for token in windows_only + unix_only)
    if is_linux:
        return any(token in text for token in windows_only + mac_only)
    return False
