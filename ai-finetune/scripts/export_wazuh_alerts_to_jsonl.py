#!/usr/bin/env python3
"""Convert Wazuh alerts.json lines into GuizangAI seed JSONL records.

The output is NOT ready for training. It is marked as needs_review so a human
can write or approve expected_output before moving it to data/processed.

Usage:
  python ai-finetune/scripts/export_wazuh_alerts_to_jsonl.py \
    /var/ossec/logs/alerts/alerts.json \
    ai-finetune/data/raw/wazuh-alerts-seed.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOME_RE = re.compile(r"/Users/[^/\s]+|/home/[^/\s]+")
WIN_USER_RE = re.compile(r"C:\\Users\\[^\\\s]+", re.I)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        text = IP_RE.sub("<IP>", value)
        text = HOME_RE.sub("/Users/<USER>", text)
        text = WIN_USER_RE.sub(r"C:\\Users\\<USER>", text)
        return text
    return value


def slim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    syscheck = alert.get("syscheck") if isinstance(alert.get("syscheck"), dict) else {}
    return redact({
        "timestamp": alert.get("timestamp"),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "rule": {
            "id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "groups": rule.get("groups"),
            "mitre": rule.get("mitre"),
        },
        "location": alert.get("location"),
        "decoder": alert.get("decoder"),
        "data": data,
        "syscheck": {
            "path": syscheck.get("path"),
            "event": syscheck.get("event"),
        },
        "full_log": alert.get("full_log"),
    })


def to_record(alert: dict[str, Any]) -> dict[str, Any]:
    context = slim_alert(alert)
    return {
        "task": "alert_advice",
        "instruction": "根据这条 Wazuh 告警生成中文处置建议和可执行 runbook，只返回 JSON。",
        "input": {
            "kind": "alert",
            "context": context,
        },
        "expected_output": {},
        "source": "local_wazuh_alerts_json",
        "review_status": "needs_review",
        "notes": "由 Wazuh alerts.json 自动生成。训练前必须人工补全 expected_output 并复核脱敏结果。",
    }


def iter_alerts(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                print(f"[WARN] skip invalid JSON line {line_no}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                yield obj


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip())
        return 2

    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with dst.open("w", encoding="utf-8") as out:
        for alert in iter_alerts(src):
            out.write(json.dumps(to_record(alert), ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    print(f"[OK] wrote {count} seed records to {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
