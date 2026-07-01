#!/usr/bin/env python3
"""Validate GuizangAI fine-tuning JSONL records with stdlib checks.

Usage:
  python ai-finetune/scripts/validate_jsonl.py ai-finetune/data/train.example.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ALLOWED_TASKS = {
    "overview",
    "alert_triage",
    "compliance",
    "alert_advice",
    "vuln_advice",
    "alert_description",
}
ALLOWED_STATUS = {"needs_review", "reviewed", "rejected"}
REQUIRED = {"task", "instruction", "input", "expected_output", "source", "review_status"}


def validate_record(record: dict[str, Any], line_no: int) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED - set(record)
    if missing:
        errors.append(f"line {line_no}: missing fields: {', '.join(sorted(missing))}")
    if record.get("task") not in ALLOWED_TASKS:
        errors.append(f"line {line_no}: invalid task={record.get('task')!r}")
    if record.get("review_status") not in ALLOWED_STATUS:
        errors.append(f"line {line_no}: invalid review_status={record.get('review_status')!r}")
    if not isinstance(record.get("instruction"), str) or len(record.get("instruction", "")) < 8:
        errors.append(f"line {line_no}: instruction is too short")
    if not isinstance(record.get("input"), dict):
        errors.append(f"line {line_no}: input must be an object")
    if not isinstance(record.get("expected_output"), dict):
        errors.append(f"line {line_no}: expected_output must be an object")
    if record.get("review_status") == "reviewed" and not record.get("expected_output"):
        errors.append(f"line {line_no}: reviewed record needs a non-empty expected_output")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2

    path = Path(sys.argv[1])
    errors: list[str] = []
    total = 0
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            text = line.strip()
            if not text:
                continue
            total += 1
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: invalid JSON: {exc}")
                continue
            if not isinstance(record, dict):
                errors.append(f"line {line_no}: record must be an object")
                continue
            errors.extend(validate_record(record, line_no))

    if errors:
        print(f"[FAIL] {path}: {len(errors)} error(s)")
        for error in errors:
            print(" -", error)
        return 1
    print(f"[OK] {path}: {total} record(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
