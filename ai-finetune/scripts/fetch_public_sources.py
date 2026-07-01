#!/usr/bin/env python3
"""Fetch small public security data sources used to build GuizangAI training seeds.

This script intentionally downloads only machine-readable reference data.
Large Hugging Face datasets should be downloaded manually after reviewing
license and privacy notes in SOURCES.md.

Usage:
  python ai-finetune/scripts/fetch_public_sources.py ai-finetune/data/raw/public
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path


SOURCES = {
    "cisa-kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "mitre-attack-enterprise-index.json": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
}


def download(url: str, dst: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    dst.write_bytes(data)
    try:
        parsed = json.loads(data.decode("utf-8"))
        dst.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2

    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, url in SOURCES.items():
        dst = out_dir / filename
        print(f"[GET] {url}")
        download(url, dst)
        print(f"[OK]  {dst}")

    print("\nManual review still required. Do not train directly on raw public data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
