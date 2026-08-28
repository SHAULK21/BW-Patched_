"""Command-line entry point for the reverse-engineering analyzer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .thumb_re import ThumbREAnalyzer


def main() -> int:
    parser = argparse.ArgumentParser(description="Xiaomi 5 Plus Thumb-2 RE analyzer")
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--target", action="append", type=lambda value: int(value, 0), default=[])
    parser.add_argument("--json", dest="json_path", type=Path)
    args = parser.parse_args()

    analyzer = ThumbREAnalyzer(args.firmware.read_bytes())
    report = analyzer.report(args.target or None)

    print(json.dumps(report, indent=2))
    if args.json_path:
        args.json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
