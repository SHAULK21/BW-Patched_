#!/usr/bin/env python3
"""Evidence-first static RE for Xiaomi 5 Plus raw MCU firmware.

Examples:
    python tools/analyze_mi5plus.py firmware.bin
    python tools/analyze_mi5plus.py firmware.bin --json report.json
    python tools/analyze_mi5plus.py firmware.bin --target 0x20001E2C

This command never modifies the firmware.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bwpatcher.re.thumb_re import ThumbREAnalyzer


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidence-first Xiaomi 5 Plus RE analyzer")
    parser.add_argument("firmware", type=Path, help="raw firmware .bin")
    parser.add_argument("--target", action="append", type=parse_int, default=[], help="RAM/Flash address to inspect (repeatable)")
    parser.add_argument("--json", dest="json_path", type=Path, default=None, help="write full JSON report")
    args = parser.parse_args()

    data = args.firmware.read_bytes()
    analyzer = ThumbREAnalyzer(data)
    targets = args.target or None
    report = analyzer.report(targets)

    fw = report["firmware"]
    vt = fw["vector_table"]
    print("=" * 72)
    print("XIAOMI 5 PLUS / BRIGHTWAY — EVIDENCE-FIRST RE")
    print("=" * 72)
    print(f"Firmware: {args.firmware}")
    print(f"Size:    {fw['size']} bytes")
    print(f"SHA-256: {fw['sha256']}")
    print(f"Vector:  {'PASS' if vt['valid'] else 'FAIL'}")
    if vt.get("reset_vector") is not None:
        print(f"Reset:   0x{vt['reset_address']:08X}")
    print(f"Reachable Thumb instructions: {report['reachable_code']['instruction_count']}")
    print()

    print("Speed hooks:")
    for item in report["speed_hooks"]:
        print(
            f"  [{item['confidence']}] file 0x{item['file_offset']:05X} "
            f"MCU 0x{item['address']:08X}: {item['message']}"
        )
    if not report["speed_hooks"]:
        print("  none")
    print()

    print("Mode-like comparisons (not automatically labelled):")
    for item in report["mode_candidates"][:60]:
        print(
            f"  [{item['confidence']}] file 0x{item['file_offset']:05X} "
            f"MCU 0x{item['address']:08X}: {item['message']} "
            f"({'; '.join(item['evidence'])})"
        )
    if not report["mode_candidates"]:
        print("  none")
    print()

    print("Target reports:")
    for target, details in report["addresses"].items():
        print(
            f"  {target}: literal_xrefs={len(details['literal_xrefs'])}, "
            f"readers={len(details['readers'])}, writers={len(details['writers'])}"
        )
        for writer in details["writers"][:12]:
            inst = writer["instruction"]
            print(
                f"    WRITE [{writer['confidence']}] "
                f"0x{inst['address']:08X} {inst['bytes_hex']:<12} "
                f"{inst['mnemonic']} {inst['op_str']} "
                f"base=0x{writer['resolved_base']:08X}"
            )
        for reader in details["readers"][:12]:
            inst = reader["instruction"]
            print(
                f"    READ  [{reader['confidence']}] "
                f"0x{inst['address']:08X} {inst['bytes_hex']:<12} "
                f"{inst['mnemonic']} {inst['op_str']} "
                f"base=0x{reader['resolved_base']:08X}"
            )

    if args.json_path:
        args.json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report: {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
