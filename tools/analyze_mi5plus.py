#!/usr/bin/env python3
"""Run evidence-first static RE on a Xiaomi 5 Plus raw MCU image.

Example:
    python tools/analyze_mi5plus.py mcu_xiaomi.scooter.5plus.bin
    python tools/analyze_mi5plus.py firmware.bin --json report.json

The command never changes the firmware. It disassembles Thumb code, finds the
verified speed hook, resolves literal XREFs, looks for candidate writers and
mode-like comparisons, and writes a JSON report.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bwpatcher.re.thumb_re import ThumbREAnalyzer


DEFAULT_RANGES = (
    (0x0000, 0x6200),
    (0x9000, 0xA800),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidence-first Xiaomi 5 Plus RE analyzer")
    parser.add_argument("firmware", type=Path, help="raw firmware .bin")
    parser.add_argument("--start", type=lambda x: int(x, 0), default=None, help="single analysis start file offset")
    parser.add_argument("--end", type=lambda x: int(x, 0), default=None, help="single analysis end file offset")
    parser.add_argument("--json", dest="json_path", type=Path, default=None, help="write full JSON report")
    args = parser.parse_args()

    data = args.firmware.read_bytes()
    analyzer = ThumbREAnalyzer(data)

    ranges = DEFAULT_RANGES
    if args.start is not None:
        end = args.end if args.end is not None else len(data)
        ranges = ((args.start, end),)

    report = analyzer.report(ranges)

    fw = report["firmware"]
    print("=" * 72)
    print("XIAOMI 5 PLUS / BRIGHTWAY — EVIDENCE-FIRST RE")
    print("=" * 72)
    print(f"Firmware: {args.firmware}")
    print(f"Size:    {fw['size']} bytes")
    print(f"SHA-256: {fw['sha256']}")
    print(f"Vector table valid: {fw['vector_table']['valid']}")
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

    print("Mode-like CMP candidates:")
    for item in report["mode_candidates"][:40]:
        print(
            f"  [{item['confidence']}] file 0x{item['file_offset']:05X} "
            f"MCU 0x{item['address']:08X}: {item['message']} "
            f"({'; '.join(item['evidence'])})"
        )
    if not report["mode_candidates"]:
        print("  none")
    print()

    print("Target address reports:")
    for target, details in report["addresses"].items():
        xrefs = details["literal_xrefs"][target]
        writers = details["memory_writers"]
        print(f"  {target}: literal_xrefs={len(xrefs)}, writers={len(writers)}")
        for writer in writers[:10]:
            store = writer["store"]
            print(
                f"    writer {store['bytes_hex']} @ MCU 0x{store['address']:08X}: "
                f"{store['mnemonic']} {store['op_str']} "
                f"resolved_base=0x{writer['resolved_base']:08X}"
            )

    if args.json_path:
        args.json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report: {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
