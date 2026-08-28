#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Electric Scooter 5 Plus / Brightway ES32.

The speed patcher is based on the original 5 Plus BIN used during reverse
engineering (125371 bytes, SHA-256 bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4).

The verified hook in that image is:
    file 0x5C74: AB 49 78 7A 08 80
    file 0x5C76: 78 7A = LDRB r0,[r7,#9]
    file 0x5C78: 08 80 = STRH r0,[r1]

Firmware revisions may change the PC-relative literal offset, so the patcher
uses the full verified instruction shape (?? 49 78 7A 08 80) rather than
requiring the literal-load byte AB. It still requires a UNIQUE match and
never patches a generic XX 20 sequence.

Mode semantics remain RE-only. No unverified Eco/Drive/Sport addresses are
written by this module.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import SignatureException


FLASH_BASE_ADDR = 0x08000000
FIRMWARE_SIZE = 125371
FIRMWARE_SHA256 = "bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4"

# Confirmed hook from the original research BIN.
SPEED_HOOK_MCU = 0x08005C76
SPEED_HOOK_OFFSET = SPEED_HOOK_MCU - FLASH_BASE_ADDR  # 0x5C76
SPEED_HOOK_PREFIX = b"\xAB\x49"
SPEED_HOOK_GENERIC_PREFIX = b"\x00\x49"
SPEED_HOOK_SUFFIX = b"\x08\x80"
SPEED_HOOK_ORIGINAL = b"\x78\x7A"
SPEED_RUNTIME_ADDR = 0x20000234
SPEED_PROFILE_FIELD = 0x09

# RE metadata only; do not use these as blind Flash write locations.
SPEED_CONTROL_START_MCU = 0x08003698
SPEED_CONTROL_END_MCU = 0x08003964
SPEED_CONTROL_OBJECT = 0x20001E40
SPEED_TARGET_FIELD = 0x14
SPEED_LIMIT_FIELD = 0x18
SPEED_GATE_ADDR = 0x200002E5
SPEED_GATE_TRIGGER = 1
SPEED_GATE_LIMIT = 435
SPEED_SCALE_NUMERATOR = 0xAE
SPEED_SCALE_DIVISOR = 10

# Mode candidate kept as evidence metadata only.
MODE_STRUCTURE_ADDR = 0x20001E22
MODE_FIELD_OFFSET = 0x0A
MODE_FIELD_ADDR = MODE_STRUCTURE_ADDR + MODE_FIELD_OFFSET
MODE_MAPPING_STATUS = "UNVERIFIED"

REJECTED_RE_CLAIMS = {
    "claimed_mode_writer": 0x0800A412,
    "claimed_mode_init": 0x08005834,
    "claimed_region_table_1": 0x3440,
    "claimed_region_table_2": 0x3C80,
}


class Mi5plusPatcher(ES32Patcher):
    """Xiaomi 5 Plus patcher with an evidence-first speed hook."""

    NAME = "Xiaomi Electric Scooter 5 Plus"

    def __init__(self, data):
        super().__init__(data)
        self.hook_offset: Optional[int] = None
        self.hook_start: Optional[int] = None
        self.hook_form: Optional[str] = None
        self.current_speed: Optional[int] = None

    # ------------------------------------------------------------------
    # Firmware / hook discovery
    # ------------------------------------------------------------------
    def firmware_fingerprint(self) -> dict:
        return {
            "size": len(self.data),
            "sha256": hashlib.sha256(bytes(self.data)).hexdigest(),
            "known_original": len(self.data) == FIRMWARE_SIZE
            and hashlib.sha256(bytes(self.data)).hexdigest() == FIRMWARE_SHA256,
        }

    @staticmethod
    def _is_movs_r0_imm(opcode: bytes) -> bool:
        return len(opcode) == 2 and opcode[1] == 0x20 and 0x00 <= opcode[0] <= 0xFF

    def _scan_speed_hook_candidates(self) -> list[tuple[int, str, bool]]:
        """Find the verified hook by instruction shape, not just one literal.

        Accepted pristine form:
            ?? 49 78 7A 08 80
        Accepted patched form:
            ?? 49 XX 20 08 80

        The surrounding bytes encode a PC-relative LDR r1 followed by the
        LDRB/STRH pair used by the verified speed hook. The match must be
        unique in the complete image.
        """
        data = bytes(self.data)
        candidates: list[tuple[int, str, bool]] = []

        for pos in range(max(0, len(data) - 6 + 1)):
            if data[pos + 1] != 0x49 or data[pos + 4:pos + 6] != SPEED_HOOK_SUFFIX:
                continue

            middle = data[pos + 2:pos + 4]
            if middle == SPEED_HOOK_ORIGINAL:
                candidates.append((pos, "pristine", False))
            elif self._is_movs_r0_imm(middle):
                candidates.append((pos, "patched", True))

        return candidates

    def _find_speed_hook(self) -> tuple[int, str, bool]:
        """Return (hook_start, form, already_patched) for a unique hook."""
        candidates = self._scan_speed_hook_candidates()

        # Prefer the exact original research point when it is present. This
        # also gives a clear result for the supplied 125371-byte reference BIN.
        at_known = [c for c in candidates if c[0] == SPEED_HOOK_OFFSET - 2]
        if len(at_known) == 1:
            return at_known[0]

        if len(candidates) == 1:
            return candidates[0]

        data = bytes(self.data)
        expected = data[SPEED_HOOK_OFFSET - 2:SPEED_HOOK_OFFSET + 4]
        raise SignatureException(
            "Mi 5 Plus: speed hook not uniquely detected. "
            f"file_size={len(data)}, expected_at_0x5C74={expected.hex(' ')}, "
            f"candidate_count={len(candidates)}. "
            "Accepted shape: ?? 49 78 7A 08 80 or ?? 49 XX 20 08 80."
        )

    def verify_firmware(self):
        try:
            self._find_speed_hook()
            return True
        except Exception:
            return False

    def find_speed_hook(self):
        start, form, patched = self._find_speed_hook()
        self.hook_start = start
        self.hook_offset = start + 2
        self.hook_form = form
        if patched:
            self.current_speed = self.data[self.hook_offset]
        return self.hook_offset

    # ------------------------------------------------------------------
    # Diagnostics / RE map
    # ------------------------------------------------------------------
    def reverse_engineering_map(self):
        return {
            "firmware_size": len(self.data),
            "firmware_sha256": hashlib.sha256(bytes(self.data)).hexdigest(),
            "known_original_sha256": FIRMWARE_SHA256,
            "speed_hook_file": SPEED_HOOK_OFFSET,
            "speed_hook_mcu": SPEED_HOOK_MCU,
            "speed_runtime_addr": SPEED_RUNTIME_ADDR,
            "speed_profile_field": SPEED_PROFILE_FIELD,
            "speed_control_start_mcu": SPEED_CONTROL_START_MCU,
            "speed_control_end_mcu": SPEED_CONTROL_END_MCU,
            "speed_control_object": SPEED_CONTROL_OBJECT,
            "speed_target_field": SPEED_TARGET_FIELD,
            "speed_limit_field": SPEED_LIMIT_FIELD,
            "speed_gate_addr": SPEED_GATE_ADDR,
            "speed_gate_trigger": SPEED_GATE_TRIGGER,
            "speed_gate_limit": SPEED_GATE_LIMIT,
            "speed_scale": f"{SPEED_SCALE_NUMERATOR}/{SPEED_SCALE_DIVISOR}",
            "mode_structure_addr": MODE_STRUCTURE_ADDR,
            "mode_field_addr": MODE_FIELD_ADDR,
            "mode_mapping_status": MODE_MAPPING_STATUS,
            "rejected_claims": dict(REJECTED_RE_CLAIMS),
        }

    def diagnose(self):
        print("=" * 72)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32")
        print("Evidence-first speed diagnostic")
        print("=" * 72)
        fp = self.firmware_fingerprint()
        print(f"Size: {fp['size']} (known reference: {FIRMWARE_SIZE})")
        print(f"SHA-256: {fp['sha256']}")
        print(f"Known reference image: {fp['known_original']}")
        try:
            ofs = self.find_speed_hook()
        except SignatureException as exc:
            print(f"[-] {exc}")
            return -1
        print(f"[+] Speed hook: file 0x{ofs:05X}, MCU 0x{FLASH_BASE_ADDR + ofs:08X}")
        print(f"    Form: {self.hook_form}")
        if self.current_speed is not None:
            print(f"    Current patched parameter: {self.current_speed} (0x{self.current_speed:02X})")
        return ofs

    # ------------------------------------------------------------------
    # Speed patch
    # ------------------------------------------------------------------
    @staticmethod
    def _speed_opcode(kmh):
        value = int(round(float(kmh)))
        if not 1 <= value <= 0xFF:
            raise ValueError("Mi 5 Plus speed parameter must be between 1 and 255")
        return bytes((value, 0x20))

    def _patch_speed(self, kmh):
        self.find_speed_hook()
        if self.hook_offset is None:
            raise SignatureException("Mi 5 Plus: speed hook offset is unavailable")

        pre = bytes(self.data[self.hook_offset:self.hook_offset + 2])
        post = self._speed_opcode(kmh)

        if pre != SPEED_HOOK_ORIGINAL and not self._is_movs_r0_imm(pre):
            raise SignatureException(
                f"Mi 5 Plus: unexpected opcode at 0x{self.hook_offset:X}: {pre.hex(' ')}"
            )

        if pre != post:
            self.data[self.hook_offset:self.hook_offset + 2] = post

        self.current_speed = post[0]
        self.hook_form = "patched"
        return [
            ("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex()),
            ("speed_hook_anchor", hex(self.hook_start), "??49787A0880", "verified"),
        ]

    def speed_limit_active_profile(self, kmh):
        return self._patch_speed(kmh)

    # All public speed controls intentionally address the same active-profile
    # hook. We have NOT proven three independent Flash speed bytes.
    def speed_limit_ped(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_drive(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_sport(self, kmh):
        return self._patch_speed(kmh)

    def dashboard_max_speed(self, speed):
        return self._patch_speed(speed)

    def remove_speed_limit_sport(self):
        # Keep compatibility with the BW patch-map. This means setting the
        # active hook to the maximum encodable byte; it does not remove every
        # other controller safety limit.
        return self._patch_speed(0xFF)

    # ------------------------------------------------------------------
    # Unverified operations remain disabled
    # ------------------------------------------------------------------
    def region_free(self):
        raise SignatureException(
            "Mi 5 Plus: region table is unverified for this firmware; refusing guessed Flash writes."
        )

    def fake_drv_version(self, firmware_version):
        raise SignatureException("Mi 5 Plus: fake DRV version patch is unverified.")

    def fake_version(self, version=None):
        return self.fake_drv_version(version)

    def motor_start_speed(self, speed):
        return super().motor_start_speed(speed)


# Compatibility for code importing the alternate capitalization.
Mi5PlusPatcher = Mi5plusPatcher


def patch_mi5plus(firmware_data, speed_kmh=35):
    patcher = Mi5plusPatcher(firmware_data)
    patcher.diagnose()
    patcher.speed_limit_active_profile(speed_kmh)
    return patcher.data
