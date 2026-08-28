#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Electric Scooter 5 Plus / Brightway ES32.

This module is intentionally based ONLY on byte sequences verified against the
original 5 Plus firmware image used for reverse engineering.

The dispatcher in bwpatcher/utils.py resolves a model named ``mi5plus`` to the
class name ``Mi5plusPatcher`` via ``model.capitalize()``.  Keep that exact
class name (and the backward-compatible alias below).
"""

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import SignatureException


FLASH_BASE_ADDR = 0x08000000
FIRMWARE_SIZE = 125371
FIRMWARE_SHA256 = "bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4"

# Confirmed speed hook for the supplied pristine BIN.
SPEED_HOOK_MCU = 0x08005C76
SPEED_HOOK_OFFSET = SPEED_HOOK_MCU - FLASH_BASE_ADDR  # 0x5C76
SPEED_HOOK_PREFIX = b"\xAB\x49"
SPEED_HOOK_SUFFIX = b"\x08\x80"
SPEED_HOOK_ORIGINAL = b"\x78\x7A"  # LDRB r0,[r7,#9]
SPEED_RUNTIME_ADDR = 0x20000234
SPEED_PROFILE_FIELD = 0x09

# These values are retained as RE metadata only. They are not used to perform
# an unsafe write unless the corresponding bytecode is independently verified.
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

# Mode structure is still RE-only metadata. Do not assign 0/1/2 semantics here.
MODE_STRUCTURE_ADDR = 0x20001E22
MODE_FIELD_OFFSET = 0x0A
MODE_FIELD_ADDR = MODE_STRUCTURE_ADDR + MODE_FIELD_OFFSET
MODE_MAPPING_STATUS = "UNVERIFIED"

# Explicitly rejected earlier AI-generated claims; useful for audit/debugging.
REJECTED_RE_CLAIMS = {
    "claimed_mode_writer": 0x0800A412,
    "claimed_mode_init": 0x08005834,
    "claimed_region_table_1": 0x3440,
    "claimed_region_table_2": 0x3C80,
}


class Mi5plusPatcher(ES32Patcher):
    """Patcher for the verified Xiaomi 5 Plus ES32 speed hook."""

    NAME = "Xiaomi Electric Scooter 5 Plus"

    def __init__(self, data):
        super().__init__(data)
        self.hook_offset = None
        self.hook_form = None
        self.current_speed = None

    # ------------------------------------------------------------------
    # Firmware identification / speed-hook discovery
    # ------------------------------------------------------------------
    def verify_firmware(self):
        """Return True only when the expected 5 Plus size and hook are present."""
        return len(self.data) == FIRMWARE_SIZE and self._find_speed_hook() is not None

    def _find_speed_hook(self):
        """Find the unique pristine or already-patched form of the verified hook.

        Accepted forms:
          AB 49 78 7A 08 80  (pristine)
          AB 49 XX 20 08 80  (our Thumb MOVS patch)

        No generic ``XX 20`` search is performed without the surrounding
        signature, preventing unrelated code from being modified.
        """
        data = bytes(self.data)
        candidates = []
        pristine = SPEED_HOOK_PREFIX + SPEED_HOOK_ORIGINAL + SPEED_HOOK_SUFFIX

        start = 0
        while True:
            pos = data.find(pristine, start)
            if pos < 0:
                break
            candidates.append((pos, "pristine", False))
            start = pos + 1

        start = 0
        while True:
            pos = data.find(SPEED_HOOK_PREFIX, start)
            if pos < 0:
                break
            if pos + 6 <= len(data):
                middle = data[pos + 2:pos + 4]
                if middle[1] == 0x20 and data[pos + 4:pos + 6] == SPEED_HOOK_SUFFIX:
                    candidates.append((pos, "patched", True))
            start = pos + 1

        if len(candidates) != 1:
            return None
        pos, form, patched = candidates[0]
        if pos != SPEED_HOOK_OFFSET:
            return None
        return (pos, form, patched)

    # Backwards-compatible name used by older callers/tests.
    def find_speed_hook(self):
        hit = self._find_speed_hook()
        if hit is None:
            self.hook_offset = -1
            self.hook_form = None
            raise SignatureException(
                "Mi 5 Plus: verified speed hook not found. Expected file offset "
                "0x5C74 / MCU 0x08005C74: AB 49 78 7A 08 80 (or exact patched form)."
            )
        pos, form, patched = hit
        self.hook_offset = pos + 2
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
            "expected_firmware_size": FIRMWARE_SIZE,
            "firmware_sha256": FIRMWARE_SHA256,
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
        print("=" * 68)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32")
        print("Verified-firmware diagnostic / RE map")
        print("=" * 68)
        print(f"Size: {len(self.data)} bytes (expected {FIRMWARE_SIZE})")
        print(f"Speed hook anchor: file 0x{SPEED_HOOK_OFFSET:05X}")
        print(f"Speed runtime: 0x{SPEED_RUNTIME_ADDR:08X}")
        print(f"Mode field candidate: 0x{MODE_FIELD_ADDR:08X} [{MODE_MAPPING_STATUS}]")
        try:
            ofs = self.find_speed_hook()
        except SignatureException as exc:
            print(f"[-] {exc}")
            return -1
        print(f"[+] Speed hook: file 0x{ofs:05X}, MCU 0x{FLASH_BASE_ADDR + ofs:08X}")
        print(f"    Form: {self.hook_form}")
        if self.current_speed is not None:
            print(f"    Current patched byte: {self.current_speed} (0x{self.current_speed:02X})")
        return ofs

    # ------------------------------------------------------------------
    # Speed patch
    # ------------------------------------------------------------------
    @staticmethod
    def _speed_opcode(kmh):
        value = int(round(float(kmh)))
        if not 1 <= value <= 0xFF:
            raise ValueError("Mi 5 Plus speed parameter must be between 1 and 255")
        return bytes((value, 0x20))  # Thumb MOVS r0,#imm8

    def _patch_speed(self, kmh):
        _, value_ofs, pre = self.find_speed_hook(), self.hook_offset, None
        pre = bytes(self.data[value_ofs:value_ofs + 2])
        post = self._speed_opcode(kmh)
        if pre != SPEED_HOOK_ORIGINAL and pre[1:2] != b"\x20":
            raise SignatureException(
                f"Mi 5 Plus: unexpected opcode at 0x{value_ofs:X}: {pre.hex()}"
            )
        if pre != post:
            self.data[value_ofs:value_ofs + 2] = post
        self.current_speed = post[0]
        self.hook_form = "patched"
        return [("speed_limit_active_profile", hex(value_ofs), pre.hex(), post.hex())]

    def speed_limit_active_profile(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_ped(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_drive(self, kmh):
        # The BIN has not yielded a separate Drive-only speed byte.
        return self._patch_speed(kmh)

    def speed_limit_sport(self, kmh):
        # The BIN has not yielded a separate Sport-only speed byte.
        return self._patch_speed(kmh)

    def dashboard_max_speed(self, speed):
        return self._patch_speed(speed)

    def remove_speed_limit_sport(self):
        return self._patch_speed(0xFF)

    # ------------------------------------------------------------------
    # Safety: unverified operations remain disabled.
    # ------------------------------------------------------------------
    def region_free(self):
        raise SignatureException(
            "Mi 5 Plus: region table is unverified for this firmware; refusing guessed writes."
        )

    def fake_drv_version(self, firmware_version):
        raise SignatureException(
            "Mi 5 Plus: fake DRV version patch is unverified."
        )

    def fake_version(self, version=None):
        return self.fake_drv_version(version)

    def motor_start_speed(self, speed):
        return super().motor_start_speed(speed)


# Explicit alias for callers that use Python naming rather than the historical
# dispatcher convention (``Mi5plusPatcher``).
Mi5PlusPatcher = Mi5plusPatcher


def patch_mi5plus(firmware_data, speed_kmh=35):
    """Standalone helper used by external scripts."""
    patcher = Mi5plusPatcher(firmware_data)
    patcher.diagnose()
    patcher.speed_limit_active_profile(speed_kmh)
    return patcher.data
