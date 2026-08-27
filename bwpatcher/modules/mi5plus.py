#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Electric Scooter 5 Plus / Brightway ES32.

This module is intentionally based ONLY on byte sequences verified against the
original 5 Plus firmware image used for reverse engineering:

SHA-256:
    bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4
Size:
    125371 bytes

CONFIRMED speed hook:
    file 0x5C74 / MCU 0x08005C74:
        AB 49 78 7A 08 80
    where +2 is:
        78 7A = LDRB r0,[r7,#9]
    and +4 is:
        08 80 = STRH r0,[r1]

CONFIRMED speed-control chain from the same original BIN:
    file 0x3698 / MCU 0x08003698
        control object = 0x20001E40
        runtime input = 0x20000234
        0x3746..0x3750: value * 0xAE, divide by 10
        0x3752: STRH r0,[control+0x18]
        0x3754..0x3788: update target control+0x14
        0x378C..0x3796: upper clamp target <= control+0x18

CONFIRMED special gate in this chain:
    MCU 0x0800373E reads byte 0x200002E5.
    If it equals 1, control+0x18 is forced to 435 (0x1B3), i.e. the
    same controller-unit value produced by 25 * 174 / 10.

IMPORTANT:
    Earlier AI-generated RE reports mixed real findings with fabricated
    addresses. In particular, 0x0800A412, 0x08005834, the claimed region
    tables at 0x3440/0x3C80, and the claimed mode mapping at 0x20001E2C
    were NOT accepted here without verification against this BIN.

MODE RESEARCH STATUS:
    0x20001E22 is a real RAM structure referenced by function 0x0800345C.
    At 0x0800352C/0x08003530 that function writes its field +0x0A
    (0x20001E2C). The field is therefore real and stateful, but its semantic
    mapping to Eco/Drive/Sport is still UNVERIFIED. The writer logic depends
    on other runtime state, so this module does not hard-code 0/1/2 meanings.
"""

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import SignatureException


FLASH_BASE_ADDR = 0x08000000
FIRMWARE_SIZE = 125371
FIRMWARE_SHA256 = "bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4"

# ---------------------------------------------------------------------------
# Confirmed speed path
# ---------------------------------------------------------------------------
SPEED_HOOK_MCU = 0x08005C76
SPEED_HOOK_OFFSET = SPEED_HOOK_MCU - FLASH_BASE_ADDR
SPEED_HOOK_PREFIX = b"\xAB\x49"
SPEED_HOOK_SUFFIX = b"\x08\x80"
SPEED_HOOK_ORIGINAL = b"\x78\x7A"       # LDRB r0,[r7,#9]
SPEED_RUNTIME_ADDR = 0x20000234
SPEED_PROFILE_FIELD = 0x09

# Confirmed speed-control object and fields.
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

# Confirmed mode-structure candidate. Semantic mapping remains unverified.
MODE_STRUCTURE_ADDR = 0x20001E22
MODE_FIELD_OFFSET = 0x0A
MODE_FIELD_ADDR = MODE_STRUCTURE_ADDR + MODE_FIELD_OFFSET
MODE_WRITER_MCU = 0x0800345C
MODE_MAPPING_STATUS = "UNVERIFIED"

# Known false/unverified claims deliberately retained only as audit notes.
REJECTED_RE_CLAIMS = {
    "claimed_mode_writer": 0x0800A412,
    "claimed_mode_init": 0x08005834,
    "claimed_region_table_1": 0x3440,
    "claimed_region_table_2": 0x3C80,
    "claimed_mode_selector": MODE_FIELD_ADDR,
}


class Mi5PlusPatcher(ES32Patcher):
    """Patcher for the verified Xiaomi 5 Plus ES32 speed hook.

    Eco/Drive/Sport currently all address the same confirmed active speed
    hook. This is intentional: the profile-selection semantics have not yet
    been proven from the original BIN.
    """

    def __init__(self, data):
        super().__init__(data)
        self.hook_offset = None
        self.hook_form = None
        self.current_speed = None

    # ------------------------------------------------------------------
    # Verified firmware identification
    # ------------------------------------------------------------------
    def verify_firmware(self):
        if len(self.data) != FIRMWARE_SIZE:
            return False
        return self._find_speed_hook_raw() is not None

    def _find_speed_hook_raw(self):
        """Find only the confirmed hook or its exact already-patched form."""
        data = bytes(self.data)
        candidates = []

        sig = SPEED_HOOK_PREFIX + SPEED_HOOK_ORIGINAL + SPEED_HOOK_SUFFIX
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos < 0:
                break
            candidates.append((pos, "original", False))
            start = pos + 1

        start = 0
        while True:
            pos = data.find(SPEED_HOOK_PREFIX, start)
            if pos < 0:
                break
            if (pos + 6 <= len(data)
                    and data[pos + 3] == 0x20
                    and data[pos + 4:pos + 6] == SPEED_HOOK_SUFFIX):
                candidates.append((pos, "patched", True))
            start = pos + 1

        if not candidates:
            return None

        expected = [c for c in candidates if c[0] == SPEED_HOOK_OFFSET]
        if len(expected) != 1 or len(candidates) != 1:
            return None
        return expected[0]

    def find_speed_hook(self):
        hit = self._find_speed_hook_raw()
        if hit is None:
            self.hook_offset = -1
            self.hook_form = None
            raise SignatureException(
                "Mi 5 Plus: verified speed hook not found. "
                "Expected file offset 0x5C74 / MCU 0x08005C74 "
                "(AB 49 78 7A 08 80) or its exact patched form."
            )

        pos, form, patched = hit
        self.hook_offset = pos + 2
        self.hook_form = form
        if patched:
            self.current_speed = self.data[self.hook_offset]
        return self.hook_offset

    # ------------------------------------------------------------------
    # Diagnostics / verified RE map
    # ------------------------------------------------------------------
    def reverse_engineering_map(self):
        return {
            "firmware_size": FIRMWARE_SIZE,
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
            "mode_writer_mcu": MODE_WRITER_MCU,
            "mode_mapping_status": MODE_MAPPING_STATUS,
        }

    def diagnose(self):
        print("=" * 68)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32")
        print("Verified-firmware diagnostic / RE map")
        print("=" * 68)
        print(f"Size: {len(self.data)} bytes (expected {FIRMWARE_SIZE})")
        print(f"Speed control: 0x{SPEED_CONTROL_START_MCU:08X}-0x{SPEED_CONTROL_END_MCU:08X}")
        print(f"Control object: 0x{SPEED_CONTROL_OBJECT:08X}")
        print(f"Scale: value * {SPEED_SCALE_NUMERATOR} / {SPEED_SCALE_DIVISOR}")
        print(f"Gate: 0x{SPEED_GATE_ADDR:08X} == {SPEED_GATE_TRIGGER} -> limit {SPEED_GATE_LIMIT}")
        print(f"Mode structure: 0x{MODE_STRUCTURE_ADDR:08X}")
        print(f"Mode field: 0x{MODE_FIELD_ADDR:08X} [{MODE_MAPPING_STATUS}]")
        try:
            ofs = self.find_speed_hook()
        except SignatureException as exc:
            print(f"[-] {exc}")
            return -1
        print(f"[+] Speed hook: file 0x{ofs:05X}, MCU 0x{FLASH_BASE_ADDR + ofs:08X}")
        print(f"    Form: {self.hook_form}")
        if self.current_speed is not None:
            print(f"    Current patched parameter: {self.current_speed}")
        return ofs

    # ------------------------------------------------------------------
    # Speed patch
    # ------------------------------------------------------------------
    @staticmethod
    def _speed_opcode(kmh):
        value = int(round(float(kmh)))
        if not 1 <= value <= 255:
            raise ValueError("Speed must be between 1 and 255 km/h")
        return bytes((value, 0x20))  # Thumb MOVS r0,#imm8

    def _patch_speed(self, kmh):
        if self.hook_offset is None:
            self.find_speed_hook()

        if self.hook_offset < 0:
            raise SignatureException("Mi 5 Plus: speed hook not found!")

        post = self._speed_opcode(kmh)
        pre = bytes(self.data[self.hook_offset:self.hook_offset + 2])

        if pre != SPEED_HOOK_ORIGINAL and not (pre[1:2] == b"\x20"):
            raise SignatureException(
                f"Mi 5 Plus: unexpected bytes at speed hook 0x{self.hook_offset:X}: {pre.hex()}"
            )

        if pre == post:
            return [("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex())]

        self.data[self.hook_offset:self.hook_offset + 2] = post
        self.current_speed = int(round(float(kmh)))
        self.hook_form = "patched"
        return [("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex())]

    def speed_limit_active_profile(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_ped(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_drive(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_sport(self, kmh):
        return self._patch_speed(kmh)

    def dashboard_max_speed(self, speed):
        return self._patch_speed(speed)

    def remove_speed_limit_sport(self):
        return self._patch_speed(255)

    # ------------------------------------------------------------------
    # Safety: unverified patches remain disabled.
    # ------------------------------------------------------------------
    def region_free(self):
        raise SignatureException(
            "Mi 5 Plus: region table is not verified against the supplied BIN; "
            "refusing to write guessed Flash addresses."
        )

    def fake_drv_version(self, firmware_version):
        raise SignatureException(
            "Mi 5 Plus: fake DRV version patch is not verified."
        )

    def fake_version(self, version=None):
        return self.fake_drv_version(version)

    def motor_start_speed(self, speed):
        return super().motor_start_speed(speed)


def patch_mi5plus(firmware_data, speed_kmh=35):
    """Small standalone entry point used by external scripts."""
    patcher = Mi5PlusPatcher(firmware_data)
    patcher.diagnose()
    patcher.speed_limit_active_profile(speed_kmh)
    return patcher.data
