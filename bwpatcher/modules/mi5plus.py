#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Electric Scooter 5 Plus / Brightway ES32.

This module is intentionally based ONLY on byte sequences verified against the
5 Plus firmware image available during reverse engineering:

SHA-256:
    bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4
Size:
    125371 bytes

Verified speed hook:
    file 0x5C74 / MCU 0x08005C74:
        AB 49 78 7A 08 80
    where +2 is:
        78 7A = LDRB r0,[r7,#9]
    and +4 is:
        08 80 = STRH r0,[r1]

IMPORTANT:
    No mode selector, profile table, region table, current limit or power
    limit is considered verified here unless its bytes were checked against
    the actual BIN. Earlier RE reports contained unverified addresses and
    must not be used as patch targets.
"""

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern, SignatureException


FLASH_BASE_ADDR = 0x08000000
FIRMWARE_SIZE = 125371
FIRMWARE_SHA256 = "bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4"

# Confirmed active-profile speed hook.
SPEED_HOOK_MCU = 0x08005C76
SPEED_HOOK_OFFSET = SPEED_HOOK_MCU - FLASH_BASE_ADDR
SPEED_HOOK_PREFIX = b"\xAB\x49"
SPEED_HOOK_SUFFIX = b"\x08\x80"
SPEED_HOOK_ORIGINAL = b"\x78\x7A"       # LDRB r0,[r7,#9]

# Runtime address used by the confirmed hook's STRH destination.
SPEED_RUNTIME_ADDR = 0x20000234
SPEED_PROFILE_FIELD = 0x09

# These are RE notes only. They are NOT patch targets.
MODE_CANDIDATE_ADDR = 0x20001E2C
MODE_CANDIDATE_STATUS = "UNVERIFIED"


class Mi5PlusPatcher(ES32Patcher):
    """Patcher for the verified Xiaomi 5 Plus ES32 speed hook.

    The firmware image exposes a common active-profile read at r7+0x09.
    Until the actual profile-selector data-flow is independently verified,
    Eco/Drive/Sport all deliberately use this same verified hook.
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
        """Return True only for the analysed image size/signature family."""
        if len(self.data) != FIRMWARE_SIZE:
            return False
        return self._find_speed_hook_raw() is not None

    def _find_speed_hook_raw(self):
        """Find the verified hook or its safe already-patched form."""
        data = bytes(self.data)
        candidates = []

        # Original: AB 49 78 7A 08 80
        sig = SPEED_HOOK_PREFIX + SPEED_HOOK_ORIGINAL + SPEED_HOOK_SUFFIX
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos < 0:
                break
            candidates.append((pos, "original", False))
            start = pos + 1

        # Already patched: AB 49 XX 20 08 80.
        # XX is the MOVS immediate. Keep the surrounding bytes fixed.
        start = 0
        while True:
            pos = data.find(SPEED_HOOK_PREFIX, start)
            if pos < 0:
                break
            if pos + 6 <= len(data) and data[pos + 3] == 0x20 and data[pos + 4:pos + 6] == SPEED_HOOK_SUFFIX:
                candidates.append((pos, "patched", True))
            start = pos + 1

        if not candidates:
            return None

        # The analysed hook has a fixed, known location. Prefer it, but refuse
        # an image where the same candidate exists elsewhere as well.
        expected = [c for c in candidates if c[0] == SPEED_HOOK_OFFSET]
        if len(expected) != 1:
            return None

        if len(candidates) != 1:
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
    # Diagnostics
    # ------------------------------------------------------------------
    def diagnose(self):
        print("=" * 64)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32")
        print("Verified-firmware diagnostic")
        print("=" * 64)
        print(f"Size: {len(self.data)} bytes (expected {FIRMWARE_SIZE})")
        print(f"Mode candidate: 0x{MODE_CANDIDATE_ADDR:08X} [{MODE_CANDIDATE_STATUS}]")
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
        # Thumb: MOVS r0,#imm8 => imm8 20
        return bytes((value, 0x20))

    def _patch_speed(self, kmh):
        if self.hook_offset is None:
            self.find_speed_hook()

        if self.hook_offset < 0:
            raise SignatureException("Mi 5 Plus: speed hook not found!")

        post = self._speed_opcode(kmh)
        pre = bytes(self.data[self.hook_offset:self.hook_offset + 2])

        # Accept only the original LDRB or an already-patched MOVS here.
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

    # Until the profile selector is independently verified, all three public
    # mode APIs use the same confirmed active-profile hook.
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
    # Safety: unverified patches are intentionally disabled.
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
