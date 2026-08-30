#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Electric Scooter 5 Plus / Brightway ES32.

The speed patcher is based on the original 5 Plus BIN used during reverse
engineering (125371 bytes, SHA-256 bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4).

Confirmed reference hook in that image:
    file 0x5C74: AB 49 78 7A 08 80
    file 0x5C76: 78 7A = LDRB r0,[r7,#9]
    file 0x5C78: 08 80 = STRH r0,[r1]

The module uses the verified 5 Plus container CRC format and keeps mode
semantics evidence-only until a concrete value can be traced from input to
control path.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import SignatureException


FLASH_BASE_ADDR = 0x08000000
FIRMWARE_SIZE = 125371
FIRMWARE_SHA256 = "bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4"

# Confirmed speed hook.
SPEED_HOOK_MCU = 0x08005C76
SPEED_HOOK_OFFSET = SPEED_HOOK_MCU - FLASH_BASE_ADDR
SPEED_HOOK_PREFIX = b"\xAB\x49"
SPEED_HOOK_SUFFIX = b"\x08\x80"
SPEED_HOOK_ORIGINAL = b"\x78\x7A"  # LDRB r0,[r7,#9]
SPEED_RUNTIME_ADDR = 0x20000234
SPEED_PROFILE_FIELD = 0x09

# Confirmed controller metadata from the reference BIN.
SPEED_CONTROL_START_MCU = 0x08003698
SPEED_CONTROL_END_MCU = 0x08003964
SPEED_CONTROL_OBJECT = 0x20001E40
SPEED_TARGET_FIELD = 0x14
SPEED_LIMIT_FIELD = 0x18

# Runtime byte is confirmed as a controller input/check, but its application
# semantics are not proven. In particular, do NOT encode "==1 -> 435" here.
SPEED_STATE_BYTE_ADDR = 0x200002E5
SPEED_STATE_BYTE_STATUS = "SEMANTICS_UNVERIFIED"
SPEED_SCALE_NUMERATOR = 0xAE
SPEED_SCALE_DIVISOR = 10

# Mode research only. No mode semantics are used for patching.
MODE_STRUCTURE_ADDR = 0x20001E22
MODE_FIELD_OFFSET = 0x0A
MODE_FIELD_ADDR = MODE_STRUCTURE_ADDR + MODE_FIELD_OFFSET
MODE_MAPPING_STATUS = "UNVERIFIED"

REJECTED_RE_CLAIMS = {
    "claimed_mode_writer": 0x0800A412,
    "claimed_mode_init": 0x08005834,
    "claimed_region_table_1": 0x3440,
    "claimed_region_table_2": 0x3C80,
    "claimed_0x200002E5_semantics": "value==1 -> 435 (rejected)",
}

# Verified 5 Plus container CRC-16.
CONTAINER_MARKER = b"SZMC-ES-02664-LQ"
CRC_SIZE_FIELD_OFFSET = -0x0A       # marker - 0x0A = file 0x86
CRC_VALUE_OFFSET_FROM_MARKER = 0x20 # marker + 0x20 = file 0xB0
CRC_DATA_OFFSET_FROM_MARKER = 0x70  # marker + 0x70 = file 0x100
CRC_POLY = 0x1021
CRC_INIT = 0x0000
CRC_XOROUT = 0x0000


class Mi5plusPatcher(ES32Patcher):
    """Xiaomi 5 Plus patcher with verified speed hook and container CRC."""

    NAME = "Xiaomi Electric Scooter 5 Plus"

    def __init__(self, data):
        super().__init__(data)
        self.hook_offset: Optional[int] = None
        self.hook_start: Optional[int] = None
        self.hook_form: Optional[str] = None
        self.current_speed: Optional[int] = None

    # ------------------------------------------------------------------
    # Firmware identity / speed hook
    # ------------------------------------------------------------------
    def firmware_fingerprint(self) -> dict:
        sha = hashlib.sha256(bytes(self.data)).hexdigest()
        return {
            "size": len(self.data),
            "sha256": sha,
            "known_original": len(self.data) == FIRMWARE_SIZE and sha == FIRMWARE_SHA256,
        }

    @staticmethod
    def _is_movs_r0_imm(opcode: bytes) -> bool:
        return len(opcode) == 2 and opcode[1] == 0x20

    def _scan_speed_hook_candidates(self):
        data = bytes(self.data)
        candidates = []
        for pos in range(0, max(0, len(data) - 5)):
            if data[pos + 1] != 0x49 or data[pos + 4:pos + 6] != SPEED_HOOK_SUFFIX:
                continue
            middle = data[pos + 2:pos + 4]
            if middle == SPEED_HOOK_ORIGINAL:
                candidates.append((pos, "pristine", False))
            elif self._is_movs_r0_imm(middle):
                candidates.append((pos, "patched", True))
        return candidates

    def _find_speed_hook(self):
        candidates = self._scan_speed_hook_candidates()
        known = [c for c in candidates if c[0] == SPEED_HOOK_OFFSET - 2]
        if len(known) == 1:
            return known[0]
        if len(candidates) == 1:
            return candidates[0]

        data = bytes(self.data)
        expected = data[SPEED_HOOK_OFFSET - 2:SPEED_HOOK_OFFSET + 4]
        raise SignatureException(
            "Mi 5 Plus: speed hook not uniquely detected. "
            f"file_size={len(data)}, expected_at_0x5C74={expected.hex(' ')}, "
            f"candidate_count={len(candidates)}. "
            "Expected shape: ?? 49 78 7A 08 80 or ?? 49 XX 20 08 80."
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
        self.current_speed = self.data[self.hook_offset] if patched else None
        return self.hook_offset

    # ------------------------------------------------------------------
    # 5 Plus container CRC-16
    # ------------------------------------------------------------------
    @staticmethod
    def _crc16_ccitt(data: bytes) -> int:
        crc = CRC_INIT
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ CRC_POLY) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc ^ CRC_XOROUT

    def _container_layout(self):
        marker = bytes(self.data).find(CONTAINER_MARKER)
        if marker < 0:
            raise SignatureException("Mi 5 Plus: container marker SZMC-ES-02664-LQ not found")

        size_pos = marker + CRC_SIZE_FIELD_OFFSET
        crc_pos = marker + CRC_VALUE_OFFSET_FROM_MARKER
        data_start = marker + CRC_DATA_OFFSET_FROM_MARKER

        if size_pos < 0 or size_pos + 2 > len(self.data):
            raise SignatureException("Mi 5 Plus: invalid CRC size field location")
        if crc_pos < 0 or crc_pos + 2 > len(self.data):
            raise SignatureException("Mi 5 Plus: invalid CRC storage location")

        region_size = int.from_bytes(self.data[size_pos:size_pos + 2], "big")
        data_end = data_start + region_size
        if data_end > len(self.data):
            raise SignatureException(
                f"Mi 5 Plus: CRC protected range exceeds firmware: 0x{data_start:X}:0x{data_end:X}"
            )

        return marker, region_size, data_start, data_end, crc_pos

    def fix_checksum(self):
        """Recalculate the confirmed 5 Plus container CRC-16."""
        marker, region_size, data_start, data_end, crc_pos = self._container_layout()
        old = bytes(self.data[crc_pos:crc_pos + 2])
        new_crc = self._crc16_ccitt(bytes(self.data[data_start:data_end]))
        post = new_crc.to_bytes(2, "big")
        self.data[crc_pos:crc_pos + 2] = post
        return [("fix_checksum_5plus", hex(crc_pos), old.hex(), post.hex())]

    def verify_checksum(self):
        marker, region_size, data_start, data_end, crc_pos = self._container_layout()
        stored = int.from_bytes(self.data[crc_pos:crc_pos + 2], "big")
        computed = self._crc16_ccitt(bytes(self.data[data_start:data_end]))
        return {
            "marker_offset": marker,
            "region_size": region_size,
            "data_start": data_start,
            "data_end": data_end,
            "crc_offset": crc_pos,
            "stored": stored,
            "computed": computed,
            "valid": stored == computed,
        }

    # ------------------------------------------------------------------
    # Diagnostics / RE map
    # ------------------------------------------------------------------
    def reverse_engineering_map(self):
        fp = self.firmware_fingerprint()
        return {
            **fp,
            "speed_hook_file": SPEED_HOOK_OFFSET,
            "speed_hook_mcu": SPEED_HOOK_MCU,
            "speed_runtime_addr": SPEED_RUNTIME_ADDR,
            "speed_profile_field": SPEED_PROFILE_FIELD,
            "speed_control_start_mcu": SPEED_CONTROL_START_MCU,
            "speed_control_end_mcu": SPEED_CONTROL_END_MCU,
            "speed_control_object": SPEED_CONTROL_OBJECT,
            "speed_target_field": SPEED_TARGET_FIELD,
            "speed_limit_field": SPEED_LIMIT_FIELD,
            "speed_state_byte_addr": SPEED_STATE_BYTE_ADDR,
            "speed_state_byte_status": SPEED_STATE_BYTE_STATUS,
            "speed_scale": f"{SPEED_SCALE_NUMERATOR}/{SPEED_SCALE_DIVISOR}",
            "mode_structure_addr": MODE_STRUCTURE_ADDR,
            "mode_field_addr": MODE_FIELD_ADDR,
            "mode_mapping_status": MODE_MAPPING_STATUS,
            "rejected_claims": dict(REJECTED_RE_CLAIMS),
        }

    def diagnose(self):
        print("=" * 72)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32")
        print("Evidence-first speed / CRC diagnostic")
        print("=" * 72)
        fp = self.firmware_fingerprint()
        print(f"Size: {fp['size']} (reference {FIRMWARE_SIZE})")
        print(f"SHA-256: {fp['sha256']}")
        print(f"Reference image: {fp['known_original']}")
        try:
            ofs = self.find_speed_hook()
            print(f"[+] Speed hook: file 0x{ofs:05X}, MCU 0x{FLASH_BASE_ADDR + ofs:08X}")
            print(f"    Form: {self.hook_form}")
        except SignatureException as exc:
            print(f"[-] {exc}")
        try:
            crc = self.verify_checksum()
            print(
                f"[CRC] stored=0x{crc['stored']:04X} computed=0x{crc['computed']:04X} "
                f"valid={crc['valid']} range=[0x{crc['data_start']:X}:0x{crc['data_end']:X}]"
            )
        except SignatureException as exc:
            print(f"[CRC] [-] {exc}")
        return self.hook_offset if self.hook_offset is not None else -1

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
        pre = bytes(self.data[self.hook_offset:self.hook_offset + 2])
        post = self._speed_opcode(kmh)
        if pre != SPEED_HOOK_ORIGINAL and not self._is_movs_r0_imm(pre):
            raise SignatureException(
                f"Mi 5 Plus: unexpected opcode at 0x{self.hook_offset:X}: {pre.hex(' ')}"
            )

        if pre != post:
            self.data[self.hook_offset:self.hook_offset + 2] = post

        # Speed hook is inside the verified protected range, so keep the
        # container CRC valid even when the caller did not request `chk`.
        crc_result = self.fix_checksum()

        self.current_speed = post[0]
        self.hook_form = "patched"
        return [
            ("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex()),
            ("speed_hook_anchor", hex(self.hook_start), "??49787A0880", "verified"),
            *crc_result,
        ]

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


Mi5PlusPatcher = Mi5plusPatcher


def patch_mi5plus(firmware_data, speed_kmh=35):
    patcher = Mi5plusPatcher(firmware_data)
    patcher.diagnose()
    patcher.speed_limit_active_profile(speed_kmh)
    return patcher.data
