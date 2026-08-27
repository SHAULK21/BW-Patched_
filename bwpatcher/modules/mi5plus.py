# ==============================================================================
# BWPATCHER MODULE: mi5plus.py
# Xiaomi Scooter 5 Plus (Brightway / ES32 MCU)
# Resilient speed hook + active-mode diagnostics
# ==============================================================================

import re
import struct

from bwpatcher.core_es32 import ES32Patcher

FLASH_BASE_ADDR = 0x08000000
MIN_FW_SIZE = 32 * 1024
MAX_FW_SIZE = 128 * 1024
SPEED_RUNTIME_ADDR = 0x20000234

# Verified pristine hook from the analysed 5 Plus image:
# 0x08005C74: AB 49 78 7A 08 80
# 0x08005C76: 78 7A = LDRB r0,[r7,#9]
# 0x08005C78: 08 80 = STRH r0,[r1]
PAT_PRISTINE_EXACT = b"\xAB\x49\x78\x7A\x08\x80"
PAT_FLEXIBLE_PC_REL = re.compile(b"(.)\x49\x78\x7A\x08\x80")
PAT_ALREADY_PATCHED = re.compile(b"(.)\x49(.)\x20\x08\x80")

# Candidate mode field established by the supplied RE report.
# 0=Eco/Ped, 1=Drive, 2=Sport. The field is a selector, not speed storage.
MODE_STRUCT_BASE = 0x20001E22
MODE_STRUCT_FIELD = 0x0A
MODE_STRUCT_ADDR = MODE_STRUCT_BASE + MODE_STRUCT_FIELD
MODE_WRITER_MCU = 0x0800A412
MODE_INIT_MCU = 0x08005834

# Speed-control block and active profile path from the RE report.
SPEED_CONTROL_START = 0x08003698
SPEED_CONTROL_END = 0x08003964
SPEED_PROFILE_LOAD_MCU = 0x08005C74
SPEED_PROFILE_LOAD_OFFSET = SPEED_PROFILE_LOAD_MCU - FLASH_BASE_ADDR
SPEED_PROFILE_VALUE_OFFSET = SPEED_PROFILE_LOAD_OFFSET + 2
SPEED_PROFILE_FIELD = 0x09
SPEED_SCALE_NUMERATOR = 174
SPEED_SCALE_DIVISOR = 10


class Mi5PlusPatcher(ES32Patcher):
    """Xiaomi Electric Scooter 5 Plus / Brightway ES32 patcher.

    The firmware uses an active-profile buffer. The riding mode selects the
    active profile, then the common hook reads profile+0x09. Therefore one
    verified hook is sufficient to override the active Eco/Drive/Sport limit.
    """

    def __init__(self, data):
        super().__init__(data)
        self.hook_offset = None
        self.hook_form = None
        self.current_speed = None
        self.is_already_patched = False
        self.mode = None

    # ------------------------------------------------------------------
    # Firmware fingerprint / diagnostics
    # ------------------------------------------------------------------
    def verify_fingerprint(self):
        if not (MIN_FW_SIZE <= len(self.data) <= MAX_FW_SIZE):
            return False
        if len(self.data) < 8:
            return False
        initial_sp = struct.unpack_from("<I", self.data, 0)[0]
        reset_vec = struct.unpack_from("<I", self.data, 4)[0]
        return (
            0x20000000 <= initial_sp <= 0x20008000
            and 0x08000000 <= (reset_vec & 0xFFFFFFFE) <= 0x08020000
        )

    @staticmethod
    def _valid_active_profile_ldr(base_byte):
        """Validate Thumb LDRB r0,[rN,#9] encoding used by the flexible hook.

        Encoding is 0111 imm5 Rn Rt. For Rt=0 and imm5=9, the low byte is
        0x40 + (Rn << 3), so only 0x40..0x78 in steps of 8 are accepted.
        This prevents the old generic regex from matching arbitrary bytes.
        """
        return 0x40 <= base_byte <= 0x78 and (base_byte & 0x07) == 0

    def _find_matches(self):
        data = bytes(self.data)
        matches = []

        # Exact / flexible PC-relative LDR r1 followed by the verified LDRB
        # and STRH. Require the complete six-byte instruction sequence.
        for pos in range(max(0, len(data) - 6 + 1)):
            if data[pos + 1] != 0x49:
                continue
            if data[pos + 3] != 0x7A:
                continue
            if data[pos + 4:pos + 6] != b"\x08\x80":
                continue
            if data[pos + 2] == 0x78:
                matches.append((pos, "Pristine/Flexible Active Profile [r7+9]", False))
            elif self._valid_active_profile_ldr(data[pos + 2]):
                matches.append((pos, "Flexible Active Profile [rN+9]", False))

        # Already patched form: same PC-relative LDR prefix, MOVS r0,#imm,
        # then the original STRH. Validate the MOVS encoding rather than
        # accepting arbitrary ?? 20 sequences.
        for pos in range(max(0, len(data) - 6 + 1)):
            if data[pos + 1] != 0x49:
                continue
            if data[pos + 3] != 0x20:
                continue
            if data[pos + 4:pos + 6] != b"\x08\x80":
                continue
            matches.append((pos, "Already patched Active Profile", True))

        # Prefer the exact analysed location when it is present.
        matches.sort(key=lambda x: (x[0] != SPEED_PROFILE_LOAD_OFFSET, x[0]))
        return matches

    def find_speed_hook(self):
        matches = self._find_matches()
        if not matches:
            self.hook_offset = -1
            self.hook_form = None
            return -1

        # A firmware may contain unrelated similar instructions. Only accept
        # one match, except when the exact known location is uniquely present.
        exact = [m for m in matches if m[0] == SPEED_PROFILE_LOAD_OFFSET]
        if exact:
            pos, form, patched = exact[0]
        elif len(matches) == 1:
            pos, form, patched = matches[0]
        else:
            self.hook_offset = -1
            raise RuntimeError(
                "Mi 5 Plus: ambiguous speed hook; refusing to patch "
                f"({len(matches)} candidate sequences found)."
            )

        self.hook_offset = pos + 2
        self.hook_form = form
        self.is_already_patched = patched
        if patched:
            self.current_speed = self.data[self.hook_offset]
        return self.hook_offset

    def _read_mode(self):
        """Best-effort static diagnostic for the mode selector.

        The value is runtime RAM and cannot be read from a raw firmware image.
        This method therefore reports the known selector mapping rather than
        pretending that the current scooter mode is present in the BIN.
        """
        return {
            0: "Eco/Ped",
            1: "Drive",
            2: "Sport",
        }

    def diagnose(self):
        print("=" * 60)
        print("XIAOMI 5 PLUS / BRIGHTWAY ES32 DIAGNOSTIC")
        print("=" * 60)
        print(f"Firmware size: {len(self.data)} bytes")
        print(f"Fingerprint: {'PASS' if self.verify_fingerprint() else 'FAIL'}")
        print(f"Mode selector: 0x{MODE_STRUCT_ADDR:08X}")
        print(f"  writer: 0x{MODE_WRITER_MCU:08X}")
        print("  mapping: 0=Eco/Ped, 1=Drive, 2=Sport")
        try:
            ofs = self.find_speed_hook()
        except RuntimeError as exc:
            print(f"[-] {exc}")
            return -1
        if ofs < 0:
            print("[-] Speed hook not found.")
            print(f"    Expected analysed location: file 0x{SPEED_PROFILE_LOAD_OFFSET:05X}")
            return -1
        print(f"[+] Speed hook: file 0x{ofs:05X}, MCU 0x{FLASH_BASE_ADDR + ofs:08X}")
        print(f"    Form: {self.hook_form}")
        if self.is_already_patched:
            print(f"    Status: already patched ({self.current_speed} km/h parameter)")
        else:
            print("    Status: factory/original instruction")
        return ofs

    # ------------------------------------------------------------------
    # Speed API required by CorePatcher
    # ------------------------------------------------------------------
    @staticmethod
    def _speed_opcode(kmh):
        value = int(round(float(kmh)))
        if not 1 <= value <= 255:
            raise ValueError("Speed must be between 1 and 255 km/h")
        return bytes((value, 0x20))

    def _patch_speed(self, kmh):
        if self.hook_offset is None:
            self.find_speed_hook()
        if self.hook_offset is None or self.hook_offset < 0:
            raise RuntimeError(
                "Mi 5 Plus: speed hook not found. This BIN does not match the "
                "analysed 5 Plus speed-hook family."
            )

        post = self._speed_opcode(kmh)
        pre = bytes(self.data[self.hook_offset:self.hook_offset + 2])
        if pre == post:
            return [("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex())]

        self.data[self.hook_offset:self.hook_offset + 2] = post
        self.is_already_patched = True
        self.current_speed = int(kmh)
        return [("speed_limit_active_profile", hex(self.hook_offset), pre.hex(), post.hex())]

    def speed_limit_active_profile(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_ped(self, kmh):
        # Mode-specific storage has not been found; the common active-profile
        # hook is the verified safe target.
        return self._patch_speed(kmh)

    def speed_limit_drive(self, kmh):
        return self._patch_speed(kmh)

    def speed_limit_sport(self, kmh):
        return self._patch_speed(kmh)

    def dashboard_max_speed(self, speed):
        # Dashboard display is not independently identified in this firmware.
        # Use the same verified speed path instead of guessing another field.
        return self._patch_speed(speed)

    def remove_speed_limit_sport(self):
        # No special Sport-only hook exists in the analysed active-profile path.
        # Use a high, explicit value through the verified common hook.
        return self._patch_speed(255)

    def region_free(self):
        unlock_val = b"\x28\x03\x00\x20"
        result = []
        for table_base in (0x3440, 0x3C80):
            for i in range(7):
                ofs = table_base + 4 * (i + 1)
                pre = bytes(self.data[ofs:ofs + 4])
                if pre != unlock_val:
                    self.data[ofs:ofs + 4] = unlock_val
                    result.append((f"region_{table_base:04X}_{i}", hex(ofs), pre.hex(), unlock_val.hex()))
        return result

    def fake_drv_version(self, firmware_version):
        return []

    def fake_version(self, version=None):
        return self.fake_drv_version(version)

    def motor_start_speed(self, speed):
        return super().motor_start_speed(speed)


# Standalone helper retained for scripts that import the module directly.
def patch_mi5plus(firmware_data, speed_kmh=35, region_free=True):
    patcher = Mi5PlusPatcher(firmware_data)
    patcher.diagnose()
    patcher.patch_speed(speed_kmh)
    if region_free:
        patcher.region_free()
    return patcher.data
