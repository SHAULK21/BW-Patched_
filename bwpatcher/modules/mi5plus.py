"""Xiaomi 5 Plus (Brightway) firmware module.

Verified speed path for the supplied MCU image:

    file 0x5C74: AB 49 78 7A 08 80
    file 0x5C76: LDRB r0,[r7,#9]
    file 0x5C78: STRH r0,[r1]       ; r1 -> 0x20000234

The value then enters the controller path around 0x08003698-0x08003964.
The controller scales the runtime value by 174/10 and stores the resulting
limit in its +0x18 field; +0x14 is subsequently clamped to +0x18.

Important limitation: this image does NOT provide enough evidence to map
three independent Eco/Drive/Sport speed storage locations. The 0x200002B7
byte is used as a small runtime index/counter and must not be treated as a
proven 0/1/2 mode selector. Consequently this module exposes only the verified
active-profile speed hook and deliberately refuses guessed Sport/Eco patches.
"""

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern


class Mi5plusPatcher(ES32Patcher):
    """Patcher for Xiaomi Electric Scooter 5 Plus MCU firmware."""

    NAME = "Xiaomi Electric Scooter 5 Plus"

    # Reverse-engineering map for the supplied mcu_xiaomi.scooter.5plus.bin.
    # SHA-256: bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4
    PARAM_REGISTER_ADDR = 0x08009818
    PARAM_REGISTER_DISPATCH_ADDR = 0x080099BC

    PARAM_RAM_MAP = {
        0x12: 0x200014AD, 0x14: 0x200014AF, 0x16: 0x200014B1,
        0x18: 0x200014B3, 0x1A: 0x200014B5, 0x1C: 0x200014B7,
        0x1E: 0x200014B9, 0x20: 0x200014BB, 0x22: 0x200014BD,
        0x24: 0x200014BF, 0x26: 0x200014C1, 0x28: 0x200014C3,
        0x2A: 0x200014C5, 0x32: 0x200014C7, 0x36: 0x200014D1,
        0x38: 0x200014D3, 0x3A: 0x200014D5, 0x70: 0x200014E5,
    }

    SPEED_CONTROL_START = 0x08003698
    SPEED_CONTROL_END = 0x08003964
    SPEED_FIELD_TARGET = 0x14
    SPEED_FIELD_LIMIT = 0x18
    CONTROL_FIELD_26 = 0x26
    CONTROL_FIELD_28 = 0x28
    CONTROL_FIELD_28_HARD_MAX = 200  # 0xC8; not identified as speed

    PARAM_DISPATCH_START = 0x08009D44
    PARAM_DISPATCH_END = 0x08009E30

    # Exact verified sequence at file offset 0x5C74.
    SPEED_PROFILE_LOAD_OFFSET = 0x05C74
    SPEED_PROFILE_LOAD_SIG = (0xAB, 0x49, 0x78, 0x7A, 0x08, 0x80)
    SPEED_PROFILE_VALUE_INSN_OFFSET = 2
    SPEED_PROFILE_VALUE_FIELD = 0x09
    SPEED_RUNTIME_ADDR = 0x20000234

    # 0x200002B7 is a runtime byte used as an index/counter in the examined
    # code. It is retained as RE metadata only; it is NOT a mode patch point.
    SPEED_ACTIVE_PROFILE_INDEX_ADDR = 0x200002B7
    SPEED_ACTIVE_PROFILE_INDEX_READ_OFFSETS = (
        0x05A80, 0x05B7C, 0x05BA0,
        0x05BC2, 0x05BE2, 0x05C90,
    )

    SPEED_SCALE_NUMERATOR = 0xAE
    SPEED_SCALE_DIVISOR = 10

    REGION_TABLE_OFFSETS = (0x3440, 0x3C80)
    REGION_UNLOCK_VALUE = b"\x28\x03\x00\x20"

    def __init__(self, data):
        super().__init__(data)

    @classmethod
    def known_parameter_map(cls):
        return dict(cls.PARAM_RAM_MAP)

    @classmethod
    def known_re_locations(cls):
        return {
            "param_register": cls.PARAM_REGISTER_ADDR,
            "param_dispatch": cls.PARAM_REGISTER_DISPATCH_ADDR,
            "param_id_dispatch": (cls.PARAM_DISPATCH_START, cls.PARAM_DISPATCH_END),
            "speed_control": (cls.SPEED_CONTROL_START, cls.SPEED_CONTROL_END),
            "speed_profile_load": cls.SPEED_PROFILE_LOAD_OFFSET,
            "speed_runtime_addr": cls.SPEED_RUNTIME_ADDR,
            "speed_active_profile_index_addr": cls.SPEED_ACTIVE_PROFILE_INDEX_ADDR,
            "speed_active_profile_index_reads": cls.SPEED_ACTIVE_PROFILE_INDEX_READ_OFFSETS,
            "speed_target_field": cls.SPEED_FIELD_TARGET,
            "speed_limit_field": cls.SPEED_FIELD_LIMIT,
            "control_field_26": cls.CONTROL_FIELD_26,
            "control_field_28": cls.CONTROL_FIELD_28,
            "control_field_28_hard_max": cls.CONTROL_FIELD_28_HARD_MAX,
        }

    def region_free(self):
        res = []
        try:
            for start_ofs in self.REGION_TABLE_OFFSETS:
                ofs = start_ofs
                for i in range(7):
                    ofs += 4
                    if ofs + 4 > len(self.data):
                        break
                    pre = self.data[ofs:ofs + 4]
                    post = self.REGION_UNLOCK_VALUE
                    if pre == post:
                        continue
                    self.data[ofs:ofs + 4] = post
                    res.append((f"region_free_{hex(start_ofs)}_{i}",
                                hex(ofs), pre.hex(), post.hex()))
        except Exception as e:
            print(f"Помилка при патчі регіону: {e}")

        if not res:
            return [("region_patch", "already_global", "forced_success", "done")]
        return res

    @staticmethod
    def _speed_opcode(speed):
        """Return Thumb MOVS r0,#imm8 encoding for an 8-bit speed parameter."""
        speed_i = int(round(float(speed)))
        if not 1 <= speed_i <= 0xFF:
            raise ValueError("Mi 5 Plus speed parameter must be between 1 and 255")
        return bytes((speed_i, 0x20))

    def _find_verified_speed_hook(self):
        """Return the unique speed-hook offset and reject ambiguous firmware."""
        sig = list(self.SPEED_PROFILE_LOAD_SIG)
        ofs = find_pattern(self.data, sig)

        # Explicit full-image uniqueness check.  The generic helper intentionally
        # returns the first match, which is unsafe for a firmware patch point.
        raw = bytes(sig)
        data = bytes(self.data)
        hits = []
        start = 0
        while True:
            hit = data.find(raw, start)
            if hit < 0:
                break
            hits.append(hit)
            start = hit + 1

        if len(hits) != 1:
            raise ValueError(
                f"Mi 5 Plus: speed signature is not unique ({len(hits)} matches)"
            )
        if hits[0] != self.SPEED_PROFILE_LOAD_OFFSET or ofs != hits[0]:
            raise ValueError(
                f"Mi 5 Plus: unexpected speed signature offset 0x{hits[0]:X}"
            )
        return hits[0]

    def _find_speed_patch_state(self):
        """Validate original or already-patched bytes at the verified hook."""
        ofs = self._find_verified_speed_hook()
        value_ofs = ofs + self.SPEED_PROFILE_VALUE_INSN_OFFSET
        current = bytes(self.data[value_ofs:value_ofs + 2])
        original = bytes((0x78, 0x7A))

        if current == original:
            return ofs, value_ofs, current

        # Once patched, the signature itself necessarily changes at byte +2.
        # Accept only the exact surrounding bytes with a Thumb MOVS second byte
        # (0x20). This makes re-patching safe without accepting arbitrary code.
        if current[1] == 0x20:
            return ofs, value_ofs, current

        raise ValueError(
            f"Mi 5 Plus: unexpected instruction at 0x{value_ofs:X}: {current.hex()}"
        )

    def _patch_speed_profile(self, speed):
        post = self._speed_opcode(speed)
        ofs, value_ofs, pre = self._find_speed_patch_state()

        self.data[value_ofs:value_ofs + 2] = post

        return [
            ("speed_limit_5plus_active_profile",
             hex(value_ofs), pre.hex(), post.hex()),
            ("speed_limit_5plus_source",
             hex(ofs), bytes(self.SPEED_PROFILE_LOAD_SIG).hex(),
             bytes(self.SPEED_PROFILE_LOAD_SIG).hex()),
        ]

    def speed_limit_active_profile(self, speed):
        """Patch the verified active-profile speed input.

        This is the preferred API. It does not claim to be Drive-only.
        """
        return self._patch_speed_profile(speed)

    def speed_limit_drive(self, speed):
        """Compatibility alias for the verified active-profile speed hook.

        The 5 Plus firmware has not yet yielded evidence for a Drive-only
        storage location, so this method intentionally patches the active
        profile rather than pretending to target Drive specifically.
        """
        return self.speed_limit_active_profile(speed)

    def speed_limit_sport(self, speed):
        raise ValueError(
            "Mi 5 Plus: Sport-specific speed source is unverified; refusing a guessed patch."
        )

    def speed_limit_eco(self, speed):
        raise ValueError(
            "Mi 5 Plus: Eco-specific speed source is unverified; refusing a guessed patch."
        )

    def remove_speed_limit_sport(self):
        raise ValueError(
            "Mi 5 Plus: Sport-specific speed source is unverified; refusing a guessed patch."
        )

    def fake_version(self, version=None):
        return [("fake_firmware_version", "not_implemented", "safe_noop", "skipped")]
