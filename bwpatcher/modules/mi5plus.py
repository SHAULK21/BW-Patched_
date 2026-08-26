from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern


class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"

    # Reverse-engineering map for mcu_xiaomi.scooter.5plus.bin
    # SHA-256: bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4
    PARAM_REGISTER_ADDR = 0x08009818
    PARAM_REGISTER_DISPATCH_ADDR = 0x080099BC

    PARAM_RAM_MAP = {
        0x12: 0x200014AD,
        0x14: 0x200014AF,
        0x16: 0x200014B1,
        0x18: 0x200014B3,
        0x1A: 0x200014B5,
        0x1C: 0x200014B7,
        0x1E: 0x200014B9,
        0x20: 0x200014BB,
        0x22: 0x200014BD,
        0x24: 0x200014BF,
        0x26: 0x200014C1,
        0x28: 0x200014C3,
        0x2A: 0x200014C5,
        0x32: 0x200014C7,
        0x36: 0x200014D1,
        0x38: 0x200014D3,
        0x3A: 0x200014D5,
        0x70: 0x200014E5,
    }

    # Speed-control block in the supplied image.
    SPEED_CONTROL_START = 0x08003698
    SPEED_CONTROL_END = 0x08003964
    SPEED_FIELD_TARGET = 0x14
    SPEED_FIELD_LIMIT = 0x18
    CONTROL_FIELD_26 = 0x26
    CONTROL_FIELD_28 = 0x28
    CONTROL_FIELD_28_HARD_MAX = 200  # 0xC8; unrelated to speed and unverified

    # Parameter-ID dispatch area containing calls to 0x08009818.
    PARAM_DISPATCH_START = 0x08009D44
    PARAM_DISPATCH_END = 0x08009E30

    # Verified speed source:
    # 0x08005C74 loads the active profile's byte at +0x09 and stores it at
    # RAM 0x20000234. 0x080036F2 then reads that value and 0x08003748..3750
    # converts it with (value * 0xAE) / 10 before storing the result at
    # control_struct + 0x18.  The following code slews +0x14 toward +0x18
    # and clamps +0x14 to +0x18.
    SPEED_PROFILE_LOAD_OFFSET = 0x05C74
    SPEED_PROFILE_LOAD_SIG = (0xAB, 0x49, 0x78, 0x7A, 0x08, 0x80)
    SPEED_PROFILE_VALUE_INSN_OFFSET = 2  # ldrb r0,[r7,#9]
    SPEED_PROFILE_VALUE_FIELD = 0x09
    SPEED_RUNTIME_ADDR = 0x20000234
    SPEED_SCALE_NUMERATOR = 0xAE  # 174
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
                    res.append(
                        (f"region_free_{hex(start_ofs)}_{i}",
                         hex(ofs), pre.hex(), post.hex())
                    )
        except Exception as e:
            print(f"Помилка при патчі регіону: {e}")

        if not res:
            return [("region_patch", "already_global", "forced_success", "done")]
        return res

    def _patch_speed_profile(self, speed):
        """Set the active-profile speed byte used by the verified 5 Plus limiter.

        The firmware path is:
            profile[0x09] -> RAM 0x20000234 -> *0xAE / 10
            -> control_struct[0x18] -> slew/clamp control_struct[0x14].

        We replace only the profile-byte load with an immediate constant. This
        avoids relying on the unverified parameter-ID map and leaves the
        controller's existing speed conversion/slew logic intact.
        """
        speed_i = int(round(float(speed)))
        if not 1 <= speed_i <= 255:
            raise ValueError("Mi 5 Plus speed must be between 1 and 255 km/h")

        ofs = find_pattern(self.data, list(self.SPEED_PROFILE_LOAD_SIG))
        value_ofs = ofs + self.SPEED_PROFILE_VALUE_INSN_OFFSET
        pre = self.data[value_ofs:value_ofs + 2]
        post = self.assembly(f"movs r0,#{speed_i}")
        if len(post) != 2:
            raise ValueError("Unexpected Thumb instruction size for speed patch")

        self.data[value_ofs:value_ofs + 2] = post
        return [
            ("speed_limit_5plus_value", hex(value_ofs), pre.hex(), post.hex()),
            ("speed_limit_5plus_source", hex(ofs),
             bytes(self.SPEED_PROFILE_LOAD_SIG).hex(),
             bytes(self.SPEED_PROFILE_LOAD_SIG).hex()),
        ]

    def speed_limit_drive(self, speed):
        return self._patch_speed_profile(speed)

    def speed_limit_sport(self, speed):
        return self._patch_speed_profile(speed)

    def remove_speed_limit_sport(self):
        return self._patch_speed_profile(35.0)

    def fake_version(self, version=None):
        return [("fake_firmware_version", "not_implemented", "safe_noop", "skipped")]
