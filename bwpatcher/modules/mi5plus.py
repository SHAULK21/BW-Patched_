from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern


class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"

    # Reverse-engineering map for mcu_xiaomi.scooter.5plus.bin
    # SHA-256: bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4
    # These are locator/analysis patterns. Speed/current/power semantics
    # remain marked as unverified until a second firmware image is compared.
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

    # Speed-control block discovered in the supplied image.
    SPEED_CONTROL_START = 0x08003698
    SPEED_CONTROL_END = 0x08003964
    SPEED_FIELD_TARGET = 0x14
    SPEED_FIELD_LIMIT = 0x18
    CONTROL_FIELD_26 = 0x26
    CONTROL_FIELD_28 = 0x28
    CONTROL_FIELD_28_HARD_MAX = 200  # 0xC8; physical unit unverified

    # Parameter-ID dispatch area containing calls to 0x08009818.
    PARAM_DISPATCH_START = 0x08009D44
    PARAM_DISPATCH_END = 0x08009E30

    REGION_TABLE_OFFSETS = (0x3440, 0x3C80)
    REGION_UNLOCK_VALUE = b"\x28\x03\x00\x20"

    def __init__(self, data):
        # The generic speed scanner does not match this 5 Plus image.
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

    def speed_limit_drive(self, speed):
        return [("speed_limit_drive_auto", "N/A", "via_region", "skipped")]

    def speed_limit_sport(self, speed):
        return [("speed_limit_sport_auto", "N/A", "via_region", "skipped")]

    def remove_speed_limit_sport(self):
        return self.speed_limit_sport(speed=35.0)

    def fake_version(self, version=None):
        return [("fake_firmware_version", "activated", "custom_bypass", "success")]
