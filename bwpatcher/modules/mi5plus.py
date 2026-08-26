from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern, SignatureException


class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"

    # Reverse-engineering map for the supplied 5 Plus MCU image.
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

    # Candidate speed-control structure found by RE.
    SPEED_CONTROL_START = 0x08003698
    SPEED_CONTROL_END = 0x08003964
    SPEED_FIELD_TARGET = 0x14
    SPEED_FIELD_LIMIT = 0x18
    SPEED_RESULT_FIELD = 0x26

    PARAM_DISPATCH_START = 0x08009D44
    PARAM_DISPATCH_END = 0x08009E30

    REGION_TABLE_OFFSETS = (0x3440, 0x3C80)
    REGION_UNLOCK_VALUE = b"\x28\x03\x00\x20"

    # Generic Mi5 speed signatures are deliberately NOT reused here:
    # the 5 Plus image has a different speed-control implementation.
    # A speed patch is enabled only when a 5 Plus-specific signature matches.
    SPEED_SIGS = ()

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
            "speed_target_field": cls.SPEED_FIELD_TARGET,
            "speed_limit_field": cls.SPEED_FIELD_LIMIT,
            "speed_result_field": cls.SPEED_RESULT_FIELD,
        }

    @staticmethod
    def _speed_value(kmh: float) -> int:
        # Do not assume the Mi5/ES32 20.9 conversion for 5 Plus.
        # The exact physical scale of the 5 Plus speed structure is not
        # proven yet, so this helper is only used by future verified patches.
        if not isinstance(kmh, (int, float)):
            raise TypeError("speed must be numeric")
        if not 0 < kmh <= 100:
            raise ValueError("speed must be between 0 and 100 km/h")
        return int(round(kmh * 10.0))

    def _find_unique(self, sig):
        try:
            first = find_pattern(self.data, sig)
            second = find_pattern(self.data, sig, start=first + 1)
            if second != first:
                raise SignatureException(f"Non-unique 5 Plus signature: {hex(first)}, {hex(second)}")
            return first
        except SignatureException:
            raise

    def speed_limit_drive(self, speed):
        # Do not apply the generic Mi5 patch.  The known 5 Plus image has a
        # different implementation and its physical speed scale is not yet
        # proven.  Returning a clear diagnostic is safer than silently
        # performing a region patch and claiming the requested speed changed.
        raise SignatureException(
            "Mi 5 Plus: drive speed patch is not yet verified for this firmware. "
            "Use region_free separately; a second 5 Plus firmware image is needed "
            "to prove the speed value/scale."
        )

    def speed_limit_sport(self, speed):
        raise SignatureException(
            "Mi 5 Plus: sport speed patch is not yet verified for this firmware. "
            "Generic Mi5 signatures must not be reused on 5 Plus."
        )

    def remove_speed_limit_sport(self):
        return self.speed_limit_sport(35.0)

    def region_free(self):
        res = []
        for start_ofs in self.REGION_TABLE_OFFSETS:
            for i in range(7):
                ofs = start_ofs + 4 * (i + 1)
                if ofs + 4 > len(self.data):
                    raise ValueError(f"Region table offset outside image: {hex(ofs)}")
                pre = self.data[ofs:ofs + 4]
                post = self.REGION_UNLOCK_VALUE
                if pre == post:
                    continue
                self.data[ofs:ofs + 4] = post
                res.append((f"region_free_{hex(start_ofs)}_{i}", hex(ofs), pre.hex(), post.hex()))
        if not res:
            return [("region_patch", "already_global", "unchanged", "ok")]
        return res

    def fake_version(self, version=None):
        return [("fake_firmware_version", "not_implemented", "unchanged", "not_applied")]
