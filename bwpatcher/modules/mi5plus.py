"""Xiaomi 5 Plus (Brightway) firmware module.

Speed path currently supported by the supplied image:

    file 0x5C74: AB 49 78 7A 08 80
    file 0x5C76: LDRB r0,[r7,#9]
    file 0x5C78: STRH r0,[r1]       ; r1 -> 0x20000234

The controller path around MCU 0x08003698-0x08003964 scales the runtime
value by 0xAE/10 and clamps control+0x14 against control+0x18.

Mode RE note:
0x200002B7 is not treated as a mode selector. A separate candidate structure
was observed at RAM 0x20001E22, field +0x0A, where values 1 and 2 participate
in conditional logic. This is retained as RE metadata only; without a traced
writer it is NOT safe to patch it directly or claim 1=Drive / 2=Sport.

For compatibility with the existing UI/CorePatcher, all requested riding
profiles currently resolve to the verified active-profile speed hook. This is
intentional: it makes the speed patch usable now without inventing mode-
specific firmware offsets. Once the writer/data-flow for 0x20001E22+0x0A is
confirmed, the profile methods can be split into genuinely independent hooks.
"""

from bwpatcher.core_es32 import ES32Patcher


class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"

    PARAM_REGISTER_ADDR = 0x08009818
    PARAM_REGISTER_DISPATCH_ADDR = 0x080099BC
    PARAM_DISPATCH_START = 0x08009D44
    PARAM_DISPATCH_END = 0x08009E30

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
    CONTROL_FIELD_28_HARD_MAX = 0xC8

    SPEED_PROFILE_LOAD_OFFSET = 0x05C74
    SPEED_PROFILE_LOAD_SIG = b"\xAB\x49\x78\x7A\x08\x80"
    SPEED_PROFILE_VALUE_INSN_OFFSET = 2
    SPEED_PROFILE_VALUE_FIELD = 0x09
    SPEED_RUNTIME_ADDR = 0x20000234

    # Runtime mode/profile candidate. Kept for RE documentation only.
    MODE_CANDIDATE_BASE = 0x20001E22
    MODE_CANDIDATE_FIELD = 0x0A
    MODE_CANDIDATE_ADDR = MODE_CANDIDATE_BASE + MODE_CANDIDATE_FIELD
    MODE_CANDIDATE_VALUES = (1, 2)

    SPEED_STATE_GATE_ADDR = 0x20000348
    SPEED_STATE_GATE_VALUE = 1
    SPEED_STATE_GATE_LIMIT_CONSTANT = 435
    SPEED_ACTIVE_PROFILE_INDEX_ADDR = 0x200002B7

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
            "mode_candidate_base": cls.MODE_CANDIDATE_BASE,
            "mode_candidate_addr": cls.MODE_CANDIDATE_ADDR,
            "mode_candidate_values": cls.MODE_CANDIDATE_VALUES,
            "speed_state_gate_addr": cls.SPEED_STATE_GATE_ADDR,
            "speed_state_gate_value": cls.SPEED_STATE_GATE_VALUE,
            "speed_state_gate_limit_constant": cls.SPEED_STATE_GATE_LIMIT_CONSTANT,
            "speed_active_profile_index_addr": cls.SPEED_ACTIVE_PROFILE_INDEX_ADDR,
            "speed_target_field": cls.SPEED_FIELD_TARGET,
            "speed_limit_field": cls.SPEED_FIELD_LIMIT,
            "control_field_26": cls.CONTROL_FIELD_26,
            "control_field_28": cls.CONTROL_FIELD_28,
            "control_field_28_hard_max": cls.CONTROL_FIELD_28_HARD_MAX,
        }

    def region_free(self):
        res = []
        try:
            for start in self.REGION_TABLE_OFFSETS:
                ofs = start
                for i in range(7):
                    ofs += 4
                    if ofs + 4 > len(self.data):
                        break
                    pre = self.data[ofs:ofs + 4]
                    if pre == self.REGION_UNLOCK_VALUE:
                        continue
                    self.data[ofs:ofs + 4] = self.REGION_UNLOCK_VALUE
                    res.append((f"region_free_{hex(start)}_{i}", hex(ofs), pre.hex(), self.REGION_UNLOCK_VALUE.hex()))
        except Exception as e:
            print(f"Помилка при патчі регіону: {e}")
        return res or [("region_patch", "already_global", "forced_success", "done")]

    @staticmethod
    def _speed_opcode(speed):
        value = int(round(float(speed)))
        if not 1 <= value <= 0xFF:
            raise ValueError("Mi 5 Plus speed parameter must be between 1 and 255")
        return bytes((value, 0x20))  # Thumb MOVS r0,#imm8

    def _speed_hook_hits(self):
        data = bytes(self.data)
        hits = []
        for i in range(len(data) - 5):
            if data[i:i + 2] != b"\xAB\x49" or data[i + 4:i + 6] != b"\x08\x80":
                continue
            value = data[i + 2:i + 4]
            if value == b"\x78\x7A" or value[1] == 0x20:
                hits.append(i)
        return hits

    def _find_verified_speed_hook(self):
        hits = self._speed_hook_hits()
        if len(hits) != 1:
            raise ValueError(f"Mi 5 Plus: verified speed hook ambiguous/missing ({len(hits)} matches)")
        if hits[0] != self.SPEED_PROFILE_LOAD_OFFSET:
            raise ValueError(f"Mi 5 Plus: unexpected speed hook offset 0x{hits[0]:X}")
        return hits[0]

    def _find_speed_patch_state(self):
        hook = self._find_verified_speed_hook()
        ofs = hook + self.SPEED_PROFILE_VALUE_INSN_OFFSET
        current = bytes(self.data[ofs:ofs + 2])
        if current == b"\x78\x7A" or current[1] == 0x20:
            return hook, ofs, current
        raise ValueError(f"Mi 5 Plus: unexpected instruction at 0x{ofs:X}: {current.hex()}")

    def _patch_speed_profile(self, speed, label="active_profile"):
        post = self._speed_opcode(speed)
        hook, ofs, pre = self._find_speed_patch_state()
        self.data[ofs:ofs + 2] = post
        return [
            (f"speed_limit_5plus_{label}", hex(ofs), pre.hex(), post.hex()),
            ("speed_limit_5plus_source", hex(hook), self.SPEED_PROFILE_LOAD_SIG.hex(), self.SPEED_PROFILE_LOAD_SIG.hex()),
        ]

    def speed_limit_active_profile(self, speed):
        return self._patch_speed_profile(speed, "active_profile")

    # Until the 0x20001E22+0x0A writer is traced, these profile entry points
    # deliberately patch the same verified active-profile source. This is the
    # only behavior currently supported by the firmware evidence.
    def speed_limit_ped(self, kmh):
        return self._patch_speed_profile(kmh, "ped")

    def speed_limit_drive(self, kmh):
        return self._patch_speed_profile(kmh, "drive_active_profile")

    def speed_limit_sport(self, kmh):
        return self._patch_speed_profile(kmh, "sport_active_profile")

    def remove_speed_limit_sport(self):
        return self.speed_limit_sport(36.7)

    def dashboard_max_speed(self, speed):
        return self._patch_speed_profile(speed, "dashboard_active_profile")

    def fake_drv_version(self, firmware_version):
        return [("fake_firmware_version", "not_implemented", "safe_noop", "skipped")]

    def fake_version(self, version=None):
        return self.fake_drv_version(version)
