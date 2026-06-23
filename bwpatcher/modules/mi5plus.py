#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# BW Patcher
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
#
# You are free to:
# - Share — copy and redistribute the material in any medium or format
# - Adapt — remix, transform, and build upon the material
#
# Under the following terms:
# - Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made.
# - NonCommercial — You may not use the material for commercial purposes.
# - ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.
#

from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import SignatureException, find_pattern


class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"
    REGION_TABLE_SIG = [0xc8, 0x03, 0x00, 0x20, None, 0x03, 0x00, 0x20]
    REGION_FIX_SIG = [None, 0x8b, None, 0x82, None, 0x48, 0x00, 0x78]
    GLOBAL_REGION_PTR = b'\x28\x03\x00\x20'

    def __init__(self, data):
        super().__init__(data)
        self._region_free_applied = False

    def region_free(self):
        """
        Region patch for Brightway ES32 (Xiaomi 5 Plus).

        Switches the regional constants to the Global/US pointer used by the
        related ES32 models, then disables the regional comparison check.
        """
        if self._region_free_applied:
            return [("region_free", "N/A", "already_applied", "skipped")]

        res = []

        try:
            ofs_table = find_pattern(self.data, self.REGION_TABLE_SIG)
        except SignatureException:
            raise SignatureException(
                "Mi 5 Plus region table was not found. "
                "Check that the selected model matches the firmware and that the file is an unpacked ES32 firmware image."
            )
        tmp_byte = None
        for i in range(7):
            ofs = ofs_table + ((i + 1) * 4)
            if tmp_byte is not None and self.data[ofs + 1] != tmp_byte:
                continue

            tmp_byte = self.data[ofs + 1]
            pre = self.data[ofs:ofs + 4]
            post = self.GLOBAL_REGION_PTR
            self.data[ofs:ofs + 4] = post
            res += [(f"region_free_{i}", hex(ofs), pre.hex(), post.hex())]

        try:
            ofs = find_pattern(self.data, self.REGION_FIX_SIG) + len(self.REGION_FIX_SIG)
        except SignatureException:
            raise SignatureException(
                "Mi 5 Plus region check was not found. "
                "This firmware version may use a different layout or may already be patched."
            )
        pre = self.data[ofs:ofs + 2]
        post = self.assembly("cmp r0,#0xff")
        self.data[ofs:ofs + 2] = post
        res += [("region_free_fix", hex(ofs), pre.hex(), post.hex())]

        self._region_free_applied = True
        return res

    def speed_limit_drive(self, speed):
        """
        Drive limit is controlled by the regional lock on this firmware.
        Applying SLD therefore applies the Mi 5 Plus region-free patch.
        """
        res = self.region_free()
        res += [("speed_limit_drive_via_region_free", "N/A", str(speed), "applied")]
        return res

    def speed_limit_sport(self, speed):
        """
        Sport limit is controlled by the regional lock on this firmware.
        Applying SLS therefore applies the Mi 5 Plus region-free patch.
        """
        res = self.region_free()
        res += [("speed_limit_sport_via_region_free", "N/A", str(speed), "applied")]
        return res

    def remove_speed_limit_sport(self):
        """
        Remove the sport limit through the same regional unlock path.
        """
        return self.speed_limit_sport(speed=36.7)
