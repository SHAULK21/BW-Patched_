#!/usr/bin/env python3
#! -*- coding: utf-8 -*-
#
# BW Patcher
# Copyright (C) 2024-2026 ScooterTeam
#
# This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# To view a copy of the license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/
# or send a letter to Creative Commons, Inc., PO Box 1866, Mountain View, CA 94042, USA.
#

import shutil
import traceback

from importlib import import_module
import re


class SignatureException(Exception):
    pass


patch_map = {
    "rsls": lambda patcher: patcher.remove_speed_limit_sport,
    "dms": lambda patcher: patcher.dashboard_max_speed,
    "slp": lambda patcher: patcher.speed_limit_ped,
    "sld": lambda patcher: patcher.speed_limit_drive,
    "sls": lambda patcher: patcher.speed_limit_sport,
    "rfm": lambda patcher: patcher.region_free,
    "fdv": lambda patcher: patcher.fake_drv_version,
    "chk": lambda patcher: patcher.fix_checksum,
    "img": lambda patcher: patcher.create_full_image,
    "mss": lambda patcher: patcher.motor_start_speed,
    "cce": lambda patcher: patcher.cruise_control_enable,
    "region_free": lambda patcher: patcher.region_free,
}


def patch_firmware(model: str, data: bytes, patches: list, web=True):
    print("Patchlist:", patches)

    errors = []
    module = import_module(f"bwpatcher.modules.{model}")
    patcher_class = getattr(module, f"{model.capitalize()}Patcher")
    patcher = patcher_class(data)

    for patch_spec in patches:
        patch_name = patch_spec
        value = None
        if '=' in patch_spec:
            patch_name, value = patch_spec.split('=', 1)
            if patch_name != 'fdv':
                value = float(value)

        if patch_name not in patch_map:
            errors.append((patch_name, "The specified patch doesn't exist."))
            continue

        try:
            fn = patch_map[patch_name](patcher)
            if value is not None:
                res = fn(value)
            else:
                res = fn()
            print(f"[{patch_name}]", res)
        except Exception as e:
            # Preserve the original exception type but add the patch name.
            # This prevents the GUI from presenting a misleading generic
            # 'Pattern not found' message when another selected patch failed.
            wrapped = SignatureException(
                f"Patch '{patch_name}' failed in {model}: {e}"
            )
            if web:
                raise wrapped from e
            errors.append((patch_name, wrapped))

    if errors:
        width = max(20, shutil.get_terminal_size(fallback=(80,24)).columns // 3)
        for patch_name, error in errors:
            msg = f"ERROR: {patch_name} "
            print(f"{msg}{'-' * max(1, width - len(msg))}")
            traceback.print_exception(type(error), error, error.__traceback__)

        print("-" * width)
        for patch_name, _ in errors:
            print(f"Failed to use the {patch_name} patch. Check the logs.")

    return patcher.data


# https://github.com/BotoX/xiaomi-m365-firmware-patcher/blob/master/patcher.py
# Thx BotoX!
def find_pattern(data, signature, mask=None, start=None, maxit=None):
    sig_len = len(signature)
    if start is None:
        start = 0
    stop = len(data) - len(signature) + 1
    if maxit is not None:
        stop = min(stop, start + maxit)

    if mask:
        assert sig_len == len(mask), 'mask must be as long as the signature!'
        for i in range(sig_len):
            signature[i] &= mask[i]

    for i in range(start, stop):
        matches = 0
        while matches < sig_len and (
            signature[matches] is None
            or signature[matches] == (data[i + matches] & (mask[matches] if mask else 0xFF))
        ):
            matches += 1
        if matches == sig_len:
            return i

    raise SignatureException('Pattern not found!')


def extract_ldr_offset(instruction: str) -> int:
    """Extract offset from an LDR instruction like 'ldr r1, [pc, #0x1dc]'"""
    match = re.search(r'\[pc,\s*#(0x[0-9a-fA-F]+)\]', instruction)
    if match:
        return int(match.group(1), 16)
    return None


def offset_to_nearest_word(ofs):
    rem = -1
    while rem != 0:
        ofs += 2
        rem = ofs % 4
    return ofs


def get_reg(disasm, default="r1"):
    reg = default
    try:
        reg = disasm.split('\t')[1].split(',')[0]
    except Exception:
        pass
    return reg
