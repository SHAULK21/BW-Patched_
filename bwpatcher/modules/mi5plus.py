# ==============================================================================
# BWPATCHER MODULE: mi5plus.py
# Xiaomi Scooter 5 Plus (Brightway / ES32 MCU)
# Resilient Multi-Pattern Speed Patcher & Firmware Fingerprint Engine
# ==============================================================================

import re
import struct

# --- 1. FIRMWARE FINGERPRINT CONSTANTS ---
FLASH_BASE_ADDR = 0x08000000
MIN_FW_SIZE = 32 * 1024       # 32 KB minimum
MAX_FW_SIZE = 128 * 1024      # 128 KB maximum
SPEED_RUNTIME_ADDR = 0x20000234

# --- 2. MULTI-FORM SPEED HOOK PATTERNS (Flexible matching) ---
# Form 1: Exact Pristine (AB 49 78 7A 08 80)
PAT_PRISTINE_EXACT = b"\xAB\x49\x78\x7A\x08\x80"

# Form 2: Flexible PC-Rel Displacement (?? 49 78 7A 08 80)
PAT_FLEXIBLE_PC_REL = re.compile(b"(.)\x49\x78\x7A\x08\x80")

# Form 3: Generalized Active Profile Base Register (?? 49 ?? 7A 08 80) -> [rX + 9]
PAT_GENERIC_BASE_REG = re.compile(b"(.)\x49(.)\x7A\x08\x80")

# Form 4: Already Patched Firmware (?? 49 ?? 20 08 80) -> MOVS r0, #imm8
PAT_ALREADY_PATCHED = re.compile(b"(.)\x49(.)\x20\x08\x80")


class Mi5PlusPatcher:
    def __init__(self, data: bytearray):
        self.data = data
        self.size = len(data)
        self.verified_fingerprint = False
        self.hook_offset = None
        self.hook_form = None
        self.current_speed = None
        self.is_already_patched = False

    def verify_fingerprint(self) -> bool:
        """Verifies vector table sanity and Brightway MCU layout."""
        if not (MIN_FW_SIZE <= self.size <= MAX_FW_SIZE):
            print(f"[!] Warning: Unexpected firmware size ({self.size} bytes).")
            return False

        # Check Vector Table: Initial SP should be in SRAM (0x2000xxxx)
        initial_sp = struct.unpack_from("<I", self.data, 0x00)[0]
        reset_vec = struct.unpack_from("<I", self.data, 0x04)[0]

        if not (0x20000000 <= initial_sp <= 0x20008000):
            print(f"[-] Vector table SP (0x{initial_sp:08X}) not in SRAM range.")
            return False

        if not (0x08000000 <= reset_vec <= 0x08020000):
            print(f"[-] Vector table Reset Handler (0x{reset_vec:08X}) not in Flash range.")
            return False

        print(f"[+] Fingerprint PASS: SP=0x{initial_sp:08X}, Reset=0x{reset_vec:08X}")
        self.verified_fingerprint = True
        return True

    def find_speed_hook(self) -> int:
        """Scans for active-profile speed loader using multiple resilient heuristics."""
        # 1. Check exact factory signature
        pos = self.data.find(PAT_PRISTINE_EXACT)
        if pos != -1:
            self.hook_offset = pos + 2  # Target instruction is at offset +2 (78 7A)
            self.hook_form = "Pristine Exact (AB 49 78 7A 08 80)"
            return self.hook_offset

        # 2. Check flexible PC-relative pool displacement
        match = PAT_FLEXIBLE_PC_REL.search(self.data)
        if match:
            self.hook_offset = match.start() + 2
            self.hook_form = "Flexible PC-Rel Displacement (?? 49 78 7A 08 80)"
            return self.hook_offset

        # 3. Check generalized base register
        match = PAT_GENERIC_BASE_REG.search(self.data)
        if match:
            self.hook_offset = match.start() + 2
            self.hook_form = "Generic Base Register (?? 49 ?? 7A 08 80)"
            return self.hook_offset

        # 4. Check already patched binary
        match = PAT_ALREADY_PATCHED.search(self.data)
        if match:
            self.hook_offset = match.start() + 2
            self.hook_form = "Already Patched Binary (MOVS r0, #imm8)"
            self.is_already_patched = True
            self.current_speed = match.group(2)[0]
            print(f"[*] Detected previously patched firmware (Current: {self.current_speed} km/h)")
            return self.hook_offset

        return -1

    def diagnose(self):
        """Prints comprehensive diagnostic log for the firmware."""
        print("=" * 60)
        print("  XIAOMI 5 PLUS (BRIGHTWAY ES32) DIAGNOSTIC TRACE")
        print("=" * 60)
        self.verify_fingerprint()
        offset = self.find_speed_hook()
        if offset != -1:
            mcu_addr = FLASH_BASE_ADDR + offset
            print(f"[+] Speed Hook Detected:")
            print(f"    - File Offset: 0x{offset:05X}")
            print(f"    - MCU Address: 0x{mcu_addr:08X}")
            print(f"    - Match Form:  {self.hook_form}")
            print(f"    - Field check: [r7 + 0x09] (Active profile speed limit)")
            if self.is_already_patched:
                print(f"    - Status:      ALREADY MODIFIED ({self.current_speed} km/h)")
            else:
                print(f"    - Status:      PRISTINE FACTORY BINARY (Ready for patch)")
        else:
            print("[-] Speed hook not found with standard heuristics.")
        print("=" * 60)

    def patch_speed(self, target_speed_kmh: int = 35) -> bool:
        """Safely patches speed limit for all riding modes automatically."""
        if not self.verified_fingerprint:
            if not self.verify_fingerprint():
                raise RuntimeError("Firmware fingerprint validation failed!")

        if self.hook_offset is None:
            self.find_speed_hook()

        if self.hook_offset is None or self.hook_offset == -1:
            raise RuntimeError("Speed hook not found! Check diagnostic output.")

        # Opcode for MOVS r0, #imm8
        opcode = bytes([target_speed_kmh, 0x20])
        prev = bytes(self.data[self.hook_offset:self.hook_offset + 2])
        self.data[self.hook_offset:self.hook_offset + 2] = opcode

        print(f"[+] Successfully patched speed hook @ 0x{self.hook_offset:05X}:")
        print(f"    Previous bytes: {prev.hex().upper()}")
        print(f"    New bytes:      {opcode.hex().upper()} (MOVS r0, #{target_speed_kmh})")
        print(f"    Target speed:   {target_speed_kmh} km/h (Universal Eco/Drive/Sport)")
        return True

    def unlock_regions(self):
        """Unlocks regional speed limit tables at 0x3440 and 0x3C80."""
        unlock_val = b"\x28\x03\x00\x20"
        for table_base in (0x3440, 0x3C80):
            for i in range(7):
                ofs = table_base + 4 * (i + 1)
                self.data[ofs:ofs + 4] = unlock_val
        print("[+] Regional tables unlocked (US / Global mode)")


# --- STANDALONE API WRAPPERS ---
def patch_mi5plus(firmware_data: bytearray, speed_kmh: int = 35, region_free: bool = True):
    patcher = Mi5PlusPatcher(firmware_data)
    patcher.diagnose()
    patcher.patch_speed(speed_kmh)
    if region_free:
        patcher.unlock_regions()
    return firmware_data
