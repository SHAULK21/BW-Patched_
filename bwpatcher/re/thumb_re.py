"""CFG-aware ARM Thumb/Thumb-2 reverse-engineering helpers.

Analysis only: this module never changes firmware bytes and never hard-codes
Eco/Drive/Sport semantics. It works from the supplied raw BIN, follows code
reachable from the Cortex-M vector table, resolves PC-relative literals, and
reports bounded data-flow candidates.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import capstone
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

CONFIRMED = "CONFIRMED"
STRONG_CANDIDATE = "STRONG CANDIDATE"
UNCONFIRMED = "UNCONFIRMED"


@dataclass(frozen=True)
class InstructionRecord:
    address: int
    file_offset: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()


@dataclass(frozen=True)
class AnalysisFinding:
    confidence: str
    category: str
    address: Optional[int]
    file_offset: Optional[int]
    message: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        value = asdict(self)
        value["evidence"] = list(self.evidence)
        return value


class ThumbREAnalyzer:
    """Static Thumb/Thumb-2 analyzer for a raw Cortex-M image."""

    CONDITIONAL_BRANCHES = {
        "beq", "bne", "bhs", "blo", "bcs", "bcc", "bmi", "bpl",
        "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble",
        "bal",
    }

    def __init__(self, data: bytes | bytearray, flash_base: int = 0x08000000):
        self.data = bytes(data)
        self.flash_base = flash_base
        self.cs = capstone.Cs(
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
        )
        self.cs.detail = True
        self._reachable: Optional[Dict[int, object]] = None

    # ------------------------------------------------------------------
    # Image/address helpers
    # ------------------------------------------------------------------
    def file_to_mcu(self, offset: int) -> int:
        return self.flash_base + offset

    def mcu_to_file(self, address: int) -> Optional[int]:
        offset = address - self.flash_base
        return offset if 0 <= offset < len(self.data) else None

    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def vector_table(self) -> dict:
        if len(self.data) < 8:
            return {"valid": False, "reason": "image too short"}
        sp, reset = struct.unpack_from("<II", self.data, 0)
        reset_addr = reset & ~1
        in_flash = self.flash_base <= reset_addr < self.flash_base + len(self.data)
        return {
            "valid": 0x20000000 <= sp <= 0x20020000 and in_flash,
            "initial_sp": sp,
            "reset_vector": reset,
            "reset_address": reset_addr,
        }

    # ------------------------------------------------------------------
    # Capstone helpers
    # ------------------------------------------------------------------
    def _decode_one(self, file_offset: int):
        if file_offset < 0 or file_offset >= len(self.data):
            return None
        return next(
            self.cs.disasm(
                self.data[file_offset:file_offset + 4],
                self.file_to_mcu(file_offset),
                count=1,
            ),
            None,
        )

    @staticmethod
    def _record(insn, flash_base: int) -> InstructionRecord:
        return InstructionRecord(
            insn.address,
            insn.address - flash_base,
            insn.size,
            insn.bytes.hex(" "),
            insn.mnemonic,
            insn.op_str,
        )

    def disassemble(self, start: int = 0, end: Optional[int] = None) -> List[InstructionRecord]:
        end = len(self.data) if end is None else min(end, len(self.data))
        start = max(0, start)
        if start >= end:
            return []
        return [
            self._record(insn, self.flash_base)
            for insn in self.cs.disasm(self.data[start:end], self.file_to_mcu(start))
        ]

    def _branch_target(self, insn) -> Optional[int]:
        mnem = insn.mnemonic.lower()
        if mnem != "b" and mnem not in self.CONDITIONAL_BRANCHES and mnem not in {"bl", "blx"}:
            return None
        for operand in insn.operands:
            if operand.type == ARM_OP_IMM:
                return operand.imm & ~1
        return None

    # ------------------------------------------------------------------
    # CFG recovery
    # ------------------------------------------------------------------
    def reachable_instructions(self, max_instructions: int = 250000) -> List[InstructionRecord]:
        """Follow direct control flow from the vector table.

        Conditional B and BL retain a fall-through edge; unconditional B and
        indirect returns terminate the current linear block. Indirect calls /
        jump tables are intentionally not guessed.
        """
        if self._reachable is not None:
            return [self._record(i, self.flash_base) for i in sorted(self._reachable.values(), key=lambda x: x.address)]

        starts: Set[int] = set()
        vt = self.vector_table()
        if vt.get("valid"):
            for index in range(min(64, len(self.data) // 4)):
                value = struct.unpack_from("<I", self.data, index * 4)[0]
                address = value & ~1
                if self.flash_base <= address < self.flash_base + len(self.data):
                    starts.add(address)
        if not starts:
            starts.add(self.flash_base)

        queue = list(starts)
        seen_offsets: Set[int] = set()
        instructions: Dict[int, object] = {}

        while queue and len(instructions) < max_instructions:
            address = queue.pop()
            if not (self.flash_base <= address < self.flash_base + len(self.data)):
                continue

            while True:
                offset = self.mcu_to_file(address)
                if offset is None or offset in seen_offsets:
                    break
                insn = self._decode_one(offset)
                if insn is None:
                    break

                seen_offsets.add(offset)
                instructions[offset] = insn
                mnem = insn.mnemonic.lower()
                target = self._branch_target(insn)
                if target is not None and self.flash_base <= target < self.flash_base + len(self.data):
                    queue.append(target)

                if mnem == "b" or mnem in {"bx", "bxj", "blx"}:
                    break
                if mnem.startswith("pop") and "pc" in insn.op_str.lower():
                    break
                address = insn.address + insn.size

        self._reachable = instructions
        return [self._record(i, self.flash_base) for i in sorted(instructions.values(), key=lambda x: x.address)]

    # ------------------------------------------------------------------
    # Literal pools
    # ------------------------------------------------------------------
    def _pc_literal_target(self, insn, operand) -> Optional[int]:
        if operand.type != ARM_OP_MEM or operand.mem.base != 15:
            return None
        return ((insn.address + 4) & ~3) + operand.mem.disp

    def read_u32(self, mcu_address: int) -> Optional[int]:
        offset = self.mcu_to_file(mcu_address)
        if offset is None or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def literal_xrefs(self, targets: Iterable[int], reachable_only: bool = True) -> Dict[int, List[InstructionRecord]]:
        targets = set(targets)
        result = {target: [] for target in targets}
        records = self.reachable_instructions() if reachable_only else self.disassemble()
        for record in records:
            insn = self._decode_one(record.file_offset)
            if insn is None:
                continue
            for operand in insn.operands:
                literal = self._pc_literal_target(insn, operand)
                if literal is None:
                    continue
                value = self.read_u32(literal)
                if value in targets:
                    result[value].append(record)
        return result

    # ------------------------------------------------------------------
    # Per-basic-block bounded data flow
    # ------------------------------------------------------------------
    def _track_defs(self, records: Sequence[InstructionRecord], index: int) -> Dict[str, int]:
        defs: Dict[str, int] = {}
        for record in records[max(0, index - 160):index]:
            insn = self._decode_one(record.file_offset)
            if insn is None or not insn.operands:
                continue
            mnem = insn.mnemonic.lower()
            ops = insn.operands

            if mnem.startswith("ldr") and len(ops) >= 2 and ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_MEM:
                literal = self._pc_literal_target(insn, ops[1])
                if literal is not None:
                    value = self.read_u32(literal)
                    if value is not None:
                        defs[insn.reg_name(ops[0].reg)] = value
                        continue

            if mnem in {"mov", "movs", "mov.w"} and len(ops) >= 2 and ops[0].type == ARM_OP_REG:
                dst = insn.reg_name(ops[0].reg)
                if ops[1].type == ARM_OP_IMM:
                    defs[dst] = ops[1].imm & 0xFFFFFFFF
                elif ops[1].type == ARM_OP_REG:
                    src = insn.reg_name(ops[1].reg)
                    if src in defs:
                        defs[dst] = defs[src]
                    else:
                        defs.pop(dst, None)
                else:
                    defs.pop(dst, None)
                continue

            if mnem in {"add", "adds", "add.w", "sub", "subs", "sub.w"} and len(ops) >= 2:
                if ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_REG and len(ops) >= 3 and ops[2].type == ARM_OP_IMM:
                    dst = insn.reg_name(ops[0].reg)
                    src = insn.reg_name(ops[1].reg)
                    if src in defs:
                        delta = ops[2].imm
                        defs[dst] = (defs[src] + delta) & 0xFFFFFFFF if mnem.startswith("add") else (defs[src] - delta) & 0xFFFFFFFF
                    else:
                        defs.pop(dst, None)
                    continue

            if ops[0].type == ARM_OP_REG and mnem not in {"cmp", "tst", "teq", "str", "strb", "strh"}:
                defs.pop(insn.reg_name(ops[0].reg), None)
        return defs

    def memory_accesses(self, target: int, access: str = "both", reachable_only: bool = True) -> List[dict]:
        records = self.reachable_instructions() if reachable_only else self.disassemble()
        result = []
        for index, record in enumerate(records):
            insn = self._decode_one(record.file_offset)
            if insn is None or len(insn.operands) < 2:
                continue
            mnem = insn.mnemonic.lower()
            is_write = mnem.startswith("str")
            is_read = mnem.startswith("ldr")
            if access == "writes" and not is_write:
                continue
            if access == "reads" and not is_read:
                continue
            mem = next((op for op in insn.operands[1:] if op.type == ARM_OP_MEM), None)
            if mem is None or mem.mem.base in (13, 15):
                continue
            base_name = insn.reg_name(mem.mem.base)
            defs = self._track_defs(records, index)
            base_value = defs.get(base_name)
            if base_value is None:
                continue
            effective = (base_value + mem.mem.disp) & 0xFFFFFFFF
            if effective != target:
                continue
            result.append({
                "confidence": CONFIRMED,
                "target": target,
                "access": "write" if is_write else "read",
                "instruction": asdict(record),
                "resolved_base": base_value,
                "effective_address": effective,
            })
        return result

    # ------------------------------------------------------------------
    # Candidate searches
    # ------------------------------------------------------------------
    def mode_compare_candidates(self) -> List[AnalysisFinding]:
        records = self.reachable_instructions()
        findings: List[AnalysisFinding] = []
        for index, record in enumerate(records):
            insn = self._decode_one(record.file_offset)
            if insn is None or not insn.mnemonic.lower().startswith("cmp"):
                continue
            immediates = [op.imm for op in insn.operands if op.type == ARM_OP_IMM]
            if not immediates or immediates[0] not in (0, 1, 2):
                continue
            imm = immediates[0]
            evidence = [f"compare_immediate={imm}"]
            if index + 1 < len(records):
                next_record = records[index + 1]
                if next_record.mnemonic.lower().startswith("b"):
                    evidence.append(f"following_branch={next_record.text}")
                    confidence = STRONG_CANDIDATE
                else:
                    confidence = UNCONFIRMED
            else:
                confidence = UNCONFIRMED
            findings.append(AnalysisFinding(
                confidence,
                "mode_candidate",
                record.address,
                record.file_offset,
                "Reachable compare against mode-like immediate 0/1/2.",
                tuple(evidence),
            ))
        return findings

    def report(self, targets: Optional[Sequence[int]] = None) -> dict:
        if targets is None:
            targets = (
                0x20000234,
                0x20001E22,
                0x20001E2C,
                0x200002E5,
                0x20000348,
                0x200002B7,
            )
        exact = b"\xAB\x49\x78\x7A\x08\x80"
        speed_hooks = []
        start = 0
        while True:
            pos = self.data.find(exact, start)
            if pos < 0:
                break
            speed_hooks.append(AnalysisFinding(
                CONFIRMED,
                "speed_hook",
                self.file_to_mcu(pos + 2),
                pos + 2,
                "Exact bytes AB 49 78 7A 08 80; +2 is LDRB r0,[r7,#9].",
                (f"file_offset=0x{pos:05X}", "patch_offset=+2", "suffix=08 80"),
            ).to_dict())
            start = pos + 1

        return {
            "firmware": {
                "size": len(self.data),
                "sha256": self.sha256(),
                "vector_table": self.vector_table(),
            },
            "reachable_code": {
                "instruction_count": len(self.reachable_instructions()),
            },
            "speed_hooks": speed_hooks,
            "mode_candidates": [f.to_dict() for f in self.mode_compare_candidates()],
            "addresses": {
                hex(target): {
                    "literal_xrefs": [asdict(x) for x in self.literal_xrefs([target])[target]],
                    "readers": self.memory_accesses(target, "reads"),
                    "writers": self.memory_accesses(target, "writes"),
                }
                for target in targets
            },
            "notes": [
                "CFG starts from the Cortex-M vector table to reduce literal-pool false positives.",
                "Memory data-flow is bounded to a linear window and is not a symbolic executor.",
                "Mode numbers are never automatically labelled Eco/Drive/Sport.",
                "This analyzer never modifies firmware bytes.",
            ],
        }
