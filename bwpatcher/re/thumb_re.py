"""Static ARM Thumb/Thumb-2 reverse-engineering helpers.

The analyzer is deliberately evidence-first. It operates on the supplied raw
firmware image and reports candidates; it does not assign semantic labels
(Eco/Drive/Sport/current/power) unless the bytecode itself provides evidence.

Requires the project's existing ``capstone`` dependency.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import capstone
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
except ImportError as exc:  # pragma: no cover - exercised only without deps
    capstone = None
    ARM_OP_IMM = ARM_OP_MEM = ARM_OP_REG = -1
    _CAPSTONE_IMPORT_ERROR = exc
else:
    _CAPSTONE_IMPORT_ERROR = None


@dataclass(frozen=True)
class AnalysisFinding:
    confidence: str
    category: str
    address: Optional[int]
    file_offset: Optional[int]
    message: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


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


class ThumbREAnalyzer:
    """Analyze a raw Cortex-M Thumb image without changing it."""

    def __init__(self, data: bytes | bytearray, flash_base: int = 0x08000000):
        if capstone is None:
            raise RuntimeError(
                "capstone is required for ThumbREAnalyzer; install dependencies "
                "from requirements.txt"
            ) from _CAPSTONE_IMPORT_ERROR
        self.data = bytes(data)
        self.flash_base = flash_base
        self.cs = capstone.Cs(
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
        )
        self.cs.detail = True

    # ------------------------------------------------------------------
    # Address helpers / identity
    # ------------------------------------------------------------------
    def file_to_mcu(self, offset: int) -> int:
        return self.flash_base + offset

    def mcu_to_file(self, address: int) -> Optional[int]:
        offset = address - self.flash_base
        if 0 <= offset < len(self.data):
            return offset
        return None

    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def vector_table(self) -> dict:
        if len(self.data) < 8:
            return {"valid": False, "reason": "image too short"}
        sp, reset = struct.unpack_from("<II", self.data, 0)
        reset_addr = reset & ~1
        return {
            "valid": 0x20000000 <= sp <= 0x20020000 and 0x08000000 <= reset_addr <= 0x08040000,
            "initial_sp": sp,
            "reset_vector": reset,
            "reset_address": reset_addr,
        }

    # ------------------------------------------------------------------
    # Thumb disassembly
    # ------------------------------------------------------------------
    def disassemble(self, start: int = 0, end: Optional[int] = None) -> List[InstructionRecord]:
        end = len(self.data) if end is None else min(end, len(self.data))
        start = max(0, start)
        if start >= end:
            return []

        result: List[InstructionRecord] = []
        for insn in self.cs.disasm(self.data[start:end], self.file_to_mcu(start)):
            file_offset = insn.address - self.flash_base
            result.append(
                InstructionRecord(
                    address=insn.address,
                    file_offset=file_offset,
                    size=insn.size,
                    bytes_hex=insn.bytes.hex(" "),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                )
            )
        return result

    # ------------------------------------------------------------------
    # Operand / literal resolution
    # ------------------------------------------------------------------
    @staticmethod
    def _is_mem_operand(op) -> bool:
        return getattr(op, "type", None) == ARM_OP_MEM

    @staticmethod
    def _is_reg_operand(op) -> bool:
        return getattr(op, "type", None) == ARM_OP_REG

    @staticmethod
    def _is_imm_operand(op) -> bool:
        return getattr(op, "type", None) == ARM_OP_IMM

    def _pc_literal_target(self, insn, operand) -> Optional[int]:
        mem = getattr(operand, "mem", None)
        if mem is None or mem.base != 15:  # ARM register 15 == PC
            return None
        # Thumb literal addressing uses Align(PC,4) + imm.
        return ((insn.address + 4) & ~3) + mem.disp

    def _read_u32_at_mcu(self, address: int) -> Optional[int]:
        ofs = self.mcu_to_file(address)
        if ofs is None or ofs + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, ofs)[0]

    # ------------------------------------------------------------------
    # Exact target XREFs
    # ------------------------------------------------------------------
    def find_literal_xrefs(self, targets: Iterable[int], start: int = 0, end: Optional[int] = None) -> Dict[int, List[InstructionRecord]]:
        wanted = set(targets)
        result: Dict[int, List[InstructionRecord]] = {target: [] for target in wanted}
        if not wanted:
            return result

        end = len(self.data) if end is None else min(end, len(self.data))
        for insn in self.cs.disasm(self.data[start:end], self.file_to_mcu(start)):
            for operand in insn.operands:
                if not self._is_mem_operand(operand):
                    continue
                literal_target = self._pc_literal_target(insn, operand)
                if literal_target is not None:
                    value = self._read_u32_at_mcu(literal_target)
                    if value in wanted:
                        result[value].append(
                            InstructionRecord(
                                insn.address,
                                insn.address - self.flash_base,
                                insn.size,
                                insn.bytes.hex(" "),
                                insn.mnemonic,
                                insn.op_str,
                            )
                        )
        return result

    # ------------------------------------------------------------------
    # Local constant/data-flow approximation
    # ------------------------------------------------------------------
    def _track_register_constants(self, insns: Sequence, until_index: int) -> Dict[str, int]:
        """Best-effort register constant tracking in one linear code window.

        This is intentionally conservative. Branches/calls invalidate registers
        that cannot safely be inferred. It is a candidate generator, not a
        symbolic executor.
        """
        regs: Dict[str, int] = {}
        for insn in insns[:until_index]:
            mnem = insn.mnemonic.lower()
            ops = insn.operands

            # Most writing instructions invalidate their destination register.
            written_reg = None
            if ops and self._is_reg_operand(ops[0]):
                written_reg = insn.reg_name(ops[0].reg)

            if mnem in {"movs", "mov", "mov.w"} and len(ops) >= 2:
                if self._is_reg_operand(ops[0]) and self._is_imm_operand(ops[1]):
                    regs[insn.reg_name(ops[0].reg)] = ops[1].imm & 0xFFFFFFFF
                    continue
                if self._is_reg_operand(ops[0]) and self._is_reg_operand(ops[1]):
                    src = insn.reg_name(ops[1].reg)
                    if src in regs:
                        regs[insn.reg_name(ops[0].reg)] = regs[src]
                    else:
                        regs.pop(insn.reg_name(ops[0].reg), None)
                    continue

            # LDR Rt,[PC,#imm]: resolve a literal into the destination register.
            if mnem.startswith("ldr") and len(ops) >= 2 and self._is_reg_operand(ops[0]) and self._is_mem_operand(ops[1]):
                literal = self._pc_literal_target(insn, ops[1])
                if literal is not None:
                    value = self._read_u32_at_mcu(literal)
                    dst = insn.reg_name(ops[0].reg)
                    if value is not None:
                        regs[dst] = value
                    else:
                        regs.pop(dst, None)
                    continue

            # ADD/SUB register,#imm on a tracked constant.
            if mnem in {"adds", "add", "add.w", "subs", "sub", "sub.w"} and len(ops) >= 2:
                if self._is_reg_operand(ops[0]) and self._is_reg_operand(ops[1]) and len(ops) >= 3 and self._is_imm_operand(ops[2]):
                    dst = insn.reg_name(ops[0].reg)
                    src = insn.reg_name(ops[1].reg)
                    if src in regs:
                        delta = ops[2].imm
                        regs[dst] = (regs[src] + delta) & 0xFFFFFFFF if mnem.startswith("add") else (regs[src] - delta) & 0xFFFFFFFF
                    else:
                        regs.pop(dst, None)
                    continue
                if self._is_reg_operand(ops[0]) and self._is_imm_operand(ops[1]):
                    dst = insn.reg_name(ops[0].reg)
                    if dst in regs:
                        delta = ops[1].imm
                        regs[dst] = (regs[dst] + delta) & 0xFFFFFFFF if mnem.startswith("add") else (regs[dst] - delta) & 0xFFFFFFFF
                    continue

            # Branch/call can invalidate assumptions beyond the call site.
            if mnem.startswith("bl"):
                for reg in list(regs):
                    if reg in {"r0", "r1", "r2", "r3", "r12"}:
                        regs.pop(reg, None)
                continue

            if written_reg:
                regs.pop(written_reg, None)

        return regs

    def find_memory_writers(self, target: int, start: int = 0, end: Optional[int] = None, context_instructions: int = 24) -> List[dict]:
        """Find stores whose base register can be resolved to ``target``.

        This follows literal-loaded base registers in a bounded linear window.
        It intentionally reports candidate writers rather than pretending to
        solve arbitrary control flow.
        """
        end = len(self.data) if end is None else min(end, len(self.data))
        disasm = list(self.cs.disasm(self.data[start:end], self.file_to_mcu(start)))
        out: List[dict] = []
        for i, insn in enumerate(disasm):
            mnem = insn.mnemonic.lower()
            if not mnem.startswith("str"):
                continue
            ops = insn.operands
            if len(ops) < 2 or not self._is_mem_operand(ops[1]):
                continue
            base = ops[1].mem.base
            if base in (15, 13):
                continue
            base_name = insn.reg_name(base)
            window_start = max(0, i - context_instructions)
            regs = self._track_register_constants(disasm[window_start:i], i - window_start)
            resolved = regs.get(base_name)
            if resolved is None:
                continue
            effective = resolved + ops[1].mem.disp
            if effective != target:
                continue
            rec = InstructionRecord(
                insn.address,
                insn.address - self.flash_base,
                insn.size,
                insn.bytes.hex(" "),
                insn.mnemonic,
                insn.op_str,
            )
            out.append({
                "store": asdict(rec),
                "resolved_base": resolved,
                "effective_address": effective,
                "preceding": [
                    {
                        "address": x.address,
                        "file_offset": x.file_offset,
                        "bytes_hex": x.bytes_hex,
                        "mnemonic": x.mnemonic,
                        "op_str": x.op_str,
                    }
                    for x in disasm[window_start:i]
                ],
            })
        return out

    # ------------------------------------------------------------------
    # Candidate detectors
    # ------------------------------------------------------------------
    def find_speed_hooks(self) -> List[AnalysisFinding]:
        findings: List[AnalysisFinding] = []
        exact = b"\xAB\x49\x78\x7A\x08\x80"
        start = 0
        while True:
            pos = self.data.find(exact, start)
            if pos < 0:
                break
            findings.append(AnalysisFinding(
                "CONFIRMED",
                "speed_hook",
                self.file_to_mcu(pos + 2),
                pos + 2,
                "Exact six-byte speed hook candidate: LDRB r0,[r7,#9] followed by STRH r0,[r1].",
                (f"signature={exact.hex(' ')}", "instruction_offset=+2", "destination_instruction_offset=+4"),
            ))
            start = pos + 1

        # Search for generic LDRB r0,[rN,#9] followed by STRH r0,[rX].
        for insn in self.disassemble():
            if insn.mnemonic.lower() != "ldrb":
                continue
            # Re-decode just this instruction for operands.
            raw = self.data[insn.file_offset:insn.file_offset + insn.size]
            decoded = next(self.cs.disasm(raw, insn.address), None)
            if decoded is None or len(decoded.operands) < 2:
                continue
            dst, mem = decoded.operands[0], decoded.operands[1]
            if not (self._is_reg_operand(dst) and self._is_mem_operand(mem)):
                continue
            if decoded.reg_name(dst.reg) != "r0" or mem.mem.disp != 9 or mem.mem.base == 15:
                continue
            findings.append(AnalysisFinding(
                "STRONG CANDIDATE",
                "speed_hook",
                insn.address,
                insn.file_offset,
                "Generic LDRB r0,[rN,#9] candidate; requires surrounding control-flow validation.",
                (f"bytes={insn.bytes_hex}", f"base={decoded.reg_name(mem.mem.base)}", "field_offset=9"),
            ))
        return findings

    def find_mode_compare_candidates(self, start: int = 0, end: Optional[int] = None) -> List[AnalysisFinding]:
        findings: List[AnalysisFinding] = []
        insns = self.disassemble(start, end)
        for i, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()
            if not mnem.startswith("cmp"):
                continue
            raw = self.data[insn.file_offset:insn.file_offset + insn.size]
            decoded = next(self.cs.disasm(raw, insn.address), None)
            if decoded is None or len(decoded.operands) < 2:
                continue
            if not self._is_imm_operand(decoded.operands[1]):
                continue
            imm = decoded.operands[1].imm
            if imm not in (0, 1, 2):
                continue
            branch = None
            if i + 1 < len(insns) and insns[i + 1].mnemonic.lower().startswith("b"):
                branch = insns[i + 1]
            evidence = [f"compare_immediate={imm}"]
            if branch:
                evidence.append(f"following_branch={branch.text}")
            findings.append(AnalysisFinding(
                "STRONG CANDIDATE" if branch else "UNCONFIRMED",
                "mode_candidate",
                insn.address,
                insn.file_offset,
                "CMP against mode-like immediate 0/1/2.",
                tuple(evidence),
            ))
        return findings

    def analyze_address(self, target: int, start: int = 0, end: Optional[int] = None) -> dict:
        """Combined XREF + writer report for one RAM/Flash address."""
        return {
            "target": target,
            "literal_xrefs": {
                str(k): [asdict(x) for x in v]
                for k, v in self.find_literal_xrefs([target], start, end).items()
            },
            "memory_writers": self.find_memory_writers(target, start, end),
        }

    def report(self, ranges: Optional[Sequence[Tuple[int, int]]] = None) -> dict:
        if ranges is None:
            ranges = [(0, len(self.data))]
        all_mode_candidates: List[AnalysisFinding] = []
        all_speed_hooks: List[AnalysisFinding] = []
        for start, end in ranges:
            all_mode_candidates.extend(self.find_mode_compare_candidates(start, end))
            all_speed_hooks.extend(self.find_speed_hooks())

        dedup = {}
        for finding in all_speed_hooks:
            dedup[(finding.category, finding.file_offset)] = finding
        all_speed_hooks = list(dedup.values())

        targets = [0x20000234, 0x20001E2C, 0x200002E5]
        target_reports = {hex(t): self.analyze_address(t) for t in targets}

        return {
            "firmware": {
                "size": len(self.data),
                "sha256": self.sha256(),
                "flash_base": self.flash_base,
                "vector_table": self.vector_table(),
            },
            "speed_hooks": [f.to_dict() for f in all_speed_hooks],
            "mode_candidates": [f.to_dict() for f in all_mode_candidates],
            "addresses": target_reports,
            "notes": [
                "Static analysis is conservative and may report candidates without semantic proof.",
                "No mode enum mapping is hard-coded.",
                "No Flash patch is applied by this analyzer.",
            ],
        }
