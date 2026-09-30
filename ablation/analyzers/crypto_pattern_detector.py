"""
Crypto implementation pattern recognizers for disassembly analysis.

HashAlgoDiscriminator -- identify hash algorithms (MD5 / SHA-1 / SHA-256 / SHA-512 /
CRC32) from K-table constants found in compiled ARM32 / Thumb2 code.

CustomCBCDetector -- recognize hand-rolled AES-128-CBC in ARM32 Thumb2: BSS-tracked
block pointer, XOR-with-prev-CT chaining, IV from .rodata.
"""
from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

try:
    import capstone
    import capstone.arm_const as arm_const
    import capstone.arm as capstone_arm
    _CAPSTONE = True
except ImportError:
    _CAPSTONE = False


# ── Hash constant signature tables ─────────────────────────────────────────────

# MD5 K-table: K[i] = floor(abs(sin(i+1)) * 2^32). First 8 give 100% confidence.
_MD5_K: Dict[str, int] = {
    "MD5_K0": 0xd76aa478, "MD5_K1": 0xe8c7b756, "MD5_K2": 0x242070db,
    "MD5_K3": 0xc1bdceee, "MD5_K4": 0xf57c0faf, "MD5_K5": 0x4787c62a,
    "MD5_K6": 0xa8304613, "MD5_K7": 0xfd469501,
}

# SHA-1: four round constants, one per 20-round group.
_SHA1_K: Dict[str, int] = {
    "SHA1_K0": 0x5a827999, "SHA1_K1": 0x6ed9eba1,
    "SHA1_K2": 0x8f1bbcdc, "SHA1_K3": 0xca62c1d6,
}

# SHA-256: 8 IV words + 8 K-table entries (cube roots of first primes).
# The upper 32 bits of SHA-512 K[0..3] match SHA-256 K[0..3]; disambiguation
# relies on SHA-512-unique lower-half constants below.
_SHA256_SIGS: Dict[str, int] = {
    "SHA256_H0": 0x6a09e667, "SHA256_H1": 0xbb67ae85,
    "SHA256_H2": 0x3c6ef372, "SHA256_H3": 0xa54ff53a,
    "SHA256_H4": 0x510e527f, "SHA256_H5": 0x9b05688c,
    "SHA256_H6": 0x1f83d9ab, "SHA256_H7": 0x5be0cd19,
    "SHA256_K0": 0x428a2f98, "SHA256_K1": 0x71374491,
    "SHA256_K2": 0xb5c0fbcf, "SHA256_K3": 0xe9b5dba5,
    "SHA256_K4": 0x3956c25b, "SHA256_K5": 0x59f111f1,
    "SHA256_K6": 0x923f82a4, "SHA256_K7": 0xab1c5ed5,
}

# SHA-512: lower 32 bits of K[0..3] and IV[0..3].
# These values do not appear in SHA-256, SHA-1, or MD5.
_SHA512_UNIQUE: Dict[str, int] = {
    "SHA512_K0_LO": 0xd728ae22, "SHA512_K1_LO": 0x23ef65cd,
    "SHA512_K2_LO": 0xec4d3b2f, "SHA512_K3_LO": 0x8189dbbc,
    "SHA512_H0_LO": 0xf3bcc908, "SHA512_H1_LO": 0x84caa73b,
    "SHA512_H2_LO": 0xfe94f82b, "SHA512_H3_LO": 0x5f1d36f1,
}

_CRC32: Dict[str, int] = {"CRC32_POLY": 0xedb88320}

# (algo, table, expected_hit_count_for_100_pct)
_ALGO_SIGS: Tuple[Tuple[str, Dict[str, int], int], ...] = (
    ("MD5",     _MD5_K,        8),
    ("SHA-1",   _SHA1_K,       4),
    ("SHA-256", _SHA256_SIGS, 16),
    ("SHA-512", _SHA512_UNIQUE, 8),
    ("CRC32",   _CRC32,         1),
)

# Flat lookup: value -> (algo, constant_name).
# First-writer wins; SHA-256 claims shared upper-half words;
# SHA-512 is detected via its unique lower-half constants.
_VALUE_TO_SIG: Dict[int, Tuple[str, str]] = {}
for _algo, _tbl, _ in _ALGO_SIGS:
    for _name, _val in _tbl.items():
        if _val not in _VALUE_TO_SIG:
            _VALUE_TO_SIG[_val] = (_algo, _name)


# ── HashAlgoDiscriminator ───────────────────────────────────────────────────────

@dataclass
class ConstMatch:
    """A matched hash constant found in disassembled code."""
    va: int
    value: int
    name: str
    algo: str


@dataclass
class HashAlgoMatch:
    """Result of a hash algorithm identification scan."""
    algo: str
    confidence: int  # 0-100
    matched: List[ConstMatch] = field(default_factory=list)

    def fmt(self) -> str:
        hits = ", ".join(f"0x{m.va:x}:{m.name}" for m in self.matched[:4])
        return f"{self.algo}  conf={self.confidence}  [{hits}{'...' if len(self.matched) > 4 else ''}]"


class HashAlgoDiscriminator:
    """Identify hash algorithms from K-table constants in compiled ARM32/Thumb2 code.

    Extracts 32-bit constants from MOVW/MOVT pairs and LDR-literal instructions,
    then matches against MD5, SHA-1, SHA-256, SHA-512, and CRC32 signatures.
    SHA-256 vs SHA-512 ambiguity is resolved via SHA-512-unique lower-half constants.
    """

    def __init__(self, binary: bytes, load_addr: int = 0) -> None:
        if not _CAPSTONE:
            raise ImportError("capstone required")
        self._binary = binary
        self._load = load_addr
        self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._md.detail = True
        self._md.skipdata = True

    def extract_constants(self, va: int, size: int) -> List[Tuple[int, int]]:
        """Return (insn_va, const_value) for 32-bit constants in [va, va+size).

        Handles MOVW/MOVT pairs (Thumb2 32-bit immediate split across two instructions)
        and LDR Rx, [PC, #N] literal-pool loads.
        """
        off = va - self._load
        if off < 0 or off + size > len(self._binary):
            return []
        results: List[Tuple[int, int]] = []
        pending: Dict[int, Tuple[int, int]] = {}  # reg_id -> (movw_va, lo16)

        for insn in self._md.disasm(self._binary[off : off + size], va):
            if not insn.id:
                continue  # skipdata pseudo-instruction
            ops = insn.operands
            if not ops:
                continue

            # capstone 5.x decodes `movw` as ARM_INS_MOV; guard with imm <= 0xFFFF
            if insn.id in (arm_const.ARM_INS_MOVW, arm_const.ARM_INS_MOV) and len(ops) == 2:
                if (ops[1].type == capstone_arm.ARM_OP_IMM
                        and (ops[1].imm & 0xFFFF0000) == 0):
                    pending[ops[0].reg] = (insn.address, ops[1].imm & 0xFFFF)

            elif insn.id == arm_const.ARM_INS_MOVT and len(ops) == 2:
                if ops[1].type == capstone_arm.ARM_OP_IMM:
                    reg = ops[0].reg
                    if reg in pending:
                        movw_va, lo = pending.pop(reg)
                        hi = ops[1].imm & 0xFFFF
                        results.append((movw_va, (hi << 16) | lo))

            elif insn.id in (arm_const.ARM_INS_LDR, arm_const.ARM_INS_VLDR) and len(ops) >= 2:
                mem = ops[1]
                if (mem.type == capstone_arm.ARM_OP_MEM
                        and mem.mem.base == arm_const.ARM_REG_PC):
                    # PC = (insn_addr & ~3) + 4 for Thumb literal loads
                    tva = (insn.address & ~3) + 4 + mem.mem.disp
                    toff = tva - self._load
                    if 0 <= toff <= len(self._binary) - 4:
                        results.append((insn.address,
                                        struct.unpack_from("<I", self._binary, toff)[0]))

        return results

    def scan_function(self, va: int, size: int) -> HashAlgoMatch:
        """Disassemble a function and identify its hash algorithm."""
        return self._match(self.extract_constants(va, size))

    @staticmethod
    def identify(constants: Sequence[int]) -> HashAlgoMatch:
        """Match a flat list of 32-bit constants without disassembly context."""
        return HashAlgoDiscriminator._match([(0, c) for c in constants])

    @staticmethod
    def _match(pairs: List[Tuple[int, int]]) -> HashAlgoMatch:
        hits: Dict[str, List[ConstMatch]] = {}
        for va, val in pairs:
            if val in _VALUE_TO_SIG:
                algo, name = _VALUE_TO_SIG[val]
                hits.setdefault(algo, []).append(ConstMatch(va, val, name, algo))
        if not hits:
            return HashAlgoMatch("unknown", 0)
        # SHA-512 unique lower-half constants override SHA-256 shared-value matches
        best = ("SHA-512" if "SHA-512" in hits and "SHA-256" in hits
                else max(hits, key=lambda a: len(hits[a])))
        matched = hits[best]
        total = next(n for a, _, n in _ALGO_SIGS if a == best)
        confidence = min(100, max(25 * len(matched), int(100 * len(matched) / total)))
        return HashAlgoMatch(best, confidence, matched)


# ── CustomCBCDetector ───────────────────────────────────────────────────────────

@dataclass
class CBCPattern:
    """A detected hand-rolled AES-128-CBC loop in ARM32 Thumb2 code."""
    outer_func_va: int         # function or scan-range VA
    block_func_va: int         # BL target = single-block AES call inside the loop
    chaining_reg: str          # register carrying prev-CT / IV pointer
    iv_va: Optional[int]       # VA of IV in .rodata (None if not resolved)
    iv_bytes: Optional[bytes]  # 16-byte IV value (None if not resolved)
    xor_va: int                # VA of first XOR instruction in the loop body
    loop_va: int               # VA of the loop start (back-edge target)
    confidence: int            # 0-100

    def fmt(self) -> str:
        iv_str = (self.iv_bytes.decode("ascii", errors="replace")
                  if self.iv_bytes else "?")
        base = (f"CBCPattern  conf={self.confidence}  "
                f"outer=0x{self.outer_func_va:x}  block_fn=0x{self.block_func_va:x}  "
                f"chain_reg={self.chaining_reg}")
        if self.iv_va:
            base += f"  iv_va=0x{self.iv_va:x}  iv={iv_str!r}"
        return base


def _build_reg_table() -> Dict[int, str]:
    if not _CAPSTONE:
        return {}
    tbl: Dict[int, str] = {}
    for n in range(16):
        attr = f"ARM_REG_R{n}"
        if hasattr(arm_const, attr):
            tbl[getattr(arm_const, attr)] = f"r{n}"
    for alias, label in (("ARM_REG_SP", "sp"), ("ARM_REG_LR", "lr"), ("ARM_REG_PC", "pc")):
        if hasattr(arm_const, alias):
            tbl[getattr(arm_const, alias)] = label
    return tbl


_REG_TABLE: Dict[int, str] = {}
_ARM_INS_VEOR: Optional[int] = getattr(arm_const, "ARM_INS_VEOR", None) if _CAPSTONE else None


def _reg_name(reg_id: int) -> str:
    global _REG_TABLE
    if not _REG_TABLE and _CAPSTONE:
        _REG_TABLE = _build_reg_table()
    return _REG_TABLE.get(reg_id, f"r?({reg_id})")


class CustomCBCDetector:
    """Detect hand-rolled AES-128-CBC patterns in ARM32 Thumb2 binaries.

    Scores loop bodies against four structural signals:
      1. BL inside a backward-branch loop                 (40 pts)
      2. 16-byte XOR with a register source               (30 pts)
      3. MOV updates a LDRB base register (CBC chaining)  (20 pts)
      4. Pre-loop LDR of .rodata address into chain reg   (10 pts)

    Patterns scoring >= 50 are returned by scan_range.
    """

    def __init__(self, binary: bytes, load_addr: int = 0) -> None:
        if not _CAPSTONE:
            raise ImportError("capstone required")
        self._binary = binary
        self._load = load_addr
        self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._md.detail = True
        self._md.skipdata = True

    def scan_range(self, va: int, size: int) -> List[CBCPattern]:
        """Scan [va, va+size) for hand-rolled AES-128-CBC loop patterns."""
        off = va - self._load
        if off < 0 or off + size > len(self._binary):
            return []
        insns = list(self._md.disasm(self._binary[off : off + size], va))
        addr_idx: Dict[int, int] = {i.address: n for n, i in enumerate(insns)}
        patterns: List[CBCPattern] = []

        for end_n, insn in enumerate(insns):
            if not insn.id:
                continue
            is_call = capstone.CS_GRP_CALL in insn.groups
            is_jump = capstone.CS_GRP_JUMP in insn.groups
            if not is_jump or is_call:
                continue
            if not insn.operands or insn.operands[0].type != capstone_arm.ARM_OP_IMM:
                continue
            target = insn.operands[0].imm
            if target >= insn.address:
                continue  # forward branch, not a loop back-edge
            start_n = addr_idx.get(target)
            if start_n is None:
                continue

            loop_body = insns[start_n : end_n + 1]
            pre_loop = insns[max(0, start_n - 64) : start_n]
            pat = self._score_loop(loop_body, pre_loop, va)
            if pat is not None and pat.confidence >= 50:
                patterns.append(pat)

        # Deduplicate: keep highest-confidence pattern per loop start VA
        seen: Dict[int, CBCPattern] = {}
        for p in patterns:
            if p.loop_va not in seen or p.confidence > seen[p.loop_va].confidence:
                seen[p.loop_va] = p
        return list(seen.values())

    def scan_function(self, va: int, size: int) -> Optional[CBCPattern]:
        """Analyze a single known-bounds function for CBC loop structure."""
        results = self.scan_range(va, size)
        return max(results, key=lambda p: p.confidence) if results else None

    def _score_loop(
        self,
        loop: List,
        pre: List,
        range_va: int,
    ) -> Optional[CBCPattern]:
        if not loop:
            return None

        # Signal 1: BL (call) inside loop -- the single-block AES function
        bl_targets = [
            (i.address, i.operands[0].imm)
            for i in loop
            if (i.id
                and capstone.CS_GRP_CALL in i.groups
                and i.operands
                and i.operands[0].type == capstone_arm.ARM_OP_IMM)
        ]
        if not bl_targets:
            return None
        confidence = 40

        # Signal 2: 16-byte XOR -- count EOR or VEOR in loop body
        eor_insns = [i for i in loop if i.id and i.id == arm_const.ARM_INS_EOR]
        veor_insns = ([i for i in loop if i.id and i.id == _ARM_INS_VEOR]
                      if _ARM_INS_VEOR is not None else [])
        xor_weight = len(eor_insns) + len(veor_insns) * 16
        xor_va = 0
        if xor_weight >= 4:
            confidence += 30
            first_xor = eor_insns[0] if eor_insns else (veor_insns[0] if veor_insns else None)
            xor_va = first_xor.address if first_xor else loop[0].address

        # Signal 3: MOV Rd, Rs where Rd is a LDRB memory-base register.
        # The register that is both a LDRB base and gets updated by MOV = chaining register.
        ldrb_bases: set = set()
        for i in loop:
            if (i.id == arm_const.ARM_INS_LDRB and len(i.operands) >= 2
                    and i.operands[1].type == capstone_arm.ARM_OP_MEM):
                base = i.operands[1].mem.base
                if base != arm_const.ARM_REG_PC:
                    ldrb_bases.add(base)

        chaining_reg_id: Optional[int] = None
        for i in loop:
            if (i.id and i.id == arm_const.ARM_INS_MOV and len(i.operands) == 2
                    and i.operands[0].reg in ldrb_bases
                    and i.operands[1].type == capstone_arm.ARM_OP_REG):
                chaining_reg_id = i.operands[0].reg
                confidence += 20
                break

        # Signal 4: pre-loop LDR into chaining_reg pointing to non-null .rodata = IV
        iv_va: Optional[int] = None
        iv_bytes: Optional[bytes] = None
        if chaining_reg_id is not None:
            for i in reversed(pre):
                if (i.id and i.id == arm_const.ARM_INS_LDR and len(i.operands) == 2
                        and i.operands[0].reg == chaining_reg_id
                        and i.operands[1].type == capstone_arm.ARM_OP_MEM
                        and i.operands[1].mem.base == arm_const.ARM_REG_PC):
                    ptr_va = (i.address & ~3) + 4 + i.operands[1].mem.disp
                    ptr_off = ptr_va - self._load
                    if 0 <= ptr_off <= len(self._binary) - 4:
                        rodata_va = struct.unpack_from("<I", self._binary, ptr_off)[0]
                        roff = rodata_va - self._load
                        if 0 <= roff <= len(self._binary) - 16:
                            cand = self._binary[roff : roff + 16]
                            if any(b != 0 for b in cand):
                                confidence += 10
                                iv_va = rodata_va
                                iv_bytes = bytes(cand)
                    break

        return CBCPattern(
            outer_func_va=range_va,
            block_func_va=bl_targets[0][1],
            chaining_reg=_reg_name(chaining_reg_id) if chaining_reg_id is not None else "unknown",
            iv_va=iv_va,
            iv_bytes=iv_bytes,
            xor_va=xor_va,
            loop_va=loop[0].address,
            confidence=min(100, confidence),
        )
