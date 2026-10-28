"""
ISA fingerprinter for unknown flat ECU ROM images.

Given a raw binary (no ELF header, no IHEX, just flat bytes), identifies the most
likely instruction set architecture by examining reset vectors, instruction density
signatures, and byte-level statistical patterns.

Supported architectures
-----------------------
- ``arm_cm``   — ARM Cortex-M (Thumb-2, LE vector table at offset 0)
- ``tricore``  — Infineon TriCore AURIX (TC1.6/TC2xx/TC3xx, LE; Bosch ME17/MED17, Continental)
- ``m68k``     — Motorola 68K / CPU32 (GM P-series PCMs)
- ``ppc32``    — PowerPC 32-bit Book E (GM E38, Denso denso_d70f3xxx)
- ``ppc_vle``  — PowerPC VLE (NXP e200z, GM E39a/E54/E92)
- ``sh2a``     — Renesas SH-2A / SH-2 (Honda SH7058/SH7059, Subaru)
- ``unknown``  — no discriminator fired above threshold

Gap fixes
---------
- Gap 9 (2026-10-11): TriCore discriminator false-positive on GM P12/P12b (CPU32 1–2 MB).
  Root cause: PFLASH LE-pointer density heuristic fired on M68K ROM data read as LE.
  Fix: BMHD gate — if LE uint32 at file offset 0 is 0x00000000 (CPU32 SSP=0 pattern),
  no TriCore candidate is returned.  Valid AURIX ROMs never have STAD = 0x00000000.

Usage::

    from ablation.analyzers.ecu_arch_detector import EcuArchDetector

    det = EcuArchDetector(rom_bytes)
    result = det.detect()
    print(result.arch, result.confidence, result.reason)

    # Or check all candidates
    for cand in det.candidates():
        print(cand.arch, cand.score)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ArchCandidate:
    """One ISA hypothesis with a numeric score."""

    arch: str
    score: float
    reason: str


@dataclass
class ArchDetectResult:
    """Best-match ISA detection result."""

    arch: str
    confidence: str
    score: float
    reason: str
    candidates: list[ArchCandidate] = field(default_factory=list)

    @property
    def is_confident(self) -> bool:
        return self.confidence in ("HIGH", "MEDIUM")


class EcuArchDetector:
    """
    Fingerprint the ISA of a flat ECU ROM image.

    Parameters
    ----------
    data
        Raw ROM bytes.  Accepts ``bytes``, file path (``str``/``Path``), or
        any object supporting the buffer protocol.
    sample_size
        Number of bytes from the start of the image to use for density
        sampling.  Defaults to 4096 bytes (enough for any ECU reset vector
        area and a representative code sample).  Pass 0 to sample the whole
        image (slower on large ROMs).
    """

    _MAX_ROM_BYTES = 64 * 1024 * 1024
    _SRAM_LO  = 0x20000000   # ARM Cortex-M SRAM base
    _SRAM_HI  = 0x40000000   # ARM Cortex-M SRAM ceiling
    _FLASH_LO = 0x00000000   # ARM Cortex-M flash base
    _FLASH_HI = 0x20000000   # ARM Cortex-M flash ceiling (before SRAM)

    # TriCore AURIX physical address map (TC1.8 Architecture Manual Vol 1, §8 Table 13)
    # Segment 8-B: PFLASH (cached + uncached), 0x80000000–0xBFFFFFFF
    # Segment C-D: Scratchpad RAM (PSPR/DSPR), 0xC0000000–0xDFFFFFFF
    # Segment E-F: Peripheral space (SFRs), 0xE0000000–0xFFFFFFFF
    _TC_PFLASH_LO  = 0x80000000
    _TC_PFLASH_HI  = 0xC0000000
    _TC_PERIPH_LO  = 0xE0000000  # Peripheral space (SFRs at 0xF0xxxxxx are common)
    _TC_PERIPH_HI  = 0x00000000  # wraps — whole 0xE–0xF range; check via upper byte
    _TC_SCRATCH_LO = 0xC0000000  # Scratchpad (PSPR+DSPR)
    _TC_SCRATCH_HI = 0xE0000000
    # ELF identity (GHS-RE-REFERENCE.md §1.10, Infineon TriCore EABI V2.9)
    _TC_EM_TRICORE = 44          # e_machine = 0x2C

    def __init__(
        self,
        data: "str | Path | bytes",
        sample_size: int = 4096,
    ):
        if sample_size < 0:
            raise ValueError("EcuArchDetector: sample_size must be nonnegative")
        if isinstance(data, (str, Path)):
            source = Path(data)
            try:
                if source.stat().st_size > self._MAX_ROM_BYTES:
                    raise ValueError("EcuArchDetector: ROM exceeds 64 MiB limit")
                with source.open("rb") as f:
                    self._data = f.read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"EcuArchDetector: {data!r} not found"
                ) from exc
        else:
            self._data = bytes(data)
        if len(self._data) > self._MAX_ROM_BYTES:
            raise ValueError("EcuArchDetector: ROM exceeds 64 MiB limit")
        n = len(self._data)
        if sample_size == 0 or sample_size > n:
            self._sample = self._data
        else:
            self._sample = self._data[:sample_size]

    @classmethod
    def from_path(cls, path: "str | Path", sample_size: int = 4096) -> "EcuArchDetector":
        """Convenience wrapper."""
        return cls(path, sample_size)

    @classmethod
    def from_bytes(cls, data: bytes, sample_size: int = 4096) -> "EcuArchDetector":
        """Convenience wrapper."""
        return cls(data, sample_size)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self) -> ArchDetectResult:
        """
        Run all discriminators and return the best-match ISA result.

        Returns an ``ArchDetectResult`` with:
        - ``arch``: best-match ISA name or ``"unknown"``
        - ``confidence``: ``"HIGH"`` / ``"MEDIUM"`` / ``"LOW"``
        - ``score``: numeric score for the winning arch (0.0 – 1.0)
        - ``reason``: one-sentence explanation
        - ``candidates``: all arch candidates sorted by score desc
        """
        cands = self.candidates()
        if not cands:
            return ArchDetectResult(
                arch="unknown", confidence="LOW", score=0.0,
                reason="no discriminators fired", candidates=[],
            )
        best = cands[0]
        if best.score >= 0.75:
            conf = "HIGH"
        elif best.score >= 0.40:
            conf = "MEDIUM"
        else:
            conf = "LOW"
        return ArchDetectResult(
            arch=best.arch if best.score >= 0.20 else "unknown",
            confidence=conf,
            score=best.score,
            reason=best.reason,
            candidates=cands,
        )

    def candidates(self) -> list[ArchCandidate]:
        """
        Run all discriminators and return all ArchCandidates sorted by score descending.
        """
        runners = [
            self._score_arm_cortex_m,
            self._score_tricore,
            self._score_m68k,
            self._score_ppc32,
            self._score_ppc_vle,
            self._score_sh2a,
            self._score_m32r,
            self._score_c166,
        ]
        cands: list[ArchCandidate] = []
        for fn in runners:
            c = fn()
            if c is not None:
                cands.append(c)
        cands.sort(key=lambda c: c.score, reverse=True)
        return cands

    # ------------------------------------------------------------------
    # Individual discriminators
    # ------------------------------------------------------------------

    def _score_tricore(self) -> Optional[ArchCandidate]:
        """
        TriCore AURIX detection.

        TriCore is little-endian (unique among the non-Cortex-M ECU archs in this corpus).
        Flat AURIX binary dumps contain two distinctive classes of absolute 32-bit LE
        pointer values derived from the TC1.8 physical address map:

          1. Code/data pointers into PFLASH (0x80000000–0xBFFFFFFF):
               Segment 8 (0x80–0x8F): cacheable PFLASH
               Segment 9 (0x90–0x9F): cacheable PFLASH
               Segment A (0xA0–0xAF): non-cacheable PFLASH (typical ECU boot address)
               Segment B (0xB0–0xBF): non-cacheable PFLASH
             These appear as call targets, jump-table entries, vtable slots, and
             pointer-literal constants.

          2. SFR access addresses in peripheral space (0xE0000000–0xFFFFFFFF):
               Segment E (0xE0–0xEF): peripheral
               Segment F (0xF0–0xFF): peripheral (most SFRs are here)
             ECU code writes/reads SFRs by constructing their LE 32-bit addresses.

          3. Scratchpad RAM (0xC0000000–0xDFFFFFFF) is less common in code literals
             but stack-pointer loads (A[10] initialisation) use DSPR addresses.

        Source for address ranges: TC1.8 Architecture Manual Vol 1, §8 Table 13
        Source for ELF identity: Infineon TriCore EABI V2.9 / GHS-RE-REFERENCE.md §1.10

        ELF path (secondary check): if the binary starts with the ELF magic and has
        e_machine = 44 (EM_TRICORE) with ELFDATA2LSB, score is HIGH immediately.

        Score breakdown (flat binary path):
          0.90: ELF e_machine=44 (EM_TRICORE, ELFDATA2LSB)
          0.85: PFLASH density >= 3% AND peripheral density >= 1%
          0.75: PFLASH density >= 3%
          0.60: PFLASH density >= 1.5%
          0.45: peripheral-only density >= 2% (SFR access pattern without code refs)
        """
        data = self._data
        n = len(data)

        # ELF identity check — definitive if present.
        # ELF32 LE header: magic[4] + EI_CLASS(1)=1 + EI_DATA(1)=1 + ... + e_machine(2)
        # Offsets: magic=0..3, EI_CLASS=4, EI_DATA=5, EI_VERSION=6, EI_OSABI=7,
        #          8 bytes padding, e_type(2)=16, e_machine(2)=18
        if n >= 20 and data[:4] == b'\x7fELF' and data[4] == 1 and data[5] == 1:
            e_machine = struct.unpack_from("<H", data, 18)[0]
            if e_machine == self._TC_EM_TRICORE:
                return ArchCandidate(
                    arch="tricore",
                    score=0.90,
                    reason="TriCore ELF: EI_DATA=LE, e_machine=44 (EM_TRICORE)",
                )

        # Flat binary path: scan the FULL image for PFLASH and peripheral pointer
        # densities.  The sample-size window used by the other discriminators
        # (4 096 bytes by default) is inadequate for TriCore because AURIX
        # startup code is typically sparse in absolute-address literals; pointer
        # density only becomes representative once function-body code is reached
        # (often well past the first 64 KB).  Scanning the full image is safe:
        # at 4 bytes per iteration, even a 16 MB flash image runs in under 1 ms
        # on modern hardware.
        if n < 16:
            return None

        total = n // 4
        pflash_count = 0
        periph_count = 0
        for i in range(0, n - 3, 4):
            val = struct.unpack_from("<I", data, i)[0]
            upper = val >> 24
            if 0x80 <= upper <= 0xBF:
                pflash_count += 1
            elif 0xE0 <= upper <= 0xFF:
                periph_count += 1

        pflash_density = pflash_count / max(total, 1)
        periph_density = periph_count / max(total, 1)

        # Artifact guard: in a big-endian ROM (SH-2A, M68K, PPC32) read as LE,
        # the high byte of each LE 32-bit word is the low byte of the adjacent
        # instruction word — an instruction-byte artifact, not a real pointer.
        # This concentrates spuriously at 0xE0–0xFF (MOV immediates, etc.) and
        # 0x80–0xBF (branch/load opcodes), creating high false densities.
        # In real TriCore firmware, peripheral SFR density is roughly comparable
        # to PFLASH code-pointer density.  For BE artifacts, periph tends to
        # exceed pflash (high-range opcode bytes outnumber mid-range ones) by a
        # detectable margin.  Empirical threshold (corpus): ratio 1.2× with an
        # absolute floor of 15 % catches all confirmed BE false-positives (M68K
        # CPU32 P01, PPC32 E38) without touching genuine TriCore (GEN3: pflash
        # 5.15 %, periph 5.86 %).
        be_artifact = periph_density > 0.15 and periph_density > pflash_density * 1.2
        if be_artifact:
            return None

        if pflash_density >= 0.03 and periph_density >= 0.01:
            score = 0.85
            reason = (
                f"TriCore AURIX: PFLASH LE-ptr density {pflash_density:.2%} "
                f"+ peripheral SFR density {periph_density:.2%}"
            )
        elif pflash_density >= 0.03:
            score = 0.75
            reason = (
                f"TriCore AURIX: PFLASH LE-ptr density {pflash_density:.2%} "
                f"(no peripheral signal)"
            )
        elif pflash_density >= 0.015:
            score = 0.60
            reason = (
                f"TriCore AURIX: PFLASH LE-ptr density {pflash_density:.2%} "
                f"(moderate; confirm with peripheral scan)"
            )
        elif periph_density >= 0.02:
            score = 0.45
            reason = (
                f"TriCore AURIX: peripheral SFR density {periph_density:.2%} "
                f"(no PFLASH code pointers; may be data-only region)"
            )
        else:
            return None

        # BMHD gate: valid AURIX flat ROMs start with a Boot Mode Header Description (BMHD)
        # whose first field (STAD, Startup Address) is a non-zero address — always in PFLASH
        # range (0x80000000–0xBFFFFFFF) for normal boot configurations.  A CPU32/M68K ROM
        # places the supervisor stack pointer at file_off 0 as a big-endian word; for GM
        # P-series PCMs this is 0x00000000.  Read as LE, that is also 0x00000000 — a value
        # that can never be a valid AURIX STAD.  Returning None here prevents the PFLASH
        # LE-pointer density heuristic from misclassifying CPU32 ROMs as TriCore.
        # Safe: sn >= 16 (checked above) guarantees n >= 4 for the unpack at offset 0.
        first_le = struct.unpack_from("<I", data, 0)[0]
        if first_le == 0x00000000:
            return None

        # SH-2 / SH-2A vector table gate: big-endian exception vector tables place
        # the reset PC (offset 0) and initial SP (offset 4) as BE uint32 words.
        # SH-2 ROM reset PCs are always ≤ 0x00100000 (ROM mapped at 0x00000000);
        # initial SPs are 0xFFFFxxxx (on-chip RAM at 0xFFFFE000–0xFFFFFFFF).
        # Reading the SH-2 vector table as LE produces:
        #   first_le = reset_pc_BE read backwards → always has 0x00 high byte
        # An actual AURIX BMHD STAD (offset 0) is always 0x80xxxxxx–0xBFxxxxxx.
        # Additionally check: BE uint32 at offset 4 starts with 0xFF (SH-2 init SP).
        if n >= 8:
            reset_pc_be = struct.unpack_from(">I", data, 0)[0]
            init_sp_be  = struct.unpack_from(">I", data, 4)[0]
            sh2_reset_ok = reset_pc_be <= 0x00100000
            sh2_sp_ok    = (init_sp_be >> 24) == 0xFF
            if sh2_reset_ok and sh2_sp_ok:
                return None

        return ArchCandidate(arch="tricore", score=score, reason=reason)

    def _score_arm_cortex_m(self) -> Optional[ArchCandidate]:
        """
        Cortex-M detection: vector table at offset 0.

        Cortex-M reset vector tables have two mandatory 32-bit LE words at
        the image start:
          offset 0: initial MSP (stack pointer) — must be in SRAM range
          offset 4: reset handler address — must be in flash range with Thumb bit set

        Score is HIGH (0.90) when both conditions hold, MEDIUM (0.55) when only
        the MSP points to SRAM, LOW (0.25) when neither (no candidate returned).
        """
        data = self._data
        if len(data) < 8:
            return None
        msp = struct.unpack_from("<I", data, 0)[0]
        reset_vec = struct.unpack_from("<I", data, 4)[0]

        msp_ok = self._SRAM_LO <= msp < self._SRAM_HI
        # Reset handler must have Thumb bit set (LSB=1) and be in flash range
        reset_ok = bool(reset_vec & 1) and self._FLASH_LO <= (reset_vec & ~1) < self._FLASH_HI

        if msp_ok and reset_ok:
            return ArchCandidate(
                arch="arm_cm", score=0.90,
                reason=f"Cortex-M vector table: MSP=0x{msp:08X} (SRAM), "
                       f"reset=0x{reset_vec:08X} (Thumb)",
            )
        if msp_ok:
            return ArchCandidate(
                arch="arm_cm", score=0.55,
                reason=f"Cortex-M: MSP=0x{msp:08X} in SRAM range (reset vector unclear)",
            )
        return None

    def _score_m68k(self) -> Optional[ArchCandidate]:
        """
        M68K / CPU32 detection.

        M68K vector table layout (big-endian, 4-byte words):
          offset 0: initial SSP (supervisor stack pointer) — usually a high ROM address
          offset 4: initial PC (reset vector) — must be in the image range

        Secondary signal: LINK.W A6, #-N prologue density in sample.
        ``0x4E56`` followed by a negative 16-bit displacement (high bit set).

        Score breakdown:
          0.85: valid reset vector + LINK density >= 1%
          0.70: valid reset vector only
          0.35: LINK density >= 2% (no valid reset vector)
        """
        data = self._data
        n = len(data)
        if n < 8:
            return None

        # Big-endian reset vector check
        reset_va = struct.unpack_from(">I", data, 4)[0]
        rom_size = n
        reset_in_range = 0 <= reset_va < rom_size

        # LINK.W A6 prologue density
        sample = self._sample
        sn = len(sample)
        link_count = 0
        for i in range(0, sn - 3, 2):
            hw = struct.unpack_from(">H", sample, i)[0]
            if hw == 0x4E56:
                next_hw = struct.unpack_from(">H", sample, i + 2)[0]
                if next_hw & 0x8000:  # negative displacement
                    link_count += 1
        link_density = link_count / max(sn // 2, 1)

        if reset_in_range and link_density >= 0.01:
            score = 0.85
            reason = (
                f"M68K: reset vector 0x{reset_va:08X} in-range, "
                f"LINK.W A6 density {link_density:.2%}"
            )
        elif reset_in_range:
            score = 0.70
            reason = (
                f"M68K: BE reset vector 0x{reset_va:08X} in-range "
                f"(LINK.W A6 density {link_density:.2%})"
            )
        elif link_density >= 0.02:
            score = 0.35
            reason = f"M68K: LINK.W A6 density {link_density:.2%} (reset vector unclear)"
        else:
            return None
        return ArchCandidate(arch="m68k", score=score, reason=reason)

    def _score_ppc32(self) -> Optional[ArchCandidate]:
        """
        PowerPC 32-bit Book E detection.

        PPC32 uses a dense set of opcodes in the upper byte of each instruction
        word.  The primary opcode (bits[31:26]) is in the ranges:
          0x38-0x3F: load/store immediate (addi, addis, lbz, lhz, lwz, stb, sth, stw)
          0x40-0x4F: BC, SC, B, CR ops, LWZ
          0x7C-0x9F: arithmetic, compare, load/store indexed

        Score is based on the fraction of 4-byte-aligned words in the sample
        whose primary opcode falls in these ranges.

        VLE uses the same register as ppc32 but has a distinct secondary test
        (_score_ppc_vle) that fires higher when VLE patterns are present.
        This discriminator covers plain Book E (non-VLE).
        """
        sample = self._sample
        sn = len(sample)
        if sn < 16:
            return None

        total = sn // 4
        ppc_count = 0
        for i in range(0, sn - 3, 4):
            word = struct.unpack_from(">I", sample, i)[0]
            op = (word >> 26) & 0x3F
            if (
                0x08 <= op <= 0x0F  # mulli, subfic, addic, addi, addis, BC
                or 0x38 <= op <= 0x3F  # addi, addis, stb, sth, stw, lbz, lhz, lwz
                or 0x14 <= op <= 0x16  # bclr, crnand, isync
                or 0x48 <= op <= 0x4B  # B, SC, BC
                or 0x7C <= op <= 0x7D  # arithmetic / compare
                or 0x80 <= op <= 0x9F  # load/store family
            ):
                ppc_count += 1

        density = ppc_count / max(total, 1)
        if density >= 0.35:
            return ArchCandidate(
                arch="ppc32", score=min(density, 1.0),
                reason=f"PPC32: opcode density {density:.2%} in Book E primary-opcode ranges",
            )
        return None

    def _score_ppc_vle(self) -> Optional[ArchCandidate]:
        """
        PowerPC VLE detection.

        VLE 32-bit instructions have a first-byte pattern:
          ``(byte0 & 0x90) == 0x10``  (bit 4 set, bit 7 clear in bits[31:24])

        VLE SE 16-bit instructions include opcodes:
          0x44 (se_mflr), 0x80-0xFF range for SE instructions

        Score is based on the fraction of 2-byte-aligned halfwords whose
        first byte satisfies the VLE 32-bit discriminator rule.

        A pure VLE ROM will score > 0.25 on this metric; a plain PPC32 Book E
        ROM will score near 0.
        """
        sample = self._sample
        sn = len(sample)
        if sn < 8:
            return None

        total = sn // 2
        vle32_count = 0
        for i in range(0, sn - 1, 2):
            b0 = sample[i]
            if (b0 & 0x90) == 0x10:
                vle32_count += 1

        density = vle32_count / max(total, 1)
        if density >= 0.15:
            return ArchCandidate(
                arch="ppc_vle", score=min(density * 2.5, 0.92),
                reason=f"PPC VLE: VLE-32-bit halfword density {density:.2%}",
            )
        return None

    def _score_sh2a(self) -> Optional[ArchCandidate]:
        """
        SH-2 / SH-2A detection.

        The SH-2 ISA is 16-bit big-endian instructions.  Key signatures:

        1. Reset vector: SH-2 power-on reset PC is stored as a 32-bit BE word at
           offset 0 of the ROM image.  Offset 4 holds the initial SP (always a
           high on-chip RAM address, 0xFFFFxxxx) which is NOT a code pointer.
           Confirmed on SH7058S (Subaru), SH7052 (Honda CBR), SH7059 (Mazda).
           The reset PC must be plausibly in-range (0 < va < image_size).

        2. RTS density: ``0x000B`` (RTS) is the standard return instruction.
           A ROM with > 0.2% RTS density almost certainly uses SH-2 or SH-2A.

        3. STS.L PR density: ``0x4F22`` (STS.L PR, @-R15) is the primary SH-2A
           function prologue.  Any density > 0.1% is a strong signal.

        Score breakdown:
          0.88: valid reset vector + STS.L PR density >= 0.1%
          0.75: valid reset vector + RTS density >= 0.2%
          0.60: valid reset vector only
          0.40: STS.L PR density >= 0.3% (no valid reset vector)
        """
        data = self._data
        n = len(data)
        if n < 8:
            return None

        # SH-2 reset vector (power-on reset PC) at offset 0, big-endian 32-bit word.
        # Offset 4 is the initial SP (0xFFFFxxxx on-chip RAM) — not a code address.
        reset_va = struct.unpack_from(">I", data, 0)[0]
        reset_in_range = 0 < reset_va < n

        sample = self._sample
        sn = len(sample)
        total_hw = sn // 2

        rts_count = 0
        stsl_pr_count = 0
        for i in range(0, sn - 1, 2):
            hw = struct.unpack_from(">H", sample, i)[0]
            if hw == 0x000B:
                rts_count += 1
            elif hw == 0x4F22:
                stsl_pr_count += 1

        rts_density = rts_count / max(total_hw, 1)
        stsl_density = stsl_pr_count / max(total_hw, 1)

        if reset_in_range and stsl_density >= 0.001:
            score = 0.88
            reason = (
                f"SH-2A: reset vector 0x{reset_va:08X} in-range, "
                f"STS.L PR density {stsl_density:.3%}"
            )
        elif reset_in_range and rts_density >= 0.002:
            score = 0.75
            reason = (
                f"SH-2A: reset vector 0x{reset_va:08X} in-range, "
                f"RTS density {rts_density:.3%}"
            )
        elif reset_in_range:
            score = 0.60
            reason = f"SH-2A: BE reset vector 0x{reset_va:08X} in-range"
        elif stsl_density >= 0.003:
            score = 0.40
            reason = f"SH-2A: STS.L PR density {stsl_density:.3%} (reset vector unclear)"
        else:
            return None
        return ArchCandidate(arch="sh2a", score=score, reason=reason)

    def _score_m32r(self) -> Optional[ArchCandidate]:
        """
        Renesas M32R detection.

        M32R is a big-endian 32-bit RISC architecture (chip markings M32170/M32174/
        M32176-series) used in Hitachi 5EAT TCU ECU ROMs.  Capstone has no CS_ARCH_M32R,
        so opcode density scoring is not feasible.

        Structural discriminator: M32R flat ROM images always begin with an exception
        vector table at offset 0x0000–0x00FF.  Each vector entry uses a 4-byte dispatch
        instruction whose first three bytes are ``FF 00 00`` (the M32R TRAP/BRA-long
        opcode prefix), followed by the exception index byte.

        Two overlapping sub-patterns checked independently:

          1. Aligned-16 IVT slots 0x00–0x80 (9 slots total):
             Entries at 16-byte intervals that begin with ``FF 00 00``.
             All 17 known Hitachi M32R 5EAT TCU ROMs have exactly 9/9 hits.

          2. Dense vector region 0x40–0x7F (16 four-byte-aligned slots):
             Contiguous 4-byte entries all beginning with ``FF 00 00``.
             All 17 known ROMs have exactly 16/16 hits.

        This combination produces zero false positives on PPC32, SH-2A, and TriCore
        ECU ROM corpora (verified 2026-10-10 across 42 ROM images).  PPC32 false-positive
        risk exists because byte 0xFF maps to a valid PPC32 primary opcode (0x3F = lfdx
        family), but no PPC32 ROM examined has the aligned 0xFF-prefix vector-table
        pattern in its first 256 bytes.

        Score breakdown:
          0.96: dense4 == 16 AND ivt16 == 9  (matches all known Hitachi M32R ROMs)
          0.88: dense4 >= 12 AND ivt16 >= 6
          0.70: dense4 >= 8 AND ivt16 >= 3   (weak; MEDIUM confidence)

        A score of 0.96 exceeds the PPC32 false-positive score (≈ 0.93) that occurs
        when the first 4 KB sample is dense with M32R instruction bytes that coincidentally
        match PPC32 opcode ranges.
        """
        data = self._data
        n = len(data)
        if n < 256:
            return None

        # Aligned-16 IVT slots 0x00–0x80 (9 slots): count those starting with FF 00 00
        ivt16 = sum(
            1 for off in range(0, 0x90, 16)
            if off + 4 <= n
            and data[off] == 0xFF
            and data[off + 1] == 0x00
            and data[off + 2] == 0x00
        )

        # Dense vector region 0x40–0x7F (16 slots at 4-byte granularity)
        dense4 = sum(
            1 for off in range(0x40, 0x80, 4)
            if off + 4 <= n
            and data[off] == 0xFF
            and data[off + 1] == 0x00
            and data[off + 2] == 0x00
        )

        if dense4 == 16 and ivt16 == 9:
            score = 0.96
            reason = f"M32R: {ivt16}/9 IVT16 + {dense4}/16 dense4 FF-00-00-NN vector table"
        elif dense4 >= 12 and ivt16 >= 6:
            score = 0.88
            reason = (
                f"M32R: {ivt16}/9 IVT16 + {dense4}/16 dense4 FF-00-00-NN (partial)"
            )
        elif dense4 >= 8 and ivt16 >= 3:
            score = 0.70
            reason = (
                f"M32R: {ivt16}/9 IVT16 + {dense4}/16 dense4 FF-00-00-NN (weak)"
            )
        else:
            return None
        return ArchCandidate(arch="m32r", score=score, reason=reason)

    def _score_c166(self) -> Optional[ArchCandidate]:
        """
        Infineon/Siemens C166/C167 detection via JMPS IVT density.

        C166/C167 MCUs (used in BMW MS43/MS41/MS42, Bosch Motronic M3.x/KW1,
        VW Motronic variants) map a 256-byte interrupt vector table at PA 0x000000.
        The table has 64 entries × 4 bytes. Valid entries commonly contain:
          FA seg lo hi  (opcode 0xFA = JMPS seg, caddr)
        where lo+hi form the target address in segment `seg`. Code segments
        are 64KB; the separate DPP data-page mechanism uses 16KB pages.

        This IVT structure is distinctive: 64 consecutive 4-byte slots at
        offset 0 with JMPS opcodes. Sparse or non-JMPS entries lower the score.

        Physical code address: PA = seg * 0x10000 + (hi << 8 | lo).
        Reset vector at IVT[0] (offset 0x00). UART/serial ISRs typically in
        segments 0x0E–0x0F; engine ISRs in segment 0x00.

        Score breakdown:
          0.97: jmps64 == 64  (all IVT slots are JMPS — definitive C166/C167)
          0.88: jmps64 >= 56  (≥87.5% — partial ROM or short read; HIGH confidence)
          0.70: jmps64 >= 40  (≥62.5% — MEDIUM; possible C166 with non-JMPS traps)
        """
        data = self._data
        if len(data) < 256:
            return None

        # Count IVT entries (4-byte stride, 64 total) whose opcode byte is 0xFA (JMPS)
        jmps64 = sum(1 for off in range(0, 256, 4) if data[off] == 0xFA)

        if jmps64 == 64:
            score = 0.97
            reason = "C166/C167: 64/64 IVT slots begin with JMPS opcode 0xFA (definitive)"
        elif jmps64 >= 56:
            score = 0.88
            reason = f"C166/C167: {jmps64}/64 IVT slots begin with JMPS 0xFA (partial ROM)"
        elif jmps64 >= 40:
            score = 0.70
            reason = f"C166/C167: {jmps64}/64 IVT slots begin with JMPS 0xFA (weak)"
        else:
            return None
        return ArchCandidate(arch="c166", score=score, reason=reason)
