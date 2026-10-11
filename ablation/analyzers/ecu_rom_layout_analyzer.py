"""
Entropy-based ROM region analyzer for automotive ECU firmware.

Scans a ROM image in fixed-size windows, classifies each window by Shannon
entropy and fill-byte ratio, then merges adjacent same-class windows into
named regions. Works on any ECU architecture because it operates only on bytes,
not instructions.

Region types:

    ERASED      Fill byte (0xFF or 0x00) proportion above threshold. Never
                contains valid code or calibration data.
    CODE        Entropy above 6.8 bits/byte. Compressed instruction streams
                from TriCore, PPC, SH, M68k all fall here.
    CALIBRATION Entropy between 2.5 and 6.5 bits/byte. Structured numeric
                tables with repeated patterns and bounded value ranges.
    MIXED       Entropy between 6.5 and 6.8 bits/byte. Occurs at code/cal
                boundaries and in packed descriptor tables.
    PADDING     Very low entropy (< 1.5), not erased. Usually zero-fill between
                sections.
    IVT         Interrupt Vector Table region (TriCore only). High-entropy,
                mostly NOPs with sparsely populated vector entries. Looks like
                CODE by entropy but yields almost no real decoded instructions.

arch_hint parameter
~~~~~~~~~~~~~~~~~~~
Pass ``arch_hint="tricore"`` for AURIX/TriCore flat ROM images.  The default
entropy+PPC-density approach misclassifies TriCore code because:

  1. The AURIX Interrupt Vector Table (IVT) — 256 entries × 32 bytes each,
     each containing rslcx/rfe/nop sequences — has high entropy (> 6.5) and
     passes the CODE threshold, but it is NOT navigable application code.
  2. TriCore application code at 4.8–6.5 entropy fails the PPC density check
     (it has very few PPC opcode bytes) and is incorrectly labelled CALIBRATION.
  3. TriCore-compressed OS blobs have entropy ≥ 6.0 and look like CODE.

With ``arch_hint="tricore"`` a Capstone decode-density pass replaces the PPC
opcode density check.  Windows with < 10% decoded bytes are reclassified as
CALIBRATION (compressed / data); windows matching the AURIX IVT NOP pattern
are labelled IVT.

Usage::

    from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer

    ana = EcuROMLayoutAnalyzer.from_path("9663944680.bin")
    layout = ana.analyze()
    print(ana.report(layout))

    # TriCore AURIX flat ROM — use arch_hint for accurate code region detection
    ana_tc = EcuROMLayoutAnalyzer.from_path("GEN3.bin", arch_hint="tricore")
    layout_tc = ana_tc.analyze()
    for r in layout_tc.code_regions():
        print(r)

    # Feed calibration region boundaries to EcuCalibrationTableScanner
    cal_regions = [r for r in layout.regions if r.region_type == "CALIBRATION"]
    for r in cal_regions:
        print(f"0x{r.start:X} - 0x{r.end:X}")
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ROMRegion:
    start: int          # first byte offset (inclusive)
    end: int            # last byte offset (exclusive)
    region_type: str    # ERASED, CODE, CALIBRATION, MIXED, PADDING
    entropy: float      # mean entropy across all windows in this region
    window_count: int   # number of windows merged into this region

    @property
    def size(self) -> int:
        return self.end - self.start

    def __str__(self) -> str:
        return (
            f"0x{self.start:08X}-0x{self.end:08X}  "
            f"{self.region_type:12s}  {self.size // 1024:4d} KB  "
            f"entropy={self.entropy:.2f}"
        )


@dataclass
class ROMLayout:
    file_size: int
    regions: list[ROMRegion]
    window_size: int
    fill_byte: int          # 0xFF for NOR flash, 0x00 for some NAND

    def code_regions(self) -> list[ROMRegion]:
        return [r for r in self.regions if r.region_type in ("CODE", "IVT")]

    def app_code_regions(self) -> list[ROMRegion]:
        """Return only CODE regions (excludes IVT regions)."""
        return [r for r in self.regions if r.region_type == "CODE"]

    def ivt_regions(self) -> list[ROMRegion]:
        return [r for r in self.regions if r.region_type == "IVT"]

    def calibration_regions(self) -> list[ROMRegion]:
        return [r for r in self.regions if r.region_type == "CALIBRATION"]

    def erased_regions(self) -> list[ROMRegion]:
        return [r for r in self.regions if r.region_type == "ERASED"]

    def active_start(self) -> int:
        """Return the first byte offset that is not ERASED or PADDING."""
        for r in self.regions:
            if r.region_type not in ("ERASED", "PADDING"):
                return r.start
        return self.file_size

    def active_end(self) -> int:
        """Return the last byte offset that is not ERASED or PADDING."""
        for r in reversed(self.regions):
            if r.region_type not in ("ERASED", "PADDING"):
                return r.end
        return 0

    def is_calibration_only(self) -> tuple[bool, str]:
        """Return (True, reason) when the image contains no CODE regions.

        OBD tuning tools capture only the calibration flash partition.
        The program flash is absent, so any disassembler or security
        scanner run against such an image produces only false positives.
        Callers should check this before running EcuSecurityAccessScanner
        or any other code-oriented analysis.
        """
        if self.code_regions():
            return (False, "")
        active = [r for r in self.regions if r.region_type not in ("ERASED", "PADDING")]
        if not active:
            return (False, "image is fully erased")
        return (True, "OBD cal-only dump, program flash absent")


class EcuROMLayoutAnalyzer:
    """
    Classify a ROM image into layout regions by entropy.

    Parameters
    ----------
    path_or_data
        Path to the ROM file, or raw bytes.
    window_size
        Entropy window in bytes. 4096 is a good default for 1-4 MB ROM images;
        use 1024 for sub-256 KB images.
    fill_byte
        Erased flash fill byte. NOR flash erases to 0xFF; some NAND to 0x00.
    fill_threshold
        Fill-byte proportion above which a window is classified ERASED.
    """

    # Entropy thresholds (bits/byte).
    # Fixed-width ISAs (PPC32, M68k, TriCore, SH) produce code at 5.4-6.3 bits/byte
    # because aligned 4-byte instructions with clustered opcodes are less random than
    # variable-length x86. We use fill-byte ratio as a second discriminator:
    # real code has almost no fill bytes; sparse calibration tables do.
    _T_PADDING     = 1.5
    _T_CALIBRATION = 2.5
    _T_CAL_UPPER   = 6.5
    _T_MIXED_UPPER = 6.8
    # Fill-byte proportion cutoff: above this the window is treated as sparse
    # calibration even when entropy is in the code range.
    _T_FILL_SPARSE = 0.08

    def __init__(
        self,
        path_or_data: "str | Path | bytes",
        window_size: int = 4096,
        fill_byte: int = 0xFF,
        fill_threshold: float = 0.85,
        arch_hint: str = "",
    ):
        if isinstance(path_or_data, (str, Path)):
            self._data = open(path_or_data, "rb").read()
            self._path = str(path_or_data)
        else:
            self._data = path_or_data
            self._path = "<bytes>"
        self._window_size = window_size
        self._fill_byte = fill_byte
        self._fill_threshold = fill_threshold
        self._arch_hint = arch_hint.lower().strip()

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        window_size: int = 4096,
        fill_byte: int = 0xFF,
        arch_hint: str = "",
    ) -> "EcuROMLayoutAnalyzer":
        return cls(path, window_size, fill_byte, arch_hint=arch_hint)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        window_size: int = 4096,
        fill_byte: int = 0xFF,
        arch_hint: str = "",
    ) -> "EcuROMLayoutAnalyzer":
        return cls(data, window_size, fill_byte, arch_hint=arch_hint)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def analyze(self) -> ROMLayout:
        """Scan the ROM and return a ROMLayout with merged regions."""
        windows = self._scan_windows()
        regions = self._merge_windows(windows)
        return ROMLayout(
            file_size=len(self._data),
            regions=regions,
            window_size=self._window_size,
            fill_byte=self._fill_byte,
        )

    def report(self, layout: Optional["ROMLayout"] = None) -> str:
        if layout is None:
            layout = self.analyze()
        lines = [
            f"EcuROMLayoutAnalyzer  {self._path}",
            f"  file size  : 0x{layout.file_size:X} ({layout.file_size // 1024} KB)",
            f"  window     : {layout.window_size // 1024} KB",
            f"  fill byte  : 0x{layout.fill_byte:02X}",
            f"  regions    : {len(layout.regions)}",
            "",
            f"  {'Start':10s}  {'End':10s}  {'Type':12s}  {'Size':6s}  Entropy",
            "  " + "-" * 58,
        ]
        for r in layout.regions:
            lines.append(
                f"  0x{r.start:08X}  0x{r.end:08X}  {r.region_type:12s}  "
                f"{r.size // 1024:4d}KB  {r.entropy:.2f}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Internal scanning and merging                                        #
    # ------------------------------------------------------------------ #

    def _scan_windows(self) -> list[tuple[int, str, float]]:
        """Return list of (offset, region_type, entropy) for each window."""
        results = []
        data = self._data
        ws = self._window_size
        use_tricore = self._arch_hint == "tricore"
        for i in range(0, len(data), ws):
            chunk = data[i:i + ws]
            ent = _shannon_entropy(chunk)
            fill = chunk.count(self._fill_byte) / len(chunk)
            if use_tricore:
                tc_d, is_ivt = _tricore_density(chunk)
                rtype = self._classify_tricore(ent, fill, tc_d, is_ivt)
            else:
                ppc_d = _ppc_density(chunk, self._PPC_OPCODE_BYTES)
                rtype = self._classify(ent, fill, ppc_d)
            results.append((i, rtype, ent))
        return results

    # Low-entropy ceiling: windows below this entropy cannot be instruction code
    # regardless of fill-byte ratio. Dense calibration tables (lookup arrays,
    # descriptor structs) fall here; instruction streams never do.
    _T_CODE_FLOOR = 4.8

    # PPC32 instruction density threshold for the ambiguous 4.8-6.5 band.
    # True PPC code windows have ~60-70% of 4-byte-aligned words with a high
    # byte in the standard opcode ranges; calibration windows have <10%.
    # A 20% cutoff separates them cleanly across all tested GM PCM images.
    _T_PPC_DENSITY = 0.20

    # PPC32 high-byte opcode ranges (PowerPC Architecture Book v2.02 table A-1)
    _PPC_OPCODE_BYTES = (
        frozenset(range(0x38, 0x40))   # addi/addic/ori/xori/andis/addis
        | frozenset(range(0x80, 0xa0)) # lbz/lhz/lha/lwz/stb/sth/stw loads+stores
        | frozenset(range(0xb0, 0xc0)) # stbu/sthu/stwu/lmw/stmw
        | frozenset({0x48, 0x4c, 0x4e, # b/bl/bc/bclr/bctr branches
                     0x7c, 0x7d, 0x7e, 0x7f,  # integer/compare/move ops
                     0x60, 0x61, 0x62, 0x63,   # ori/oris/xor/xoris/andi
                     0x20, 0x21, 0x28, 0x29,   # lfsx/stfsx/lfsux/stfsux
                     })
    )

    def _classify(self, entropy: float, fill_ratio: float, ppc_density: float = 0.0) -> str:
        if fill_ratio >= self._fill_threshold:
            return "ERASED"
        if entropy <= self._T_PADDING:
            return "PADDING"
        # Four-variable decision for the 2.5-6.5 entropy band:
        #   low entropy (< 4.8)      : always CALIBRATION
        #   sparse fill (>= 8%)      : CALIBRATION (table data with erased padding)
        #   PPC density >= 20%       : CODE (PPC32 instruction stream confirmed)
        #   otherwise                : CALIBRATION (could not confirm as code)
        if entropy <= self._T_CAL_UPPER:
            if entropy < self._T_CODE_FLOOR or fill_ratio >= self._T_FILL_SPARSE:
                return "CALIBRATION"
            if ppc_density >= self._T_PPC_DENSITY:
                return "CODE"
            return "CALIBRATION"
        if entropy <= self._T_MIXED_UPPER:
            return "MIXED"
        return "CODE"

    # TriCore decode-density thresholds.
    # Real TriCore application code: > 35% of bytes decode as valid instructions.
    # AURIX IVT (rslcx/rfe + NOPs): decode rate varies 5–30%; IVT flag is authoritative.
    # TriCore-compressed OS blobs / lookup tables: < 10% decode rate.
    _T_TC_CODE    = 0.35
    _T_TC_DATA    = 0.10

    def _classify_tricore(
        self,
        entropy: float,
        fill_ratio: float,
        tc_density: float,
        is_ivt: bool,
    ) -> str:
        if fill_ratio >= self._fill_threshold:
            return "ERASED"
        if entropy <= self._T_PADDING:
            return "PADDING"
        if entropy < self._T_CODE_FLOOR:
            return "CALIBRATION"
        if fill_ratio >= self._T_FILL_SPARSE:
            return "CALIBRATION"
        # IVT detected by rslcx/rfe vector-entry pattern.
        if is_ivt:
            return "IVT"
        # Capstone decode density discriminates real code from compressed blobs.
        if tc_density >= self._T_TC_CODE:
            return "CODE"
        if tc_density < self._T_TC_DATA:
            return "CALIBRATION"
        # Middle band (10–35%): mixed instruction + data (may be partial code).
        if entropy <= self._T_MIXED_UPPER:
            return "MIXED"
        return "CODE"

    def _merge_windows(
        self, windows: list[tuple[int, str, float]]
    ) -> list[ROMRegion]:
        """Merge adjacent same-type windows into ROMRegion entries."""
        if not windows:
            return []

        regions: list[ROMRegion] = []
        cur_start, cur_type, cur_ent_sum = windows[0]
        cur_count = 1

        for off, rtype, ent in windows[1:]:
            if rtype == cur_type:
                cur_ent_sum += ent
                cur_count += 1
            else:
                end = off
                regions.append(ROMRegion(
                    start=cur_start,
                    end=end,
                    region_type=cur_type,
                    entropy=cur_ent_sum / cur_count,
                    window_count=cur_count,
                ))
                cur_start = off
                cur_type = rtype
                cur_ent_sum = ent
                cur_count = 1

        # Final region
        regions.append(ROMRegion(
            start=cur_start,
            end=len(self._data),
            region_type=cur_type,
            entropy=cur_ent_sum / cur_count,
            window_count=cur_count,
        ))

        return regions

    def detect_reset_vector(self) -> Optional[int]:
        """
        Return the file offset of the MCU reset vector, or None.

        Checks the Infineon TriCore TC1x reset vector at offset 0x100
        (internal flash start after the Boot Mode Header) and the Renesas
        SH705x/SH7058 reset vector at offset 0x00 (word-aligned 32-bit pointer).
        Returns the first non-erased address found at either location.
        """
        data = self._data
        # TriCore: first instruction at flash base + 0x100
        for candidate in (0x100, 0x000, 0x004):
            if candidate + 4 > len(data):
                continue
            word = struct.unpack(">I", data[candidate:candidate + 4])[0]
            if word not in (0xFFFFFFFF, 0x00000000):
                return candidate
        return None


# ------------------------------------------------------------------ #
# Utility                                                              #
# ------------------------------------------------------------------ #

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _ppc_density(data: bytes, opcode_bytes: frozenset) -> float:
    """
    Return the fraction of 4-byte-aligned words whose high byte is in
    opcode_bytes.

    PPC32 instruction streams produce ~60-70% density; calibration data
    produces <10%. This is the tie-breaker in the ambiguous entropy band
    where both fixed-width code and dense numeric tables overlap.
    """
    n = len(data) // 4
    if n == 0:
        return 0.0
    hits = sum(1 for i in range(0, n * 4, 4) if data[i] in opcode_bytes)
    return hits / n


def _tricore_density(data: bytes) -> tuple[float, bool]:
    """Return (decode_density, is_ivt) for a TriCore data window.

    decode_density
        Fraction of bytes that are covered by valid Capstone TriCore 1.6.2
        instructions.  Samples the first 512 bytes of the window for speed;
        returns 0.0 if Capstone is not available.

    is_ivt
        True when the window matches the AURIX Interrupt Vector Table pattern:
        every 32-byte aligned entry contains exactly one ``rslcx`` or ``rfe``
        instruction.  The IVT has high entropy but is NOT navigable application
        code and should not be fed to disassemblers as a code region.

    AURIX IVT signature (TC27x, TC38x, TC39x — all use 32-byte vector entries):
        - 256 entries × 32 bytes = 8 KB per IVT block
        - Each entry ends with ``rfe`` (Return From Exception, 16-bit opcode)
        - Entries are padded with ``nop`` instructions (0x0D 0x00 in LE)
        - At least 8 entries must match for a window to be labelled IVT
          (guards against code that happens to contain a few rfe instructions)
    """
    try:
        import capstone
    except ImportError:
        return 0.0, False

    md = capstone.Cs(capstone.CS_ARCH_TRICORE, capstone.CS_MODE_TRICORE_162)
    md.detail = False

    # Decode the first 512 bytes for density estimation.
    sample = data[:512]
    decoded_bytes = sum(i.size for i in md.disasm(sample, 0))
    density = decoded_bytes / len(sample) if sample else 0.0

    # IVT detection: scan for rslcx/rfe pattern in 32-byte aligned slots.
    # TriCore rslcx = 0x03 0x82 (16-bit SSR format, opcode = 0x03)
    # TriCore rfe   = 0x4E 0x28 (16-bit RET format, opcode = 0x4E ... varies by mode)
    # More reliable: use Capstone mnemonics on the first 8 × 32 = 256 bytes.
    ivt_entry_hits = 0
    entry_size = 32
    for entry_off in range(0, min(len(data), 8 * entry_size), entry_size):
        entry = data[entry_off:entry_off + entry_size]
        for insn in md.disasm(entry, 0):
            if insn.mnemonic in ("rslcx", "rfe", "rfedc"):
                ivt_entry_hits += 1
                break  # one hit per 32-byte entry is enough

    is_ivt = ivt_entry_hits >= 4  # at least 4 of the first 8 entries match

    return density, is_ivt
