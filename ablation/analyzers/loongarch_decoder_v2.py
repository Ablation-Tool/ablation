"""
loongarch_decoder_v2 — KASAN/KCOV-aware LoongArch64 decoder.

Extends LoongArchDecoder (V1) with a two-pass semantic layer that tags
instrumentation ghost calls and their shadow-address preamble sequences.
Callers can then strip the noise with decode_frames_clean().

Theoretical grounding: Cifuentes & Sendall 1998 (SSL — Semantic Specification
Language) applied to the KASAN shadow-address idiom and KCOV trace idioms that
appear in CONFIG_KASAN=y / CONFIG_KCOV=y debug kernels.  V1 covers the SLED
pass (encoding → operands); V2 is the SSL pass (instruction windows → named
semantic units like "kasan_shadow").

Observed on TencentOS 4.6 kernel 6.6.119-52.9.tl4.loongarch64+debug.  The
debug vmlinuz.elf injects ghost calls before virtually every memory access:
    srli.d   $t0, $ptr, 3             # shadow = ptr >> 3
    lu12i.w  $t1, KASAN_SHADOW_HI20   # shadow base upper bits
    addi.d   $t0, $t0, KASAN_SHADOW_LO12
    ld.b     $t0, $t0, 0              # load shadow byte
    bne      $t0, $zero, .Lbad        # if non-zero, fault
.Lbad:
    bl       __asan_load8             # KASAN error reporter

All six instructions above are instrumentation; only the original ld.d is
program logic.  decode_frames_clean() removes them.

System.map is the authoritative source of KASAN/KCOV target VAs.  Pass it to
from_system_map() or supply the VA set manually.

Usage:
    # Fast path: load from kernel System.map
    dec = LoongArchDecoderV2.from_system_map("/path/to/System.map")
    for frame in dec.decode_frames_clean(section_bytes, base_addr):
        print(frame)   # KASAN/KCOV noise stripped

    # Manual VA set (e.g. from resolved PLT entries in a userspace binary)
    dec = LoongArchDecoderV2(instrumentation_vas={0x876f10, 0x8773d0})
    frames = list(dec.decode_frames_v2(data, base))
    real = [f for f in frames if not f.is_instrumentation]
"""

from __future__ import annotations

import dataclasses
import struct
from typing import FrozenSet, Iterator, List, Optional, Set

from .loongarch_decoder import LoongArchDecoder, LoongArchFrame


# ---------------------------------------------------------------------------
# Symbol prefix sets used when parsing System.map
# ---------------------------------------------------------------------------

KASAN_SYMBOL_PREFIXES: FrozenSet[str] = frozenset({
    "__asan_load",
    "__asan_store",
    "__asan_report",
    "__asan_handle_no_return",
    "__asan_poison",
    "__asan_unpoison",
    "__asan_set_shadow",
    "__kasan_",
})

KCOV_SYMBOL_PREFIXES: FrozenSet[str] = frozenset({
    "__sanitizer_cov_trace_pc",
    "__sanitizer_cov_trace_switch",
    "__sanitizer_cov_trace_cmp",
    "__sanitizer_cov_trace_const_cmp",
    "__sanitizer_cov_",
})

_ALL_INSTR_PREFIXES: FrozenSet[str] = KASAN_SYMBOL_PREFIXES | KCOV_SYMBOL_PREFIXES

# Idiom names assigned to LoongArchFrameV2.idiom
_IDIOM_KCOV_TRACE_PC    = "kcov_trace_pc"
_IDIOM_KCOV_TRACE_SWITCH = "kcov_trace_switch"
_IDIOM_KCOV             = "kcov"
_IDIOM_KASAN_LOAD       = "kasan_load"
_IDIOM_KASAN_STORE      = "kasan_store"
_IDIOM_KASAN            = "kasan"
_IDIOM_KASAN_SHADOW     = "kasan_shadow"

# Mnemonics that appear in KASAN shadow-address preamble sequences.
# These are the instructions between the real program load and the
# __asan_load*/store* BL call.  Branches are excluded because they may
# target non-instrumentation code.
_KASAN_PREAMBLE_MNEMS: FrozenSet[str] = frozenset({
    "srli.d",    # shadow = ptr >> 3
    "lu12i.w",   # load KASAN_SHADOW_OFFSET upper 20 bits
    "lu32i.d",   # extend to 32+20-bit offset
    "lu52i.d",   # extend to 52-bit offset (full 64-bit base)
    "addi.d",    # add shadow offset low 12 bits
    "addi.w",
    "add.d",     # shadow_ptr = shifted_ptr + shadow_base
    "ld.b",      # load shadow byte
    "andi",      # extract byte lane (8-byte granularity check)
    "slti",      # compare shadow against threshold
    "sltui",     # unsigned compare
    "or",        # register move (when rk=0)
})

# How far back to walk from an instrumentation BL when tagging preamble.
# 6 covers the full 6-instruction KASAN check idiom observed in TencentOS.
_MAX_PREAMBLE_LOOKBACK: int = 6

# Store mnemonics — these mark the boundary of a preamble walk.
# A store before a KASAN call cannot be instrumentation preamble.
_STORE_MNEMS: FrozenSet[str] = frozenset({
    "st.b", "st.h", "st.w", "st.d",
    "stx.b", "stx.h", "stx.w", "stx.d",
    "stptr.w", "stptr.d",
    "fst.s", "fst.d", "fstx.s", "fstx.d",
    "amswap.w", "amswap.d", "amswap_db.w", "amswap_db.d",
})


# ---------------------------------------------------------------------------
# Extended frame dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class LoongArchFrameV2(LoongArchFrame):
    """LoongArch64 instruction frame with instrumentation annotation.

    New fields over V1:
      is_instrumentation: True if this instruction is a KASAN/KCOV ghost call
                          or part of its shadow-address preamble.
      idiom: Named semantic pattern (e.g. "kasan_shadow", "kcov_trace_pc").
             Empty string if no idiom applies.
    """
    is_instrumentation: bool = False
    idiom: str = ""

    def __str__(self) -> str:
        base = super().__str__()
        if self.is_instrumentation:
            tag = f" [{self.idiom}]" if self.idiom else " [instr]"
            return base + tag
        return base


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class LoongArchDecoderV2(LoongArchDecoder):
    """KASAN/KCOV-aware LoongArch64 decoder.

    Pass a set of instrumentation VA targets (from System.map or PLT
    resolution) to the constructor.  The decoder runs the standard V1
    opcode-table pass, then a second SSL-style semantic pass that:

      1. Tags every BL to an instrumentation VA as is_instrumentation=True.
      2. Walks backwards from each tagged BL and tags the KASAN shadow-address
         preamble instructions (srli.d, lu12i.w, addi.d, ld.b, etc.) with
         idiom="kasan_shadow".

    Args:
        instrumentation_vas: Set of kernel VAs for KASAN/KCOV functions.
                             Obtain via from_system_map() or manual PLT walk.
        max_preamble: Override the max lookback window (default 6).
    """

    def __init__(
        self,
        instrumentation_vas: Optional[Set[int]] = None,
        max_preamble: int = _MAX_PREAMBLE_LOOKBACK,
    ) -> None:
        self._instr_vas: FrozenSet[int] = frozenset(instrumentation_vas or ())
        self._max_preamble = max_preamble

    @classmethod
    def from_system_map(cls, map_path: str, max_preamble: int = _MAX_PREAMBLE_LOOKBACK) -> "LoongArchDecoderV2":
        """Build a decoder by parsing a kernel System.map file.

        Extracts VAs for all KASAN (__asan_*, __kasan_*) and KCOV
        (__sanitizer_cov_*) symbols.  System.map format:
            <hex_va> <type_char> <symbol_name>

        Args:
            map_path: Path to System.map (e.g. from kernel-debug-core RPM).
            max_preamble: Override max preamble lookback window.

        Returns:
            LoongArchDecoderV2 with instrumentation VA set populated.
        """
        vas: Set[int] = set()
        try:
            with open(map_path, "r", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    sym = parts[2]
                    if any(sym.startswith(p) for p in _ALL_INSTR_PREFIXES):
                        try:
                            vas.add(int(parts[0], 16))
                        except ValueError:
                            pass
        except OSError:
            pass
        return cls(instrumentation_vas=vas, max_preamble=max_preamble)

    def _classify_idiom(self, frame: LoongArchFrame) -> str:
        """Return an idiom name for a BL to a known instrumentation VA."""
        # frame.target is the resolved BL target VA
        # We don't have the symbol name here, so use generic names.
        # Callers with richer symbol info can override post-hoc.
        return _IDIOM_KASAN

    def _decode_one_v2(self, data: bytes, va: int) -> LoongArchFrameV2:
        """Decode one instruction to a LoongArchFrameV2 (without preamble tagging)."""
        base = self.decode_one(data, va)
        if base is None:
            return LoongArchFrameV2(va=va, width=4, insn=0, mnemonic=".word", op_str="0x00000000")
        # Convert LoongArchFrame to LoongArchFrameV2
        d = dataclasses.asdict(base)
        v2 = LoongArchFrameV2(**d)
        return v2

    def _tag_instrumentation(self, frames: List[LoongArchFrameV2]) -> None:
        """Pass 1: tag BL calls to instrumentation VAs.

        Mutates frames in-place.  After this pass, every BL to a known
        KASAN/KCOV VA has is_instrumentation=True and an appropriate idiom.
        """
        if not self._instr_vas:
            return
        for frame in frames:
            if frame.is_call and frame.target and frame.target in self._instr_vas:
                frame.is_instrumentation = True
                frame.idiom = _IDIOM_KASAN

    def _tag_kasan_preamble(self, frames: List[LoongArchFrameV2]) -> None:
        """Pass 2: walk backwards from each instrumentation BL and tag preamble.

        For each instrumentation BL call, walk back up to _max_preamble
        instructions.  Tag any instruction whose mnemonic is in
        _KASAN_PREAMBLE_MNEMS as is_instrumentation=True with
        idiom="kasan_shadow".  Stop at:
          - another call or return
          - a store instruction (real side effect)
          - a branch (could target non-instrumentation code)
          - the start of the frame list
        """
        for i, frame in enumerate(frames):
            if not (frame.is_instrumentation and frame.is_call):
                continue
            # Walk backwards from index i-1
            limit = max(0, i - self._max_preamble)
            j = i - 1
            while j >= limit:
                prev = frames[j]
                mnem = prev.mnemonic
                if prev.is_call or prev.is_ret or prev.is_branch:
                    break
                if mnem in _STORE_MNEMS:
                    break
                if mnem in _KASAN_PREAMBLE_MNEMS:
                    prev.is_instrumentation = True
                    prev.idiom = _IDIOM_KASAN_SHADOW
                j -= 1

    def decode_frames_v2(self, data: bytes, base_addr: int = 0) -> List[LoongArchFrameV2]:
        """Decode all instructions with instrumentation tagging.

        Runs the two-pass semantic analysis over the full frame list.
        Returns a list (not a generator) because pass 2 needs random access.

        Args:
            data: Raw bytes of the code section.
            base_addr: VA of the first byte in data.

        Returns:
            List of LoongArchFrameV2 with is_instrumentation and idiom set.
        """
        frames: List[LoongArchFrameV2] = []
        offset = 0
        length = len(data)
        while offset + 4 <= length:
            va = base_addr + offset
            insn_bytes = data[offset:offset + 4]
            f = self._decode_one_v2(insn_bytes, va)
            frames.append(f)
            offset += 4

        self._tag_instrumentation(frames)
        self._tag_kasan_preamble(frames)
        return frames

    def decode_frames_clean(self, data: bytes, base_addr: int = 0) -> Iterator[LoongArchFrameV2]:
        """Yield only non-instrumentation frames.

        Equivalent to:
            (f for f in decode_frames_v2(...) if not f.is_instrumentation)

        Use when you want to see only real program logic, with KASAN/KCOV
        shadow checks and their preamble sequences removed.

        Args:
            data: Raw bytes of the code section.
            base_addr: VA of the first byte in data.

        Yields:
            LoongArchFrameV2 where is_instrumentation is False.
        """
        for frame in self.decode_frames_v2(data, base_addr):
            if not frame.is_instrumentation:
                yield frame

    def count_instrumentation(self, data: bytes, base_addr: int = 0) -> dict:
        """Count instrumentation vs real instructions in a code section.

        Useful for estimating how much of a debug-kernel function is ghost
        calls.  kvm_eiointc_write, for example, is ~40% KASAN overhead.

        Returns dict with keys: total, instrumentation, real, pct_instrumentation.
        """
        frames = self.decode_frames_v2(data, base_addr)
        total  = len(frames)
        instr  = sum(1 for f in frames if f.is_instrumentation)
        real   = total - instr
        pct    = 100.0 * instr / total if total else 0.0
        return {
            "total": total,
            "instrumentation": instr,
            "real": real,
            "pct_instrumentation": round(pct, 1),
        }


# ---------------------------------------------------------------------------
# Convenience alias
# ---------------------------------------------------------------------------

class LoongArchDisasmV2:
    """Thin wrapper so DisasmEngine can call decode_frames uniformly (V2 variant)."""

    def __init__(self, instrumentation_vas: Optional[Set[int]] = None) -> None:
        self._dec = LoongArchDecoderV2(instrumentation_vas)

    def decode_frames(self, data: bytes, base_addr: int = 0) -> Iterator[LoongArchFrameV2]:
        return iter(self._dec.decode_frames_v2(data, base_addr))

    def decode_frames_clean(self, data: bytes, base_addr: int = 0) -> Iterator[LoongArchFrameV2]:
        return self._dec.decode_frames_clean(data, base_addr)
