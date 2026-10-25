"""
xcoff32_call_scanner.py: stride-based BL call-site scanner for XCOFF32 PPC32 BE.

Why this exists:
  1. Capstone linear disassembly fails on XCOFF32 binaries that embed data words
     or trap instructions (tweq r1,r1 + NULL-word function tables) inside .text.
     For yppasswd (AIX 4.3.3 ML11), Capstone returned 43 of 2658 instructions;
     all callers-of() results from that session were wrong.  Gap ID: AIX-XCOFF32-GAP-001.
  2. XCOFF32Info.callers_of() (aix_bff_extractor.py) solves the same scan problem
     but requires re-parsing from a file path.  It does not integrate with
     XcoffBinary (xcoff_parser.py) or BinaryContext.
  3. After LDREL classification (xcoff_parser.classify_toc_slots), stub VAs can be
     auto-named and all import call sites found in a single .text pass.

How it works:
  - Sweep every 4-byte-aligned word in .text.
  - PPC32 BL (AA=0, LK=1): opcode=18, AA=0, LK=1.
    Mask: (word >> 26) == 18 AND (word & 3) == 1.
    Target: insn_va + sign_extend(LI << 2), where LI = bits[6:29] (24-bit).
  - Return all {target_va: [caller_vas]} unconditionally; caller maps targets
    to import names using classify_toc_slots or binary.imports.

Usage:
    from ablation.analyzers.xcoff32_call_scanner import XCOFF32CallScanner
    from ablation.core.xcoff_parser import parse

    binary = parse('/tmp/yppasswd_431.xcoff')
    scanner = XCOFF32CallScanner.from_binary(binary)

    # All BL instructions: {target_va: [caller_vas]}
    calls = scanner.scan_all()

    # Named import calls: {import_name: [caller_vas]}
    named = scanner.named_calls()
    for name, sites in named.items():
        print(f'{name}: {[hex(v) for v in sites]}')

    # Specific stub:
    sites = scanner.calls_to(0x10002740)   # gets() stub in yppasswd

    # From BinaryContext:
    scanner = XCOFF32CallScanner.from_context(ctx)
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ablation.core.xcoff_parser import XcoffBinary

__all__ = ['XCOFF32CallScanner']

# PPC32 BL (Branch and Link, AA=0, LK=1) opcode filter.
# bits[0:5] = opcode 18 = 0x12; bit[30] = AA=0; bit[31] = LK=1.
# Equivalent: (word >> 26) == 18 and (word & 3) == 1.
_BL_MASK  = 0xFC000003
_BL_MATCH = 0x48000001

# XCOFF32 glink stub: 6 words starting with lwz r12, TOC_SLOT(r2).
# Encoding: opcode=32 (lwz), rt=12, ra=2, d=TOC_SLOT.
# Word: (32<<26) | (12<<21) | (2<<16) | TOC_SLOT = 0x818200xx (low word)
_GLINK_LWZ_MASK = 0xFFFF0000
_GLINK_LWZ_BASE = 0x81820000   # lwz r12, ?(r2)


def _decode_bl_target(insn_va: int, word: int) -> int:
    """Return absolute target VA for a PPC32/64 BL instruction."""
    li = (word >> 2) & 0x00FFFFFF
    if li & 0x800000:
        li -= 0x1000000
    return insn_va + li * 4


class XCOFF32CallScanner:
    """Stride-based BL call-site scanner for stripped XCOFF32 PPC32 BE binaries."""

    def __init__(
        self,
        text_data: bytes,
        text_va: int,
        toc_va: int,
        imports: Optional[Dict[int, str]] = None,   # stub_va → import_name
    ) -> None:
        self._text   = text_data
        self._tva    = text_va
        self._toc_va = toc_va
        # Map from stub VA to import name (built from LDREL or from binary.imports)
        self._imports: Dict[int, str] = imports or {}

    # ── constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_binary(cls, binary: 'XcoffBinary') -> 'XCOFF32CallScanner':
        """Build from an XcoffBinary (xcoff_parser.parse() output).

        Automatically runs classify_toc_slots() to map stub VAs to import names.
        """
        from ablation.core.xcoff_parser import classify_toc_slots

        txt = binary.text
        if txt is None or not txt.data:
            return cls(b'', 0, binary.toc_va)

        # Build stub_va → name from LDREL classification
        stub_map: Dict[int, str] = {}
        try:
            slots = classify_toc_slots(binary)
            for _toc_off, slot in slots.items():
                if slot.kind == 'FUNC_IMPORT' and slot.name:
                    # Compute the stub VA from the TOC slot:
                    # glink stub first word = lwz r12, toc_offset(r2).
                    # Scan .text for that lwz word to locate the stub.
                    lwz_word = _GLINK_LWZ_BASE | (slot.toc_offset & 0xFFFF)
                    stub_va = _find_glink_stub(txt.data, txt.vaddr, lwz_word)
                    if stub_va:
                        stub_map[stub_va] = slot.name
        except Exception:
            pass

        # Fallback: map stubs via binary.imports (names only, no VAs here)
        # The scanner still works without names — calls_to(va) is always available.

        return cls(txt.data, txt.vaddr, binary.toc_va, stub_map)

    @classmethod
    def from_path(cls, path: str) -> 'XCOFF32CallScanner':
        """Build by parsing the XCOFF32 binary at path."""
        from ablation.core.xcoff_parser import parse
        return cls.from_binary(parse(path))

    @classmethod
    def from_context(cls, ctx) -> 'XCOFF32CallScanner':
        """Build from a BinaryContext (uses ctx.path to load XcoffBinary)."""
        from ablation.core.xcoff_parser import parse
        binary = parse(ctx.path)
        return cls.from_binary(binary)

    # ── stub name registration ────────────────────────────────────────────────

    def set_stub(self, stub_va: int, name: str) -> None:
        """Manually register a stub VA → import name mapping."""
        self._imports[stub_va] = name

    # ── scan ─────────────────────────────────────────────────────────────────

    def scan_all(self) -> Dict[int, List[int]]:
        """Return {target_va: [caller_vas]} for every BL in .text.

        Includes both external (stub) calls and internal direct calls.
        """
        result: Dict[int, List[int]] = {}
        for off in range(0, len(self._text) - 3, 4):
            word = struct.unpack_from('>I', self._text, off)[0]
            if (word & _BL_MASK) != _BL_MATCH:
                continue
            insn_va = self._tva + off
            target  = _decode_bl_target(insn_va, word)
            result.setdefault(target, []).append(insn_va)
        return result

    def calls_to(self, target_va: int) -> List[int]:
        """Return all call-site VAs of BL instructions targeting target_va."""
        result: List[int] = []
        for off in range(0, len(self._text) - 3, 4):
            word = struct.unpack_from('>I', self._text, off)[0]
            if (word & _BL_MASK) != _BL_MATCH:
                continue
            insn_va = self._tva + off
            if _decode_bl_target(insn_va, word) == target_va:
                result.append(insn_va)
        return result

    def named_calls(self) -> Dict[str, List[int]]:
        """Return {import_name: [caller_vas]} for all calls to registered stubs.

        Only stubs known via classify_toc_slots or set_stub() are included.
        Use scan_all() for the complete picture including unnamed targets.
        """
        all_calls = self.scan_all()
        named: Dict[str, List[int]] = {}
        for stub_va, name in self._imports.items():
            callers = all_calls.get(stub_va, [])
            if callers:
                named[name] = callers
        return named

    def stub_va(self, import_name: str) -> Optional[int]:
        """Return the stub VA registered for import_name, or None."""
        for va, name in self._imports.items():
            if name == import_name:
                return va
        return None


# ── helpers ───────────────────────────────────────────────────────────────────

def _find_glink_stub(text_data: bytes, text_va: int, lwz_word: int) -> Optional[int]:
    """Scan .text for a glink stub starting with lwz_word; return its VA or None.

    XCOFF32 glink stubs are 6-word sequences starting with:
      lwz r12, TOC_SLOT(r2)   (0x81820000 | toc_slot)

    The stub is always 4-byte aligned and lies outside the function body
    range (typically in the high part of .text).
    """
    for off in range(0, len(text_data) - 3, 4):
        word = struct.unpack_from('>I', text_data, off)[0]
        if word == lwz_word:
            # Verify next word is stw r2, 0x14(r1) = 0x90410014
            if off + 4 < len(text_data):
                next_w = struct.unpack_from('>I', text_data, off + 4)[0]
                if next_w == 0x90410014:
                    return text_va + off
    return None


# ── FORGE gate ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    from ablation.analyzers.forge import FORGE
    FORGE.audit_module(__file__)
