"""XCOFF32 AIX PPC32 BE function decompiler.

Why this exists
---------------
1. No open-source Python-native decompiler handles IBM AIX XCOFF32 binaries.
   Ghidra has partial XCOFF support but is banned from this toolkit; IDA/BN
   are commercial.  Neither understands the full AIX descriptor+TOC pattern.
2. ``Ppc476Decompiler.from_context()`` calls ``lief_parse(ctx.path)`` and
   reads the ELF ``.text`` section — this fails on XCOFF32 format, which LIEF
   does not fully expose as section data.  Every AIX binary (automountd,
   rlogind, ksh93, libc.a members) requires XCOFF32 parsing via xcoff_parser.
3. AIX XCOFF32 has four patterns Ppc476Decompiler does not model:
     a. Function descriptors: sym.va (in .data) ≠ sym.code_va (in .text).
        Decompiling from sym.va produces garbage; must start at code_va.
     b. TOC base: r2 = TOC virtual address (from descriptor[1] or .toc section
        start).  lwz r0, N(r2) loads from a named TOC slot.
     c. Glue trampolines: lwz r0,0(r2); mtctr r0; bctr = call through TOC entry.
        Must be resolved to a symbol name, not emitted as raw *(toc+N)().
     d. csect local functions: C_HIDEXT symbols in .text with dotted names.
        XcoffSymtabParser populates ctx with these; the decompiler uses ctx.name().

AIX PPC32 calling convention
------------------------------
    r1   : stack pointer (stwu r1,-N(r1) = frame allocation)
    r2   : TOC pointer (set at function entry; descriptor[1] = toc_va)
    r3-r10: arguments (r3 = arg0 = first arg / return value)
    r11-r12: scratch / call stub temporaries
    r13  : small-data area (rarely used in AIX user-space)
    r14-r31: callee-saved
    LR   : return address (mflr/mtlr/blr)
    CTR  : count register (bctr = indirect branch)

Function descriptor format (XCOFF32 shared objects)
----------------------------------------------------
    data_va:   uint32_t code_va   (4 bytes, big-endian)
    data_va+4: uint32_t toc_va    (4 bytes, big-endian)
    Symbols in .exports have sym.va = data_va, sym.code_va = code_va (resolved
    by xcoff_parser._resolve_descriptors).

TOC layout
----------
    TOC base (r2) is defined per-module.  Each TOC entry (4 bytes) holds either:
      - Address of a global variable (data pointer)
      - Address of an import function descriptor
      The TOC is indexed as *(r2 + signed_offset) in lwz r0, N(r2) instructions.

Trampoline pattern (call through TOC)
--------------------------------------
    lwz  r0,  N(r2)       # load function descriptor address from TOC
    lwz  r2,  4(r0)       # load callee TOC from descriptor[1]
    mtctr r0              # load code_va into CTR
    bctr                  # jump to code_va (with updated r2)
    Simplified 2-insn form:
    lwz  r12, N(r2)
    mtctr r12; bctr       # r12 = code_va directly (no descriptor load)

Usage
-----
    from ablation.analyzers.xcoff32_decompiler import Xcoff32Decompiler
    from ablation.analyzers.binary_context import BinaryContext

    ctx = BinaryContext.load_or_build('/path/to/automountd')
    dec = Xcoff32Decompiler.from_context(ctx)
    print(dec.decompile(ctx.exports[0].code_va, n_insn=200))

    # Decompile by name:
    va = dec.va_for_name('automount')
    print(dec.decompile(va, n_insn=300))
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    _CS_OK = True
except ImportError:
    _CS_OK = False

from ablation.analyzers.ppc476_decompiler import (
    _Val, _RegFile, _StackFrame, _CFG, _CRState, _LOAD_TYPES, _STORE_TYPES,
)


class Xcoff32Decompiler:
    """C-like pseudocode decompiler for IBM AIX XCOFF32 PPC32 BE binaries.

    Handles AIX-specific patterns absent from Ppc476Decompiler:
    function descriptors, TOC-relative loads, glue trampolines, and
    csect local functions from XcoffSymtabParser.

    Parameters
    ----------
    text_data:
        Raw bytes of the .text section.
    text_va:
        Virtual address of the first byte of text_data.
    toc_va:
        Virtual address of the TOC base (r2 at function entry).
        If 0: TOC lookups emit symbolic offsets instead of resolved names.
    toc_data:
        Raw bytes of the .data section (for TOC entry resolution).
    data_va:
        Virtual address of the first byte of toc_data.
    exports:
        {code_va → name} from BinaryContext / XcoffBinary.exports.
    descriptors:
        {descriptor_va → code_va} for import resolution.
    name_map:
        {va → name} populated by XcoffSymtabParser (C_HIDEXT local functions).
    """

    def __init__(
        self,
        text_data: bytes,
        text_va: int,
        toc_va: int = 0,
        toc_data: bytes = b'',
        data_va: int = 0,
        exports: Dict[int, str] | None = None,
        descriptors: Dict[int, int] | None = None,
        name_map: Dict[int, str] | None = None,
    ) -> None:
        self._text = text_data
        self._text_va = text_va
        self._toc_va = toc_va
        self._toc_data = toc_data
        self._data_va = data_va
        self._exports: Dict[int, str] = exports or {}
        self._descriptors: Dict[int, int] = descriptors or {}
        self._name_map: Dict[int, str] = name_map or {}
        # Merge name sources: exports win over name_map win over hex address.
        self._all_names: Dict[int, str] = {**self._name_map, **self._exports}

    @classmethod
    def from_context(cls, ctx) -> 'Xcoff32Decompiler':
        """Build decompiler from a loaded BinaryContext for an XCOFF32 binary.

        Reads .text and .data sections via xcoff_parser's XcoffBinary (already
        loaded by BinaryContext).  Resolves function descriptors.  Populates
        the TOC base from the first export descriptor.

        Raises ValueError if the binary is not XCOFF32 (magic ≠ 0x01df).
        """
        import struct as _struct
        from pathlib import Path

        path = getattr(ctx, 'path', None)
        if path is None:
            raise ValueError("BinaryContext has no path")

        data = Path(path).read_bytes()
        magic = _struct.unpack_from('>H', data, 0)[0]
        if magic not in (0x01df, 0x01f7):
            raise ValueError(
                f"Not an XCOFF binary (magic=0x{magic:04x}); expected 0x01df or 0x01f7"
            )

        _magic, _nscns = _struct.unpack_from('>HH', data, 0)
        _timdat, _symptr, _nsyms = _struct.unpack_from('>III', data, 4)
        _opthdr, _flags = _struct.unpack_from('>HH', data, 16)
        hdr_sz = 20 + _opthdr

        text_data = b''
        text_va = 0
        toc_data = b''
        data_va = 0

        _STYP_TEXT = 0x0020
        _STYP_DATA = 0x0040

        for sn in range(_nscns):
            off = hdr_sz + sn * 40
            if off + 40 > len(data):
                break
            s_vaddr = _struct.unpack_from('>I', data, off + 12)[0]
            s_size  = _struct.unpack_from('>I', data, off + 16)[0]
            s_scnptr = _struct.unpack_from('>I', data, off + 20)[0]
            s_flags = _struct.unpack_from('>H', data, off + 36)[0]
            if s_flags & _STYP_TEXT and not text_data:
                text_data = data[s_scnptr: s_scnptr + s_size]
                text_va = s_vaddr
            elif s_flags & _STYP_DATA and not toc_data:
                toc_data = data[s_scnptr: s_scnptr + s_size]
                data_va = s_vaddr

        exports: Dict[int, str] = {}
        descriptors: Dict[int, int] = {}

        xcoff_bin = getattr(ctx, '_xcoff_binary', None)
        if xcoff_bin is not None:
            for sym in getattr(xcoff_bin, 'exports', []):
                code = getattr(sym, 'code_va', 0) or sym.va
                if code:
                    exports[code] = sym.name
                if sym.va and code and sym.va != code:
                    descriptors[sym.va] = code
            for sym in getattr(xcoff_bin, 'imports', []):
                if sym.va:
                    exports[sym.va] = sym.name

        name_map: Dict[int, str] = {}
        names_cache = getattr(ctx, '_names', None)
        if names_cache is not None:
            for va, entry in names_cache.items():
                nm = entry[0] if isinstance(entry, (list, tuple)) else str(entry)
                if nm and not nm.startswith('sub_') and not nm.startswith('0x'):
                    name_map[va] = nm

        toc_va = 0
        if toc_data and data_va:
            # TOC base: use first export descriptor's toc_va field (descriptor[1]).
            for sym_va, code_va in descriptors.items():
                off = sym_va - data_va
                if 0 <= off + 8 <= len(toc_data):
                    toc_va = _struct.unpack_from('>I', toc_data, off + 4)[0]
                    if toc_va:
                        break

        return cls(
            text_data=text_data,
            text_va=text_va,
            toc_va=toc_va,
            toc_data=toc_data,
            data_va=data_va,
            exports=exports,
            descriptors=descriptors,
            name_map=name_map,
        )

    def va_for_name(self, name: str) -> Optional[int]:
        """Return the code VA for a function name, or None if not found."""
        for va, nm in self._all_names.items():
            if nm == name:
                return va
        return None

    def decompile(self, func_va: int, n_insn: int = 200) -> str:
        """Decompile up to n_insn PPC32 instructions starting at func_va.

        Parameters
        ----------
        func_va:
            Code VA to start decompilation from.  For XCOFF32 shared objects,
            pass ``sym.code_va`` (not the descriptor VA ``sym.va``).
        n_insn:
            Maximum number of instructions to process.

        Returns
        -------
        str
            C-like pseudocode as a multi-line string.
        """
        if not _CS_OK:
            return '// capstone unavailable — pip install capstone'

        insns = self._disasm(func_va, n_insn)
        if not insns:
            return (
                f'// Xcoff32Decompiler: func_va {hex(func_va)} not in .text '
                f'(text_va={hex(self._text_va)}, '
                f'text_end={hex(self._text_va + len(self._text))})'
            )

        cfg   = _CFG(insns)
        regs  = _RegFile()
        regs.set(2, _Val.expr(f'toc/*{hex(self._toc_va)}*/', regs._r.get(2, _Val.expr('toc')).type_))
        frame = _StackFrame()
        cr    = _CRState()

        fn_name = self._all_names.get(func_va, f'sub_{func_va:#x}')
        lines: List[str] = []
        lines.append(f'// Xcoff32Decompiler: {fn_name} @ {hex(func_va)}  (toc={hex(self._toc_va)})')
        lines.append(f'auto {fn_name}(auto arg0, auto arg1, auto arg2, auto arg3) {{')

        decls_str = frame.declarations()

        body: List[str] = []
        for va, mn, op in insns:
            if cfg.is_branch_target(va):
                body.append(f'loc_{va:#x}:')

            line = self._emit(va, mn, op, regs, frame, cr, cfg)
            if line:
                body.append(f'  {line}')

            if mn == 'blr':
                break
            if mn.startswith('b') and not op and not mn.startswith('bl'):
                break

        if decls_str:
            lines.append('  // locals')
            lines.append(decls_str.rstrip())

        lines.extend(body)
        lines.append('}')
        return '\n'.join(lines)

    def _disasm(self, va: int, n_insn: int) -> List[Tuple[int, str, str]]:
        """Disassemble PPC32 BE instructions from .text starting at va."""
        if not _CS_OK:
            return []
        off = va - self._text_va
        if off < 0 or off >= len(self._text):
            return []
        code = self._text[off: off + n_insn * 4]
        md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        md.detail = False
        result = []
        for insn in md.disasm(code, va):
            result.append((insn.address, insn.mnemonic, insn.op_str))
            if len(result) >= n_insn:
                break
        return result

    def _resolve_toc(self, offset: int) -> str:
        """Resolve a TOC-relative offset to a name or address string.

        offset is SIGNED (as used in lwz r0, N(r2)).
        Returns e.g. 'strlen' if the TOC entry at r2+offset holds a descriptor
        for strlen, else 'toc+0x38' if unresolved.
        """
        if not self._toc_va or not self._toc_data:
            return f'toc+{offset:#x}' if offset >= 0 else f'toc-{(-offset):#x}'
        addr = self._toc_va + offset
        idx = addr - self._data_va
        if 0 <= idx + 4 <= len(self._toc_data):
            target = struct.unpack_from('>I', self._toc_data, idx)[0]
            if target in self._all_names:
                return self._all_names[target]
            if target in self._descriptors:
                code = self._descriptors[target]
                if code in self._all_names:
                    return self._all_names[code]
        label = offset if offset >= 0 else f'-{hex(-offset)}'
        return f'toc+{hex(offset)}' if offset >= 0 else f'toc-{hex(-offset)}'

    # ─────────────────────────────────────────────────────────────────────
    # Instruction pattern tables used by _emit
    # ─────────────────────────────────────────────────────────────────────

    # Mnemonics that are pure prologue/epilogue or synchronization — suppressed.
    # NOTE: 'ori' is NOT suppressed here because it may be a real OR-immediate.
    # The ori r0,r0,0 = nop case is handled in _emit by checking operands.
    _SUPPRESS = frozenset({
        'mflr', 'mtlr', 'nop',
        'stmw',                            # callee-save block — prologue only
        'lmw',                             # callee-restore block — epilogue only
        'mfcr', 'mtcrf', 'mtocrf',
        'isync', 'sync', 'lwsync', 'eieio',
        'tlbie', 'tlbsync', 'slbia', 'slbie',
    })

    # Two-register arithmetic: dst = src1 OP src2
    _BIN_REG3 = {
        'add': '+', 'add.': '+',
        'subf': '-', 'subf.': '-',
        'mullw': '*', 'mullw.': '*',
        'divw': '/', 'divwu': '/u',
        'and': '&', 'and.': '&',
        'or': '|', 'or.': '|',
        'xor': '^', 'xor.': '^',
        'nand': '~&', 'nand.': '~&',
        'nor': '~|', 'nor.': '~|',
        'andc': '&~', 'andc.': '&~',
        'orc': '|~', 'orc.': '|~',
        'eqv': '==', 'eqv.': '==',
        'slw': '<<', 'slw.': '<<',
        'srw': '>>', 'srw.': '>>',
        'sraw': '>>a', 'sraw.': '>>a',
        'mulhw': 'mulhi', 'mulhwu': 'mulhiu',
        'addc': '+c', 'adde': '+e',
    }

    # Immediate arithmetic: dst = src OP imm16
    _BIN_IMM = {
        'addi': '+', 'subfic': '-', 'mulli': '*',
        'andi.': '&', 'andis.': '<<16&',
        'ori': '|', 'oris': '<<16|',
        'xori': '^', 'xoris': '<<16^',
        'srawi': '>>a', 'srawi.': '>>a',
    }

    # Class-level load/store tables (avoid per-call re-construction in _emit)
    _ALL_LOADS: Dict[str, str] = {
        'lwz': 'uint32_t', 'lwa': 'int32_t', 'lwzu': 'uint32_t',
        'lhz': 'uint16_t', 'lha': 'int16_t', 'lhzu': 'uint16_t',
        'lbz': 'uint8_t', 'lbzu': 'uint8_t',
        'lfs': 'float', 'lfd': 'double',
        'lwax': 'int32_t', 'lhax': 'int16_t',
        'lwzx': 'uint32_t', 'lhzx': 'uint16_t', 'lbzx': 'uint8_t',
        'ld': 'uint64_t',
    }
    _ALL_STORES: Dict[str, str] = {
        'stw': 'uint32_t', 'stwu': 'uint32_t', 'stwx': 'uint32_t',
        'sth': 'uint16_t', 'sthu': 'uint16_t', 'sthx': 'uint16_t',
        'stb': 'uint8_t', 'stbu': 'uint8_t', 'stbx': 'uint8_t',
        'stfs': 'float', 'stfd': 'double',
        'std': 'uint64_t', 'stdx': 'uint64_t',
    }

    def _emit(
        self,
        va: int,
        mn: str,
        op: str,
        regs: _RegFile,
        frame: _StackFrame,
        cr: _CRState,
        cfg: _CFG,
    ) -> Optional[str]:
        """Emit one pseudocode line for (mn, op).  Returns None to suppress.

        Covers all major PPC32 BE instruction families:
          - Frame management (stwu sp, mflr/mtlr)
          - Load / store (all widths, TOC-relative, indexed)
          - Arithmetic (add, sub, mul, div, with and without carry)
          - Logical (and, or, xor, nand, nor, andc, orc, eqv)
          - Shifts and rotates (slw, srw, sraw, srawi, rlwinm, rlwimi, rldicl)
          - Load immediate (li, lis, addis for address synthesis)
          - Moves (mr, fmr, mfspr, mtspr)
          - Compare (cmpwi/cmpw/cmplwi/cmplw; updates CR for branches)
          - Branches (b, bl, blr, bctr, conditional b*)
          - Sign/zero extension (extsb, extsh, extsw)
          - Count / population (cntlzw, popcntw)
          - Prologue/epilogue mechanics → suppressed
        """
        parts = [p.strip() for p in op.split(',')]

        def regnum(s: str) -> int:
            s = s.strip()
            if s.startswith('r'):
                try:
                    return int(s[1:])
                except ValueError:
                    pass
            if s.startswith('f'):
                try:
                    return int(s[1:]) + 64   # FPRs offset by 64 to avoid collision
                except ValueError:
                    pass
            try:
                return int(s, 0)
            except ValueError:
                return -1

        def imm(s: str) -> int:
            s = s.strip()
            try:
                return int(s, 0)
            except ValueError:
                return 0

        def signed16(v: int) -> int:
            v &= 0xFFFF
            return v if v < 0x8000 else v - 0x10000

        def mem_parts(s: str) -> Tuple[int, int]:
            """Parse 'N(rX)' → (N as signed int, register number)."""
            try:
                disp_s, rest = s.split('(', 1)
                base = regnum(rest.rstrip(')'))
                return signed16(imm(disp_s)), base
            except (ValueError, AttributeError):
                return 0, 1

        def rv(r: int) -> str:
            """Readable register value string."""
            return str(regs.get(r))

        # ── Completely suppress prologue/epilogue noise ───────────────────
        if mn in self._SUPPRESS:
            # Suppress callee-save stw rN, off(r1) for N >= 14
            if mn == 'stmw':
                return None
            if mn == 'lmw':
                # On return: clobber nothing; values from stack not tracked.
                return None
            return None

        # Suppress individual callee-save stw/lwz for rN (N>=14) relative to sp.
        if mn in ('stw', 'lwz') and len(parts) >= 2:
            r = regnum(parts[0])
            d, b = mem_parts(parts[1])
            if b == 1 and r >= 14:
                # Callee-save / callee-restore — prologue/epilogue mechanics.
                return None

        # ── Frame allocation: stwu r1, -N(r1) ────────────────────────────
        if mn == 'stwu' and len(parts) >= 2:
            d, b = mem_parts(parts[1])
            if b == 1 and regnum(parts[0]) == 1:
                frame.record_frame(d)
                return f'// frame: sp -= {abs(d)}'

        # ── LR / CTR management ───────────────────────────────────────────
        if mn == 'mtctr' and parts:
            src = regnum(parts[0])
            regs.set(32, regs.get(src))
            return None  # absorbed into bctr emission

        if mn == 'mflr' and parts:
            dst = regnum(parts[0])
            regs.set(dst, _Val.expr('LR', 'void *'))
            return None  # prologue; not shown

        if mn == 'mtlr' and parts:
            return None  # epilogue; not shown

        if mn == 'mfctr' and parts:
            dst = regnum(parts[0])
            regs.set(dst, regs.get(32))
            return None

        # ── mfspr / mtspr (SPR access: LR=8, CTR=9, XER=1, SPRG0-3) ─────
        if mn == 'mfspr' and len(parts) >= 2:
            dst = regnum(parts[0])
            spr = imm(parts[1])
            spr_name = {8: 'LR', 9: 'CTR', 1: 'XER', 256: 'SPRG0'}.get(spr, f'spr{spr}')
            regs.set(dst, _Val.expr(spr_name))
            return f'r{dst} = {spr_name};'
        if mn == 'mtspr' and len(parts) >= 2:
            spr = imm(parts[0])
            src_r = regnum(parts[1])
            spr_name = {8: 'LR', 9: 'CTR', 1: 'XER', 256: 'SPRG0'}.get(spr, f'spr{spr}')
            if spr == 9:
                regs.set(32, regs.get(src_r))
            return None  # SPR stores are internals

        # ── Direct branch-and-link ────────────────────────────────────────
        if mn in ('bl', 'bla') and parts:
            target = imm(parts[0])
            sym = self._all_names.get(target, f'sub_{target:#x}')
            args = ', '.join(rv(3 + i) for i in range(4))
            regs.clobber_caller_saves()
            regs.set(3, _Val.call_ret(sym))
            return f'r3 = {sym}({args});'

        # ── Indirect call through CTR ─────────────────────────────────────
        if mn in ('bctr', 'bctrl'):
            ctr_val = regs.get(32)
            sym_text = ctr_val.text
            if sym_text and not sym_text.startswith('r') and 'toc' not in sym_text:
                sym = sym_text.lstrip('&')
                args = ', '.join(rv(3 + i) for i in range(4))
                regs.clobber_caller_saves()
                regs.set(3, _Val.call_ret(sym))
                return f'r3 = {sym}({args});'
            args = ', '.join(rv(3 + i) for i in range(4))
            regs.clobber_caller_saves()
            return f'r3 = (*ctr)({args});'

        # ── Return ────────────────────────────────────────────────────────
        if mn == 'blr':
            ret_val = regs.get(3)
            return f'return {ret_val};'

        # ── Unconditional branch ──────────────────────────────────────────
        if mn in ('b', 'ba') and parts:
            target = imm(parts[0])
            sym = self._all_names.get(target)
            if cfg.is_back_edge(va):
                return f'goto loc_{target:#x};  // loop'
            if sym:
                return f'goto {sym};'
            return f'goto loc_{target:#x};'

        # ── Conditional branch ────────────────────────────────────────────
        if mn.startswith('b') and len(parts) >= 1:
            cond_expr, target_hex = cr.decode(mn, op)
            if cond_expr is None:
                return f'// [{hex(va)}] {mn} {op}'
            try:
                target = int(target_hex, 0)
            except (ValueError, TypeError):
                target = 0
            if target:
                sym = self._all_names.get(target, f'loc_{target:#x}')
                return f'if ({cond_expr}) goto {sym};'
            return f'if ({cond_expr}) goto {target_hex};'

        # ── Compare instructions → update CR for next branch ─────────────
        if mn in ('cmpwi', 'cmplwi', 'cmpw', 'cmplw',
                  'cmpdi', 'cmpldi', 'cmpd', 'cmpld') and len(parts) >= 2:
            cr_field = 0
            idx = 0
            if parts[0].startswith('cr'):
                try:
                    cr_field = int(parts[0][2:])
                    idx = 1
                except ValueError:
                    pass
            lhs_r = regnum(parts[idx]) if idx < len(parts) else 0
            rhs = parts[idx + 1].strip() if idx + 1 < len(parts) else '0'
            unsigned = 'l' in mn
            cr.update(cr_field, rv(lhs_r), rhs, unsigned)
            return None  # consumed by next branch

        # ── TOC-relative load (r2 base) ───────────────────────────────────
        if mn in ('lwz', 'ld', 'lwa', 'lwzu') and len(parts) >= 2:
            d, b = mem_parts(parts[1])
            if b == 2:
                dst = regnum(parts[0])
                sym = self._resolve_toc(d)
                regs.set(dst, _Val.expr(sym))
                return f'r{dst} = {sym};  // TOC+{d}'

        # ── Load (all widths) ─────────────────────────────────────────────
        if mn in self._ALL_LOADS and len(parts) >= 2:
            dst = regnum(parts[0])
            t = self._ALL_LOADS[mn]
            if '(' in parts[1]:
                d, b = mem_parts(parts[1])
                base_v = rv(b)
                if b == 1:
                    name = frame.slot(d, t)
                    regs.set(dst, _Val.local(name, t))
                    return f'r{dst} = {name};  // {t}'
                regs.set(dst, _Val.expr(f'*({t}*)({base_v}+{d})', t))
                return f'r{dst} = *({t}*)({base_v}+{d});'
            elif len(parts) >= 3:
                # indexed form: rD, rA, rB
                ra = regnum(parts[1]); rb = regnum(parts[2])
                regs.set(dst, _Val.expr(f'*({t}*)({rv(ra)}+{rv(rb)})', t))
                return f'r{dst} = *({t}*)({rv(ra)}+{rv(rb)});'

        # ── Store (all widths) ────────────────────────────────────────────
        if mn in self._ALL_STORES and len(parts) >= 2:
            src = regnum(parts[0])
            t = self._ALL_STORES[mn]
            if '(' in parts[1]:
                d, b = mem_parts(parts[1])
                if b == 1:
                    # Callee-save already suppressed above (rN>=14).
                    name = frame.slot(d, t)
                    return f'{name} = {rv(src)};  // {t}'
                return f'*({t}*)({rv(b)}+{d}) = {rv(src)};'
            elif len(parts) >= 3:
                ra = regnum(parts[1]); rb = regnum(parts[2])
                return f'*({t}*)({rv(ra)}+{rv(rb)}) = {rv(src)};'

        # ── Move register ─────────────────────────────────────────────────
        if mn in ('mr', 'mr.', 'fmr') and len(parts) >= 2:
            dst = regnum(parts[0]); src = regnum(parts[1])
            regs.set(dst, regs.get(src))
            return f'r{dst} = r{src};'

        # ── Load immediate ────────────────────────────────────────────────
        if mn == 'li' and len(parts) >= 2:
            dst = regnum(parts[0]); v = imm(parts[1])
            regs.set(dst, _Val.const(v))
            return f'r{dst} = {parts[1]};'

        if mn == 'lis' and len(parts) >= 2:
            # lis rD, N  → r[D] = N << 16  (2-arg canonical form)
            dst = regnum(parts[0]); hi = imm(parts[1])
            v = (hi << 16) & 0xFFFFFFFF
            regs.set(dst, _Val.const(v))
            return f'r{dst} = {hex(v)};  // lis'

        if mn == 'addis' and len(parts) >= 3:
            # addis rD, rA, N  → r[D] = r[A] + (N << 16); or lis if rA == 0
            dst = regnum(parts[0]); base_r = regnum(parts[1]); hi = imm(parts[2])
            if base_r == 0:
                v = (hi << 16) & 0xFFFFFFFF
                regs.set(dst, _Val.const(v))
                return f'r{dst} = {hex(v)};  // lis'
            base_v = regs.get(base_r)
            if base_v.kind == 'const':
                try:
                    v = (int(base_v.text, 0) + (hi << 16)) & 0xFFFFFFFF
                    regs.set(dst, _Val.const(v))
                    return f'r{dst} = {hex(v)};  // addis'
                except ValueError:
                    pass
            regs.set(dst, _Val.expr(f'{base_v}+{hex(hi << 16)}'))
            return f'r{dst} = {base_v} + {hex(hi << 16)};'

        # ── Add immediate (addi / la / subi alias) ────────────────────────
        if mn in ('addi', 'la') and len(parts) >= 3:
            dst = regnum(parts[0]); base = regnum(parts[1]); off = signed16(imm(parts[2]))
            if base == 0:
                regs.set(dst, _Val.const(off))
                return f'r{dst} = {off};  // li'
            base_v = regs.get(base)
            if base == 1:
                name = frame.slot(off, 'void *')
                regs.set(dst, _Val.ptr_local(name))
                return f'r{dst} = &{name};'
            if base_v.kind == 'const':
                v = (int(base_v.text, 0) + off) & 0xFFFFFFFF
                regs.set(dst, _Val.const(v))
                return f'r{dst} = {hex(v)};'
            new_v = _Val.expr(f'{base_v}+{off}')
            regs.set(dst, new_v)
            return f'r{dst} = {base_v} + {off};'

        # ── Two-register binary operations ────────────────────────────────
        if mn in self._BIN_REG3 and len(parts) >= 3:
            dst = regnum(parts[0]); ra = regnum(parts[1]); rb = regnum(parts[2])
            op_sym = self._BIN_REG3[mn]
            if op_sym in ('mulhi', 'mulhiu'):
                regs.set(dst, _Val.expr(f'{op_sym}({rv(ra)}, {rv(rb)})'))
                return f'r{dst} = {op_sym}({rv(ra)}, {rv(rb)});'
            if op_sym in ('+c', '+e'):
                regs.set(dst, _Val.expr(f'{rv(ra)} + {rv(rb)}'))
                return f'r{dst} = {rv(ra)} + {rv(rb)};  // with carry'
            if mn == 'subf':
                regs.set(dst, _Val.expr(f'{rv(rb)} - {rv(ra)}'))
                return f'r{dst} = {rv(rb)} - {rv(ra)};'
            regs.set(dst, _Val.expr(f'{rv(ra)} {op_sym} {rv(rb)}'))
            return f'r{dst} = {rv(ra)} {op_sym} {rv(rb)};'

        # ── Immediate binary operations ───────────────────────────────────
        if mn in self._BIN_IMM and len(parts) >= 3:
            dst = regnum(parts[0]); src_r = regnum(parts[1]); iv = imm(parts[2])
            op_sym = self._BIN_IMM[mn]
            if op_sym == '+':
                v = _Val.expr(f'{rv(src_r)} + {iv}')
            elif op_sym in ('<<16+', '<<16&', '<<16|'):
                real_op = op_sym[4:]
                v = _Val.expr(f'{rv(src_r)} {real_op} {hex(iv << 16)}')
                return f'r{dst} = {rv(src_r)} {real_op} {hex(iv << 16)};'
            elif op_sym == '>>a':
                v = _Val.expr(f'{rv(src_r)} >> {iv}  /* arithmetic */')
            elif op_sym == '-':
                v = _Val.expr(f'{rv(src_r)} - {iv}')
            else:
                v = _Val.expr(f'{rv(src_r)} {op_sym} {iv}')
            regs.set(dst, v)
            return f'r{dst} = {rv(src_r)} {op_sym} {iv};'

        # ── Rotate / shift immediates ─────────────────────────────────────
        if mn in ('rlwinm', 'rlwinm.') and len(parts) >= 5:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            sh = imm(parts[2]); mb = imm(parts[3]); me = imm(parts[4])
            if mb == 0 and me == 31 - sh:
                regs.set(dst, _Val.expr(f'{rv(src_r)} << {sh}'))
                return f'r{dst} = {rv(src_r)} << {sh};  // slwi'
            if sh == 32 - (me - mb + 1) and mb == 0:
                regs.set(dst, _Val.expr(f'{rv(src_r)} >> {32 - sh}'))
                return f'r{dst} = {rv(src_r)} >> {32 - sh};  // srwi'
            mask = ((2 << (31 - mb)) - 1) & ~((1 << (32 - 1 - me)) - 1) if mb <= me else 0
            regs.set(dst, _Val.expr(f'rlwinm({rv(src_r)},{sh},{mb},{me})'))
            return f'r{dst} = rlwinm({rv(src_r)}, {sh}, {mb}, {me});'

        if mn in ('rlwimi', 'rlwimi.') and len(parts) >= 5:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            sh = imm(parts[2]); mb = imm(parts[3]); me = imm(parts[4])
            regs.set(dst, _Val.expr(f'rlwimi(r{dst},{rv(src_r)},{sh},{mb},{me})'))
            return f'r{dst} = rlwimi(r{dst}, {rv(src_r)}, {sh}, {mb}, {me});'

        if mn in ('rotlwi',) and len(parts) >= 3:
            dst = regnum(parts[0]); src_r = regnum(parts[1]); sh = imm(parts[2])
            regs.set(dst, _Val.expr(f'rotl({rv(src_r)}, {sh})'))
            return f'r{dst} = rotl({rv(src_r)}, {sh});'

        # ── Unary / single-register ops ───────────────────────────────────
        if mn in ('neg', 'neg.') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'-{rv(src_r)}'))
            return f'r{dst} = -{rv(src_r)};'

        if mn in ('extsb', 'extsb.') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'(int8_t){rv(src_r)}'))
            return f'r{dst} = (int8_t){rv(src_r)};'

        if mn in ('extsh', 'extsh.') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'(int16_t){rv(src_r)}'))
            return f'r{dst} = (int16_t){rv(src_r)};'

        if mn in ('extsw', 'extsw.') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'(int32_t){rv(src_r)}'))
            return f'r{dst} = (int32_t){rv(src_r)};'

        if mn in ('cntlzw', 'cntlzw.', 'cntlzd') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'clz({rv(src_r)})'))
            return f'r{dst} = clz({rv(src_r)});'

        if mn in ('popcntw', 'popcntb') and len(parts) >= 2:
            dst = regnum(parts[0]); src_r = regnum(parts[1])
            regs.set(dst, _Val.expr(f'popcount({rv(src_r)})'))
            return f'r{dst} = popcount({rv(src_r)});'

        # ── Floating-point arithmetic ─────────────────────────────────────
        _FP_BIN = {
            'fadd': '+', 'fadds': '+', 'fsub': '-', 'fsubs': '-',
            'fmul': '*', 'fmuls': '*', 'fdiv': '/', 'fdivs': '/',
        }
        if mn in _FP_BIN and len(parts) >= 3:
            dst = regnum(parts[0]); ra = regnum(parts[1]); rb = regnum(parts[2])
            op_sym = _FP_BIN[mn]
            regs.set(dst, _Val.expr(f'f{dst}'))
            return f'f{dst - 64} = f{ra - 64} {op_sym} f{rb - 64};'

        if mn in ('fmadd', 'fmadds', 'fnmadd') and len(parts) >= 4:
            dst = regnum(parts[0]); ra = regnum(parts[1])
            rb = regnum(parts[2]); rc = regnum(parts[3])
            sign = '-' if 'n' in mn else ''
            regs.set(dst, _Val.expr(f'f{dst}'))
            return f'f{dst - 64} = {sign}(f{ra - 64} * f{rc - 64} + f{rb - 64});'

        if mn in ('fcmpu', 'fcmpo') and len(parts) >= 3:
            cr_field = 0
            if parts[0].startswith('cr'):
                try:
                    cr_field = int(parts[0][2:])
                except ValueError:
                    pass
                ra = regnum(parts[1]); rb = regnum(parts[2])
            else:
                ra = regnum(parts[0]); rb = regnum(parts[1])
            cr.update(cr_field, f'f{ra - 64}', f'f{rb - 64}', False)
            return None

        # ── System call ───────────────────────────────────────────────────
        if mn == 'sc':
            return f'syscall(r0={rv(0)});'

        # ── Altivec / VMX — emit as comment (complex, rare in user-space) ─
        if mn.startswith('v') and not mn.startswith('vor'):
            return f'// [{hex(va)}] {mn} {op}  // Altivec'

        # ── Absolute catch-all: emit as decoded comment ───────────────────
        return f'// [{hex(va)}] {mn} {op}'
